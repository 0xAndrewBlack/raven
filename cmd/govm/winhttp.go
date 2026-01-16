package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

const (
	whKindSession    = 0
	whKindConnection = 1
	whKindRequest    = 2
)

const (
	whQueryContentType    = 1
	whQueryContentLength  = 5
	whQueryStatusCode     = 19
	whQueryStatusText     = 20
	whQueryRawHeadersCRLF = 22
	whQueryFlagNumber     = 0x20000000
	whOptConnectTimeout   = 3
	whOptSecurityFlags    = 31
	whOptURL              = 34
	whFlagSecure          = 0x00800000
	whSchemeHTTP          = 1
	whSchemeHTTPS         = 2
)

// Error constants shared with wininet.go (errInvalidHandle, errInetCannotConnect, etc.)

type winhttpHandle struct {
	kind           int
	userAgent      string
	client         *http.Client
	serverName     string
	serverPort     uint16
	scheme         string
	method         string
	path           string
	reqHeaders     http.Header
	bodyData       []byte
	totalLen       uint64
	resp           *http.Response
	body           *bufio.Reader
	received       bool
	connectTimeout time.Duration
	securityFlags  uint32
	flags          uint32
	callback       uint64
	parent         ntapi.Handle
	mu             sync.Mutex
}

var whHandles sync.Map

func resolveWH(h ntapi.Handle) *winhttpHandle {
	v, ok := whHandles.Load(h)
	if !ok {
		return nil
	}
	return v.(*winhttpHandle)
}

func findWhSession(wh *winhttpHandle) *winhttpHandle {
	for wh != nil && wh.kind != whKindSession {
		wh = resolveWH(wh.parent)
	}
	return wh
}

func whGetClient(wh *winhttpHandle) *http.Client {
	if s := findWhSession(wh); s != nil && s.client != nil {
		return s.client
	}
	return http.DefaultClient
}

func whAlloc(ht *ntapi.HandleTable, wh *winhttpHandle) ntapi.Handle {
	h := ht.Alloc(&ntapi.GenericHandle{Kind: "winhttp"})
	whHandles.Store(h, wh)
	return h
}

func whFree(ht *ntapi.HandleTable, h ntapi.Handle) {
	whHandles.Delete(h)
	ht.Close(h)
}

func registerWinhttpHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	ht := hctx.Handles
	mem := hctx.Mem
	ps := hctx.ProcState
	readW := hctx.ReadGuestUTF16
	readWN := hctx.ReadGuestUTF16N

	dll, ok := hctx.SynthByName["winhttp.dll"]
	if !ok {
		return
	}

	setErr := func(c uint32) { mem.Write32(ps.TEBAddr+ntapi.TebLastErrorValue, c) }

	writeWide := func(addr uint64, s string, max int) int {
		ws := utf16Encode(s)
		n := len(ws)
		if max > 0 && n > max-1 {
			n = max - 1
		}
		for i := 0; i < n; i++ {
			mem.Write16(addr+uint64(i)*2, ws[i])
		}
		mem.Write16(addr+uint64(n)*2, 0)
		return n
	}
	mkClient := func(t time.Duration) *http.Client {
		return &http.Client{Timeout: t, Transport: &http.Transport{
			MaxIdleConns: 100, IdleConnTimeout: 90 * time.Second,
			MaxConnsPerHost: 10, MaxIdleConnsPerHost: 10,
		}}
	}

	// WinHttpOpen
	d.RegisterAutoStubHandler(dll, "WinHttpOpen", func(ctx *ntapi.TrapContext) uint32 {
		ag := readW(ctx.Arg(0))
		if ag == "" {
			ag = "Raven/1.0"
		}
		t := 30 * time.Second
		h := whAlloc(ht, &winhttpHandle{kind: whKindSession, userAgent: ag, client: mkClient(t), connectTimeout: t})
		ravelog.Logf("[winhttp] WinHttpOpen agent=%q -> %#x\n", ag, h)
		setErr(0)
		ctx.SetReturn(uint64(h))
		return 0
	})

	// WinHttpConnect
	d.RegisterAutoStubHandler(dll, "WinHttpConnect", func(ctx *ntapi.TrapContext) uint32 {
		hS := ntapi.Handle(ctx.Arg(0))
		srv := readW(ctx.Arg(1))
		port := uint16(ctx.Arg(2))
		if resolveWH(hS) == nil {
			setErr(errInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		sc := "http"
		if port == 443 {
			sc = "https"
		}
		if port == 0 {
			port = 80
		}
		h := whAlloc(ht, &winhttpHandle{kind: whKindConnection, serverName: srv, serverPort: port, scheme: sc, parent: hS})
		ravelog.Logf("[winhttp] WinHttpConnect %s:%d -> %#x\n", srv, port, h)
		setErr(0)
		ctx.SetReturn(uint64(h))
		return 0
	})

	// WinHttpOpenRequest
	d.RegisterAutoStubHandler(dll, "WinHttpOpenRequest", func(ctx *ntapi.TrapContext) uint32 {
		hC := ntapi.Handle(ctx.Arg(0))
		meth := readW(ctx.Arg(1))
		pth := readW(ctx.Arg(2))
		fl := uint32(ctx.Arg(6))
		cn := resolveWH(hC)
		if cn == nil || cn.kind != whKindConnection {
			setErr(errInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		if meth == "" {
			meth = "GET"
		}
		if pth == "" {
			pth = "/"
		}
		sc := cn.scheme
		if fl&whFlagSecure != 0 {
			sc = "https"
		}
		h := whAlloc(ht, &winhttpHandle{kind: whKindRequest, method: strings.ToUpper(meth), path: pth, reqHeaders: make(http.Header), parent: hC, flags: fl, scheme: sc})
		ravelog.Logf("[winhttp] OpenRequest %s %s -> %#x\n", meth, pth, h)
		setErr(0)
		ctx.SetReturn(uint64(h))
		return 0
	})

	// WinHttpSendRequest
	d.RegisterAutoStubHandler(dll, "WinHttpSendRequest", func(ctx *ntapi.TrapContext) uint32 {
		rq := resolveWH(ntapi.Handle(ctx.Arg(0)))
		if rq == nil || rq.kind != whKindRequest {
			setErr(errInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		ha := ctx.Arg(1)
		hl := int(int32(ctx.Arg(2)))
		oa := ctx.Arg(3)
		ol := int(ctx.Arg(4))
		rq.totalLen = ctx.Arg(5)

		if ha != 0 && hl != 0 {
			var hdrs string
			if hl < 0 {
				hdrs = readW(ha)
			} else {
				hdrs = readWN(ha, hl)
			}
			for _, line := range strings.Split(hdrs, "\r\n") {
				if idx := strings.Index(line, ":"); idx > 0 {
					rq.reqHeaders.Add(strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:]))
				}
			}
		}
		if oa != 0 && ol > 0 {
			b, err := mem.ReadBytes(oa, ol)
			if err != nil {
				setErr(errInvalidParameter)
				ctx.SetReturn(0)
				return 0
			}
			rq.bodyData = b
		}

		cn := resolveWH(rq.parent)
		if cn == nil {
			setErr(errInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		sc := rq.scheme
		if sc == "" {
			sc = cn.scheme
		}
		if sc == "" {
			sc = "http"
		}
		u := fmt.Sprintf("%s://%s:%d%s", sc, cn.serverName, cn.serverPort, rq.path)
		var br io.Reader
		if len(rq.bodyData) > 0 {
			br = bytes.NewReader(rq.bodyData)
		}
		hr, err := http.NewRequest(rq.method, u, br)
		if err != nil {
			setErr(errInetCannotConnect)
			ctx.SetReturn(0)
			return 0
		}
		if s := findWhSession(rq); s != nil {
			hr.Header.Set("User-Agent", s.userAgent)
		}
		for k, vs := range rq.reqHeaders {
			for _, v := range vs {
				hr.Header.Add(k, v)
			}
		}
		ravelog.Logf("[winhttp] SendRequest: %s %s\n", rq.method, u)
		resp, err := whGetClient(rq).Do(hr)
		if err != nil {
			ravelog.Logf("[winhttp] SendRequest failed: %v\n", err)
			setErr(errInetCannotConnect)
			ctx.SetReturn(0)
			return 0
		}
		rq.mu.Lock()
		rq.resp = resp
		rq.body = bufio.NewReaderSize(resp.Body, 8192)
		rq.mu.Unlock()
		ravelog.Logf("[winhttp] SendRequest: status=%d\n", resp.StatusCode)
		setErr(0)
		ctx.SetReturn(1)
		return 0
	})

	// WinHttpReceiveResponse
	d.RegisterAutoStubHandler(dll, "WinHttpReceiveResponse", func(ctx *ntapi.TrapContext) uint32 {
		rq := resolveWH(ntapi.Handle(ctx.Arg(0)))
		if rq == nil || rq.kind != whKindRequest {
			setErr(errInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		rq.mu.Lock()
		if rq.resp == nil {
			rq.mu.Unlock()
			setErr(errInetCannotConnect)
			ctx.SetReturn(0)
			return 0
		}
		rq.received = true
		rq.mu.Unlock()
		ravelog.Logf("[winhttp] ReceiveResponse: status=%d\n", rq.resp.StatusCode)
		setErr(0)
		ctx.SetReturn(1)
		return 0
	})

	// WinHttpReadData
	d.RegisterAutoStubHandler(dll, "WinHttpReadData", func(ctx *ntapi.TrapContext) uint32 {
		rq := resolveWH(ntapi.Handle(ctx.Arg(0)))
		if rq == nil || rq.body == nil {
			setErr(errInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		ba := ctx.Arg(1)
		tr := int(ctx.Arg(2))
		rq.mu.Lock()
		buf := make([]byte, tr)
		n, err := rq.body.Read(buf)
		rq.mu.Unlock()
		if n > 0 {
			mem.WriteBytes(ba, buf[:n])
		}
		if bra := ctx.Arg(3); bra != 0 {
			mem.Write32(bra, uint32(n))
		}
		if err != nil && err != io.EOF {
			setErr(errInetCannotConnect)
			ctx.SetReturn(0)
			return 0
		}
		setErr(0)
		ctx.SetReturn(1)
		return 0
	})

	// WinHttpQueryHeaders
	d.RegisterAutoStubHandler(dll, "WinHttpQueryHeaders", func(ctx *ntapi.TrapContext) uint32 {
		rq := resolveWH(ntapi.Handle(ctx.Arg(0)))
		if rq == nil || rq.resp == nil {
			setErr(errInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		il := uint32(ctx.Arg(1))
		ba := ctx.Arg(3)
		bla := ctx.Arg(4)
		qid := il & 0xFFFF
		asN := il&whQueryFlagNumber != 0
		var bl uint32
		if bla != 0 {
			bl, _ = mem.Read32(bla)
		}
		ww := func(s string) bool {
			ws := utf16Encode(s)
			nd := uint32((len(ws) + 1) * 2)
			if bl < nd {
				if bla != 0 { mem.Write32(bla, nd) }
				setErr(errInsufficientBuffer); ctx.SetReturn(0); return false
			}
			for i, w := range ws { mem.Write16(ba+uint64(i)*2, w) }
			mem.Write16(ba+uint64(len(ws))*2, 0)
			if bla != 0 { mem.Write32(bla, uint32(len(ws)*2)) }
			return true
		}
		wd := func(v uint32) bool {
			if bl < 4 {
				if bla != 0 { mem.Write32(bla, 4) }
				setErr(errInsufficientBuffer); ctx.SetReturn(0); return false
			}
			mem.Write32(ba, v)
			if bla != 0 { mem.Write32(bla, 4) }
			return true
		}
		switch qid {
		case whQueryStatusCode:
			if asN { if !wd(uint32(rq.resp.StatusCode)) { return 0 } } else if !ww(strconv.Itoa(rq.resp.StatusCode)) { return 0 }
		case whQueryContentLength:
			cl := rq.resp.ContentLength
			if cl < 0 { cl = 0 }
			if asN { if !wd(uint32(cl)) { return 0 } } else if !ww(strconv.FormatInt(cl, 10)) { return 0 }
		case whQueryRawHeadersCRLF:
			var sb strings.Builder
			fmt.Fprintf(&sb, "HTTP/%d.%d %d %s\r\n", rq.resp.ProtoMajor, rq.resp.ProtoMinor, rq.resp.StatusCode, http.StatusText(rq.resp.StatusCode))
			for k, vs := range rq.resp.Header { for _, v := range vs { fmt.Fprintf(&sb, "%s: %s\r\n", k, v) } }
			sb.WriteString("\r\n")
			if !ww(sb.String()) { return 0 }
		case whQueryContentType:
			ct := rq.resp.Header.Get("Content-Type")
			if ct == "" { setErr(errHttpHeaderNotFound); ctx.SetReturn(0); return 0 }
			if !ww(ct) { return 0 }
		case whQueryStatusText:
			if !ww(http.StatusText(rq.resp.StatusCode)) { return 0 }
		default:
			setErr(errHttpHeaderNotFound); ctx.SetReturn(0); return 0
		}
		setErr(0); ctx.SetReturn(1); return 0
	})

	// WinHttpQueryDataAvailable
	d.RegisterAutoStubHandler(dll, "WinHttpQueryDataAvailable", func(ctx *ntapi.TrapContext) uint32 {
		rq := resolveWH(ntapi.Handle(ctx.Arg(0)))
		if rq == nil || rq.body == nil { setErr(errInvalidHandle); ctx.SetReturn(0); return 0 }
		rq.mu.Lock()
		n := rq.body.Buffered()
		if n == 0 { if _, e := rq.body.Peek(1); e == nil { n = rq.body.Buffered() } }
		rq.mu.Unlock()
		if a := ctx.Arg(1); a != 0 { mem.Write32(a, uint32(n)) }
		setErr(0); ctx.SetReturn(1); return 0
	})

	// WinHttpCloseHandle
	d.RegisterAutoStubHandler(dll, "WinHttpCloseHandle", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		wh := resolveWH(h)
		if wh == nil { setErr(errInvalidHandle); ctx.SetReturn(0); return 0 }
		wh.mu.Lock()
		if wh.resp != nil && wh.resp.Body != nil { wh.resp.Body.Close(); wh.resp = nil; wh.body = nil }
		wh.mu.Unlock()
		whFree(ht, h)
		ravelog.Logf("[winhttp] CloseHandle %#x\n", h)
		setErr(0); ctx.SetReturn(1); return 0
	})

	// WinHttpCrackUrl
	d.RegisterAutoStubHandler(dll, "WinHttpCrackUrl", func(ctx *ntapi.TrapContext) uint32 {
		n := int(int32(ctx.Arg(1)))
		comp := ctx.Arg(3)
		if comp == 0 { setErr(errInvalidParameter); ctx.SetReturn(0); return 0 }
		var raw string
		if n > 0 { raw = readWN(ctx.Arg(0), n) } else { raw = readW(ctx.Arg(0)) }
		if raw == "" { setErr(errInetInvalidURL); ctx.SetReturn(0); return 0 }
		p, err := url.Parse(raw)
		if err != nil { setErr(errInetInvalidURL); ctx.SetReturn(0); return 0 }
		sc := p.Scheme
		ho := p.Hostname()
		pStr := p.Port()
		po := uint16(80)
		if pStr != "" { pv, _ := strconv.Atoi(pStr); po = uint16(pv) } else if sc == "https" { po = 443 }
		pa := p.Path
		if pa == "" { pa = "/" }
		ex := ""
		if p.RawQuery != "" { ex = "?" + p.RawQuery }
		if p.Fragment != "" { ex += "#" + p.Fragment }
		ns := uint32(whSchemeHTTP)
		if sc == "https" { ns = uint32(whSchemeHTTPS) }
		usr := ""
		pw := ""
		if p.User != nil { usr = p.User.Username(); pw, _ = p.User.Password() }
		wc := func(pOff, lOff uint64, val string) {
			ptr, _ := mem.Read64(comp + pOff)
			ml, _ := mem.Read32(comp + lOff)
			if ptr != 0 && ml > 0 { writeWide(ptr, val, int(ml)) }
			mem.Write32(comp+lOff, uint32(len(val)))
		}
		wc(8, 16, sc); mem.Write32(comp+20, ns); wc(24, 32, ho); mem.Write16(comp+36, po)
		wc(40, 48, usr); wc(56, 64, pw); wc(72, 80, pa); wc(88, 96, ex)
		ravelog.Logf("[winhttp] CrackUrl: %s -> %s://%s:%d%s\n", raw, sc, ho, po, pa)
		setErr(0); ctx.SetReturn(1); return 0
	})

	// WinHttpSetOption
	d.RegisterAutoStubHandler(dll, "WinHttpSetOption", func(ctx *ntapi.TrapContext) uint32 {
		wh := resolveWH(ntapi.Handle(ctx.Arg(0)))
		if wh == nil { setErr(errInvalidHandle); ctx.SetReturn(0); return 0 }
		opt := uint32(ctx.Arg(1))
		ba := ctx.Arg(2)
		bl := uint32(ctx.Arg(3))
		switch opt {
		case whOptConnectTimeout:
			if bl >= 4 && ba != 0 {
				ms, _ := mem.Read32(ba)
				wh.connectTimeout = time.Duration(ms) * time.Millisecond
				if s := findWhSession(wh); s != nil && s.client != nil { s.client.Timeout = wh.connectTimeout }
			}
		case whOptSecurityFlags:
			if bl >= 4 && ba != 0 { f, _ := mem.Read32(ba); wh.securityFlags = f }
		default:
			ravelog.Logf("[winhttp] SetOption %d\n", opt)
		}
		setErr(0); ctx.SetReturn(1); return 0
	})

	// WinHttpQueryOption
	d.RegisterAutoStubHandler(dll, "WinHttpQueryOption", func(ctx *ntapi.TrapContext) uint32 {
		wh := resolveWH(ntapi.Handle(ctx.Arg(0)))
		opt := uint32(ctx.Arg(1))
		ba := ctx.Arg(2)
		bla := ctx.Arg(3)
		var bl uint32
		if bla != 0 { bl, _ = mem.Read32(bla) }
		wd := func(v uint32) bool {
			if bl < 4 { if bla != 0 { mem.Write32(bla, 4) }; setErr(errInsufficientBuffer); ctx.SetReturn(0); return false }
			mem.Write32(ba, v)
			if bla != 0 { mem.Write32(bla, 4) }
			return true
		}
		switch opt {
		case whOptConnectTimeout:
			ms := uint32(30000)
			if wh != nil { ms = uint32(wh.connectTimeout / time.Millisecond) }
			if !wd(ms) { return 0 }
		case whOptSecurityFlags:
			f := uint32(0)
			if wh != nil { f = wh.securityFlags }
			if !wd(f) { return 0 }
		case whOptURL:
			u := ""
			if wh != nil { u = wh.path }
			ws := utf16Encode(u)
			nd := uint32((len(ws) + 1) * 2)
			if bl < nd { if bla != 0 { mem.Write32(bla, nd) }; setErr(errInsufficientBuffer); ctx.SetReturn(0); return 0 }
			writeWide(ba, u, int(bl/2))
			if bla != 0 { mem.Write32(bla, uint32(len(ws)*2)) }
		default:
			setErr(errInvalidParameter); ctx.SetReturn(0); return 0
		}
		setErr(0); ctx.SetReturn(1); return 0
	})

	// WinHttpAddRequestHeaders
	d.RegisterAutoStubHandler(dll, "WinHttpAddRequestHeaders", func(ctx *ntapi.TrapContext) uint32 {
		rq := resolveWH(ntapi.Handle(ctx.Arg(0)))
		if rq == nil || rq.kind != whKindRequest { setErr(errInvalidHandle); ctx.SetReturn(0); return 0 }
		n := int(int32(ctx.Arg(2)))
		var hdrs string
		if n < 0 { hdrs = readW(ctx.Arg(1)) } else { hdrs = readWN(ctx.Arg(1), n) }
		for _, line := range strings.Split(hdrs, "\r\n") {
			if idx := strings.Index(line, ":"); idx > 0 { rq.reqHeaders.Add(strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:])) }
		}
		setErr(0); ctx.SetReturn(1); return 0
	})
}
