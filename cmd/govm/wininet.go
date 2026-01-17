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
	inetKindSession    = 0
	inetKindConnection = 1
	inetKindRequest    = 2
)

const (
	httpQueryContentType    = 1
	httpQueryContentLength  = 5
	httpQueryStatusCode     = 19
	httpQueryStatusText     = 20
	httpQueryRawHeadersCRLF = 22
	httpQueryFlagNumber     = 0x20000000
	inetOptConnectTimeout   = 2
	inetOptSecurityFlags    = 31
	inetOptURL              = 34
	inetOptUserAgent        = 41
	inetFlagSecure          = 0x00800000
	inetConnectionLAN       = 0x02
	inetSchemeHTTP          = 1
	inetSchemeHTTPS         = 2
	errInetInvalidURL       = 12005
	errInetCannotConnect    = 12029
	errHttpHeaderNotFound   = 12150
	errInsufficientBuffer   = 122
	errInvalidHandle        = 6
	errInvalidParameter     = 87
)

type inetHandle struct {
	kind           int
	userAgent      string
	client         *http.Client
	serverName     string
	serverPort     uint16
	scheme         string
	method         string
	path           string
	reqHeaders     http.Header
	resp           *http.Response
	body           *bufio.Reader
	sent           bool
	connectTimeout time.Duration
	securityFlags  uint32
	flags          uint32
	callback       uint64
	parent         ntapi.Handle
	mu             sync.Mutex
}

var inetHandles sync.Map

func resolveInet(h ntapi.Handle) *inetHandle {
	v, ok := inetHandles.Load(h)
	if !ok {
		return nil
	}
	return v.(*inetHandle)
}

func findInetSession(ih *inetHandle) *inetHandle {
	for ih != nil && ih.kind != inetKindSession {
		ih = resolveInet(ih.parent)
	}
	return ih
}

func inetGetClient(ih *inetHandle) *http.Client {
	if s := findInetSession(ih); s != nil && s.client != nil {
		return s.client
	}
	return http.DefaultClient
}

func inetAlloc(ht *ntapi.HandleTable, ih *inetHandle) ntapi.Handle {
	h := ht.Alloc(&ntapi.GenericHandle{Kind: "wininet"})
	inetHandles.Store(h, ih)
	return h
}

func inetFree(ht *ntapi.HandleTable, h ntapi.Handle) {
	inetHandles.Delete(h)
	ht.Close(h)
}

func registerWininetHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	ht := hctx.Handles
	mem := hctx.Mem
	ps := hctx.ProcState
	readW := hctx.ReadGuestUTF16
	readWN := hctx.ReadGuestUTF16N
	readA := hctx.ReadGuestString

	dll, ok := hctx.SynthByName["wininet.dll"]
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
	writeAnsiStr := func(addr uint64, s string, max int) int {
		b := []byte(s)
		n := len(b)
		if max > 0 && n > max-1 {
			n = max - 1
		}
		if n > 0 {
			mem.WriteBytes(addr, b[:n])
		}
		mem.Write8(addr+uint64(n), 0)
		return n
	}
	parseHdrs := func(h string) http.Header {
		hdr := make(http.Header)
		for _, line := range strings.Split(h, "\r\n") {
			if idx := strings.Index(line, ":"); idx > 0 {
				hdr.Add(strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:]))
			}
		}
		return hdr
	}
	mkClient := func(t time.Duration) *http.Client {
		return &http.Client{Timeout: t, Transport: &http.Transport{
			MaxIdleConns: 100, IdleConnTimeout: 90 * time.Second,
			MaxConnsPerHost: 10, MaxIdleConnsPerHost: 10,
		}}
	}

	// InternetOpenW/A
	d.RegisterAutoStubHandler(dll, "InternetOpenW", func(ctx *ntapi.TrapContext) uint32 {
		ag := readW(ctx.Arg(0))
		if ag == "" {
			ag = "Raven/1.0"
		}
		t := 30 * time.Second
		h := inetAlloc(ht, &inetHandle{kind: inetKindSession, userAgent: ag, client: mkClient(t), connectTimeout: t})
		ravelog.Logf("[wininet] InternetOpenW agent=%q -> %#x\n", ag, h)
		setErr(0)
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "InternetOpenA", func(ctx *ntapi.TrapContext) uint32 {
		ag := readA(ctx.Arg(0))
		if ag == "" {
			ag = "Raven/1.0"
		}
		t := 30 * time.Second
		h := inetAlloc(ht, &inetHandle{kind: inetKindSession, userAgent: ag, client: mkClient(t), connectTimeout: t})
		ravelog.Logf("[wininet] InternetOpenA agent=%q -> %#x\n", ag, h)
		setErr(0)
		ctx.SetReturn(uint64(h))
		return 0
	})

	// InternetConnectW/A
	inetConnect := func(ctx *ntapi.TrapContext, srv string) uint32 {
		hS := ntapi.Handle(ctx.Arg(0))
		port := uint16(ctx.Arg(2))
		fl := uint32(ctx.Arg(6))
		if resolveInet(hS) == nil {
			setErr(errInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		sc := "http"
		if port == 443 || fl&inetFlagSecure != 0 {
			sc = "https"
		}
		if port == 0 {
			if sc == "https" {
				port = 443
			} else {
				port = 80
			}
		}
		h := inetAlloc(ht, &inetHandle{kind: inetKindConnection, serverName: srv, serverPort: port, scheme: sc, parent: hS, flags: fl})
		ravelog.Logf("[wininet] Connect %s:%d -> %#x\n", srv, port, h)
		setErr(0)
		ctx.SetReturn(uint64(h))
		return 0
	}
	d.RegisterAutoStubHandler(dll, "InternetConnectW", func(ctx *ntapi.TrapContext) uint32 {
		return inetConnect(ctx, readW(ctx.Arg(1)))
	})
	d.RegisterAutoStubHandler(dll, "InternetConnectA", func(ctx *ntapi.TrapContext) uint32 {
		return inetConnect(ctx, readA(ctx.Arg(1)))
	})

	// HttpOpenRequestW/A
	openReq := func(hC ntapi.Handle, meth, pth string, fl uint32) ntapi.Handle {
		cn := resolveInet(hC)
		if cn == nil || cn.kind != inetKindConnection {
			return 0
		}
		if meth == "" {
			meth = "GET"
		}
		if pth == "" {
			pth = "/"
		}
		sc := cn.scheme
		if fl&inetFlagSecure != 0 {
			sc = "https"
		}
		return inetAlloc(ht, &inetHandle{kind: inetKindRequest, method: strings.ToUpper(meth), path: pth, reqHeaders: make(http.Header), parent: hC, flags: fl, scheme: sc})
	}
	d.RegisterAutoStubHandler(dll, "HttpOpenRequestW", func(ctx *ntapi.TrapContext) uint32 {
		h := openReq(ntapi.Handle(ctx.Arg(0)), readW(ctx.Arg(1)), readW(ctx.Arg(2)), uint32(ctx.Arg(6)))
		if h == 0 {
			setErr(errInvalidHandle)
		} else {
			setErr(0)
		}
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "HttpOpenRequestA", func(ctx *ntapi.TrapContext) uint32 {
		h := openReq(ntapi.Handle(ctx.Arg(0)), readA(ctx.Arg(1)), readA(ctx.Arg(2)), uint32(ctx.Arg(6)))
		if h == 0 {
			setErr(errInvalidHandle)
		} else {
			setErr(0)
		}
		ctx.SetReturn(uint64(h))
		return 0
	})

	// HttpSendRequestW/A
	doSend := func(rq *inetHandle, ex http.Header, bd []byte) error {
		cn := resolveInet(rq.parent)
		if cn == nil {
			return fmt.Errorf("no connection")
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
		if len(bd) > 0 {
			br = bytes.NewReader(bd)
		}
		hr, err := http.NewRequest(rq.method, u, br)
		if err != nil {
			return err
		}
		if s := findInetSession(rq); s != nil {
			hr.Header.Set("User-Agent", s.userAgent)
		}
		for k, vs := range rq.reqHeaders {
			for _, v := range vs {
				hr.Header.Add(k, v)
			}
		}
		for k, vs := range ex {
			for _, v := range vs {
				hr.Header.Add(k, v)
			}
		}
		ravelog.Logf("[wininet] HTTP %s %s\n", rq.method, u)
		resp, err := inetGetClient(rq).Do(hr)
		if err != nil {
			return err
		}
		rq.mu.Lock()
		rq.resp = resp
		rq.body = bufio.NewReaderSize(resp.Body, 8192)
		rq.sent = true
		rq.mu.Unlock()
		ravelog.Logf("[wininet] HTTP status=%d\n", resp.StatusCode)
		return nil
	}
	sendHdl := func(ctx *ntapi.TrapContext, rs func(uint64) string, rn func(uint64, int) string) uint32 {
		rq := resolveInet(ntapi.Handle(ctx.Arg(0)))
		if rq == nil || rq.kind != inetKindRequest {
			setErr(errInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		ha := ctx.Arg(1)
		hl := int(int32(ctx.Arg(2)))
		var ex http.Header
		if ha != 0 && hl != 0 {
			var s string
			if hl < 0 {
				s = rs(ha)
			} else {
				s = rn(ha, hl)
			}
			ex = parseHdrs(s)
		}
		var bd []byte
		if oa := ctx.Arg(3); oa != 0 {
			if ol := int(ctx.Arg(4)); ol > 0 {
				b, err := mem.ReadBytes(oa, ol)
				if err != nil {
					setErr(errInvalidParameter)
					ctx.SetReturn(0)
					return 0
				}
				bd = b
			}
		}
		if err := doSend(rq, ex, bd); err != nil {
			ravelog.Logf("[wininet] HttpSendRequest failed: %v\n", err)
			setErr(errInetCannotConnect)
			ctx.SetReturn(0)
			return 0
		}
		setErr(0)
		ctx.SetReturn(1)
		return 0
	}
	d.RegisterAutoStubHandler(dll, "HttpSendRequestW", func(ctx *ntapi.TrapContext) uint32 {
		return sendHdl(ctx, readW, func(a uint64, n int) string { return readWN(a, n) })
	})
	d.RegisterAutoStubHandler(dll, "HttpSendRequestA", func(ctx *ntapi.TrapContext) uint32 {
		return sendHdl(ctx, readA, func(a uint64, n int) string {
			r, e := mem.ReadBytes(a, n)
			if e != nil {
				return ""
			}
			return string(r)
		})
	})

	// InternetOpenUrlW/A
	doOpen := func(ss *inetHandle, hS ntapi.Handle, rawURL string, ex http.Header, fl uint32) (ntapi.Handle, error) {
		hr, err := http.NewRequest("GET", rawURL, nil)
		if err != nil {
			return 0, err
		}
		hr.Header.Set("User-Agent", ss.userAgent)
		for k, vs := range ex {
			for _, v := range vs {
				hr.Header.Add(k, v)
			}
		}
		cl := ss.client
		if cl == nil {
			cl = http.DefaultClient
		}
		ravelog.Logf("[wininet] OpenUrl: GET %s\n", rawURL)
		resp, err := cl.Do(hr)
		if err != nil {
			return 0, err
		}
		h := inetAlloc(ht, &inetHandle{kind: inetKindRequest, method: "GET", path: rawURL, resp: resp, body: bufio.NewReaderSize(resp.Body, 8192), sent: true, parent: hS, flags: fl})
		ravelog.Logf("[wininet] OpenUrl: status=%d -> %#x\n", resp.StatusCode, h)
		return h, nil
	}
	openURLHdl := func(ctx *ntapi.TrapContext, rawURL string, rs func(uint64) string, rn func(uint64, int) string) uint32 {
		hS := ntapi.Handle(ctx.Arg(0))
		ha := ctx.Arg(2)
		hl := int(int32(ctx.Arg(3)))
		fl := uint32(ctx.Arg(4))
		ss := resolveInet(hS)
		if ss == nil || ss.kind != inetKindSession {
			setErr(errInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		if rawURL == "" {
			setErr(errInvalidParameter)
			ctx.SetReturn(0)
			return 0
		}
		var ex http.Header
		if ha != 0 && hl != 0 {
			var s string
			if hl < 0 {
				s = rs(ha)
			} else {
				s = rn(ha, hl)
			}
			ex = parseHdrs(s)
		}
		h, err := doOpen(ss, hS, rawURL, ex, fl)
		if err != nil {
			ravelog.Logf("[wininet] OpenUrl failed: %v\n", err)
			setErr(errInetCannotConnect)
			ctx.SetReturn(0)
			return 0
		}
		setErr(0)
		ctx.SetReturn(uint64(h))
		return 0
	}
	d.RegisterAutoStubHandler(dll, "InternetOpenUrlW", func(ctx *ntapi.TrapContext) uint32 {
		return openURLHdl(ctx, readW(ctx.Arg(1)), readW, func(a uint64, n int) string { return readWN(a, n) })
	})
	d.RegisterAutoStubHandler(dll, "InternetOpenUrlA", func(ctx *ntapi.TrapContext) uint32 {
		return openURLHdl(ctx, readA(ctx.Arg(1)), readA, func(a uint64, n int) string {
			r, e := mem.ReadBytes(a, n)
			if e != nil {
				return ""
			}
			return string(r)
		})
	})

	// InternetReadFile
	d.RegisterAutoStubHandler(dll, "InternetReadFile", func(ctx *ntapi.TrapContext) uint32 {
		ih := resolveInet(ntapi.Handle(ctx.Arg(0)))
		if ih == nil || ih.body == nil {
			setErr(errInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		ba := ctx.Arg(1)
		tr := int(ctx.Arg(2))
		ih.mu.Lock()
		buf := make([]byte, tr)
		n, err := ih.body.Read(buf)
		ih.mu.Unlock()
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

	// InternetCloseHandle
	d.RegisterAutoStubHandler(dll, "InternetCloseHandle", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		ih := resolveInet(h)
		if ih == nil {
			setErr(errInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		ih.mu.Lock()
		if ih.resp != nil && ih.resp.Body != nil {
			ih.resp.Body.Close()
			ih.resp = nil
			ih.body = nil
		}
		ih.mu.Unlock()
		inetFree(ht, h)
		ravelog.Logf("[wininet] CloseHandle %#x\n", h)
		setErr(0)
		ctx.SetReturn(1)
		return 0
	})

	// HttpQueryInfoW
	d.RegisterAutoStubHandler(dll, "HttpQueryInfoW", func(ctx *ntapi.TrapContext) uint32 {
		rq := resolveInet(ntapi.Handle(ctx.Arg(0)))
		if rq == nil || rq.resp == nil {
			setErr(errInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		il := uint32(ctx.Arg(1))
		ba := ctx.Arg(2)
		bla := ctx.Arg(3)
		qid := il & 0xFFFF
		asN := il&httpQueryFlagNumber != 0
		var bl uint32
		if bla != 0 {
			bl, _ = mem.Read32(bla)
		}
		ww := func(s string) bool {
			ws := utf16Encode(s)
			nd := uint32((len(ws) + 1) * 2)
			if bl < nd {
				if bla != 0 {
					mem.Write32(bla, nd)
				}
				setErr(errInsufficientBuffer)
				ctx.SetReturn(0)
				return false
			}
			for i, w := range ws {
				mem.Write16(ba+uint64(i)*2, w)
			}
			mem.Write16(ba+uint64(len(ws))*2, 0)
			if bla != 0 {
				mem.Write32(bla, uint32(len(ws)*2))
			}
			return true
		}
		wd := func(v uint32) bool {
			if bl < 4 {
				if bla != 0 {
					mem.Write32(bla, 4)
				}
				setErr(errInsufficientBuffer)
				ctx.SetReturn(0)
				return false
			}
			mem.Write32(ba, v)
			if bla != 0 {
				mem.Write32(bla, 4)
			}
			return true
		}
		switch qid {
		case httpQueryStatusCode:
			if asN {
				if !wd(uint32(rq.resp.StatusCode)) {
					return 0
				}
			} else if !ww(strconv.Itoa(rq.resp.StatusCode)) {
				return 0
			}
		case httpQueryContentLength:
			cl := rq.resp.ContentLength
			if cl < 0 {
				cl = 0
			}
			if asN {
				if !wd(uint32(cl)) {
					return 0
				}
			} else if !ww(strconv.FormatInt(cl, 10)) {
				return 0
			}
		case httpQueryRawHeadersCRLF:
			var sb strings.Builder
			fmt.Fprintf(&sb, "HTTP/%d.%d %d %s\r\n", rq.resp.ProtoMajor, rq.resp.ProtoMinor, rq.resp.StatusCode, http.StatusText(rq.resp.StatusCode))
			for k, vs := range rq.resp.Header {
				for _, v := range vs {
					fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
				}
			}
			sb.WriteString("\r\n")
			if !ww(sb.String()) {
				return 0
			}
		case httpQueryContentType:
			ct := rq.resp.Header.Get("Content-Type")
			if ct == "" {
				setErr(errHttpHeaderNotFound)
				ctx.SetReturn(0)
				return 0
			}
			if !ww(ct) {
				return 0
			}
		case httpQueryStatusText:
			if !ww(http.StatusText(rq.resp.StatusCode)) {
				return 0
			}
		default:
			setErr(errHttpHeaderNotFound)
			ctx.SetReturn(0)
			return 0
		}
		setErr(0)
		ctx.SetReturn(1)
		return 0
	})

	// HttpQueryInfoA
	d.RegisterAutoStubHandler(dll, "HttpQueryInfoA", func(ctx *ntapi.TrapContext) uint32 {
		rq := resolveInet(ntapi.Handle(ctx.Arg(0)))
		if rq == nil || rq.resp == nil {
			setErr(errInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		il := uint32(ctx.Arg(1))
		ba := ctx.Arg(2)
		bla := ctx.Arg(3)
		qid := il & 0xFFFF
		asN := il&httpQueryFlagNumber != 0
		var bl uint32
		if bla != 0 {
			bl, _ = mem.Read32(bla)
		}
		wa := func(s string) bool {
			nd := uint32(len(s) + 1)
			if bl < nd {
				if bla != 0 {
					mem.Write32(bla, nd)
				}
				setErr(errInsufficientBuffer)
				ctx.SetReturn(0)
				return false
			}
			mem.WriteBytes(ba, []byte(s))
			mem.Write8(ba+uint64(len(s)), 0)
			if bla != 0 {
				mem.Write32(bla, uint32(len(s)))
			}
			return true
		}
		wd := func(v uint32) bool {
			if bl < 4 {
				if bla != 0 {
					mem.Write32(bla, 4)
				}
				setErr(errInsufficientBuffer)
				ctx.SetReturn(0)
				return false
			}
			mem.Write32(ba, v)
			if bla != 0 {
				mem.Write32(bla, 4)
			}
			return true
		}
		switch qid {
		case httpQueryStatusCode:
			if asN {
				if !wd(uint32(rq.resp.StatusCode)) {
					return 0
				}
			} else if !wa(strconv.Itoa(rq.resp.StatusCode)) {
				return 0
			}
		case httpQueryContentLength:
			cl := rq.resp.ContentLength
			if cl < 0 {
				cl = 0
			}
			if asN {
				if !wd(uint32(cl)) {
					return 0
				}
			} else if !wa(strconv.FormatInt(cl, 10)) {
				return 0
			}
		case httpQueryRawHeadersCRLF:
			var sb strings.Builder
			fmt.Fprintf(&sb, "HTTP/%d.%d %d %s\r\n", rq.resp.ProtoMajor, rq.resp.ProtoMinor, rq.resp.StatusCode, http.StatusText(rq.resp.StatusCode))
			for k, vs := range rq.resp.Header {
				for _, v := range vs {
					fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
				}
			}
			sb.WriteString("\r\n")
			if !wa(sb.String()) {
				return 0
			}
		case httpQueryContentType:
			ct := rq.resp.Header.Get("Content-Type")
			if ct == "" {
				setErr(errHttpHeaderNotFound)
				ctx.SetReturn(0)
				return 0
			}
			if !wa(ct) {
				return 0
			}
		case httpQueryStatusText:
			if !wa(http.StatusText(rq.resp.StatusCode)) {
				return 0
			}
		default:
			setErr(errHttpHeaderNotFound)
			ctx.SetReturn(0)
			return 0
		}
		setErr(0)
		ctx.SetReturn(1)
		return 0
	})

	// InternetQueryDataAvailable
	d.RegisterAutoStubHandler(dll, "InternetQueryDataAvailable", func(ctx *ntapi.TrapContext) uint32 {
		ih := resolveInet(ntapi.Handle(ctx.Arg(0)))
		if ih == nil || ih.body == nil {
			setErr(errInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		ih.mu.Lock()
		n := ih.body.Buffered()
		if n == 0 {
			if _, e := ih.body.Peek(1); e == nil {
				n = ih.body.Buffered()
			}
		}
		ih.mu.Unlock()
		if a := ctx.Arg(1); a != 0 {
			mem.Write32(a, uint32(n))
		}
		setErr(0)
		ctx.SetReturn(1)
		return 0
	})

	// InternetSetOptionW/A
	setOpt := func(ih *inetHandle, opt uint32, ba uint64, bl uint32, rs func(uint64) string) {
		switch opt {
		case inetOptConnectTimeout:
			if bl >= 4 && ba != 0 {
				ms, _ := mem.Read32(ba)
				ih.connectTimeout = time.Duration(ms) * time.Millisecond
				if s := findInetSession(ih); s != nil && s.client != nil {
					s.client.Timeout = ih.connectTimeout
				}
			}
		case inetOptSecurityFlags:
			if bl >= 4 && ba != 0 {
				f, _ := mem.Read32(ba)
				ih.securityFlags = f
			}
		case inetOptUserAgent:
			if ba != 0 {
				ih.userAgent = rs(ba)
			}
		default:
			ravelog.Logf("[wininet] SetOption %d\n", opt)
		}
	}
	d.RegisterAutoStubHandler(dll, "InternetSetOptionW", func(ctx *ntapi.TrapContext) uint32 {
		ih := resolveInet(ntapi.Handle(ctx.Arg(0)))
		if ih == nil {
			setErr(errInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		setOpt(ih, uint32(ctx.Arg(1)), ctx.Arg(2), uint32(ctx.Arg(3)), readW)
		setErr(0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "InternetSetOptionA", func(ctx *ntapi.TrapContext) uint32 {
		ih := resolveInet(ntapi.Handle(ctx.Arg(0)))
		if ih == nil {
			setErr(errInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		setOpt(ih, uint32(ctx.Arg(1)), ctx.Arg(2), uint32(ctx.Arg(3)), readA)
		setErr(0)
		ctx.SetReturn(1)
		return 0
	})

	// InternetQueryOptionW
	d.RegisterAutoStubHandler(dll, "InternetQueryOptionW", func(ctx *ntapi.TrapContext) uint32 {
		ih := resolveInet(ntapi.Handle(ctx.Arg(0)))
		opt := uint32(ctx.Arg(1))
		ba := ctx.Arg(2)
		bla := ctx.Arg(3)
		var bl uint32
		if bla != 0 {
			bl, _ = mem.Read32(bla)
		}
		wd := func(v uint32) bool {
			if bl < 4 {
				if bla != 0 {
					mem.Write32(bla, 4)
				}
				setErr(errInsufficientBuffer)
				ctx.SetReturn(0)
				return false
			}
			mem.Write32(ba, v)
			if bla != 0 {
				mem.Write32(bla, 4)
			}
			return true
		}
		switch opt {
		case inetOptConnectTimeout:
			ms := uint32(30000)
			if ih != nil {
				ms = uint32(ih.connectTimeout / time.Millisecond)
			}
			if !wd(ms) {
				return 0
			}
		case inetOptSecurityFlags:
			f := uint32(0)
			if ih != nil {
				f = ih.securityFlags
			}
			if !wd(f) {
				return 0
			}
		case inetOptUserAgent:
			ag := "Raven/1.0"
			if ih != nil && ih.userAgent != "" {
				ag = ih.userAgent
			}
			ws := utf16Encode(ag)
			nd := uint32((len(ws) + 1) * 2)
			if bl < nd {
				if bla != 0 {
					mem.Write32(bla, nd)
				}
				setErr(errInsufficientBuffer)
				ctx.SetReturn(0)
				return 0
			}
			writeWide(ba, ag, int(bl/2))
			if bla != 0 {
				mem.Write32(bla, uint32(len(ws)*2))
			}
		case inetOptURL:
			u := ""
			if ih != nil {
				u = ih.path
			}
			ws := utf16Encode(u)
			nd := uint32((len(ws) + 1) * 2)
			if bl < nd {
				if bla != 0 {
					mem.Write32(bla, nd)
				}
				setErr(errInsufficientBuffer)
				ctx.SetReturn(0)
				return 0
			}
			writeWide(ba, u, int(bl/2))
			if bla != 0 {
				mem.Write32(bla, uint32(len(ws)*2))
			}
		default:
			setErr(errInvalidParameter)
			ctx.SetReturn(0)
			return 0
		}
		setErr(0)
		ctx.SetReturn(1)
		return 0
	})

	// InternetQueryOptionA
	d.RegisterAutoStubHandler(dll, "InternetQueryOptionA", func(ctx *ntapi.TrapContext) uint32 {
		ih := resolveInet(ntapi.Handle(ctx.Arg(0)))
		opt := uint32(ctx.Arg(1))
		ba := ctx.Arg(2)
		bla := ctx.Arg(3)
		var bl uint32
		if bla != 0 {
			bl, _ = mem.Read32(bla)
		}
		wd := func(v uint32) bool {
			if bl < 4 {
				if bla != 0 {
					mem.Write32(bla, 4)
				}
				setErr(errInsufficientBuffer)
				ctx.SetReturn(0)
				return false
			}
			mem.Write32(ba, v)
			if bla != 0 {
				mem.Write32(bla, 4)
			}
			return true
		}
		switch opt {
		case inetOptConnectTimeout:
			ms := uint32(30000)
			if ih != nil {
				ms = uint32(ih.connectTimeout / time.Millisecond)
			}
			if !wd(ms) {
				return 0
			}
		case inetOptSecurityFlags:
			f := uint32(0)
			if ih != nil {
				f = ih.securityFlags
			}
			if !wd(f) {
				return 0
			}
		case inetOptUserAgent:
			ag := "Raven/1.0"
			if ih != nil && ih.userAgent != "" {
				ag = ih.userAgent
			}
			nd := uint32(len(ag) + 1)
			if bl < nd {
				if bla != 0 {
					mem.Write32(bla, nd)
				}
				setErr(errInsufficientBuffer)
				ctx.SetReturn(0)
				return 0
			}
			writeAnsiStr(ba, ag, int(bl))
			if bla != 0 {
				mem.Write32(bla, uint32(len(ag)))
			}
		default:
			setErr(errInvalidParameter)
			ctx.SetReturn(0)
			return 0
		}
		setErr(0)
		ctx.SetReturn(1)
		return 0
	})

	// InternetGetConnectedState
	d.RegisterAutoStubHandler(dll, "InternetGetConnectedState", func(ctx *ntapi.TrapContext) uint32 {
		if f := ctx.Arg(0); f != 0 {
			mem.Write32(f, inetConnectionLAN)
		}
		ctx.SetReturn(1)
		return 0
	})

	// InternetSetStatusCallbackW/A
	sCB := func(ctx *ntapi.TrapContext) uint32 {
		ih := resolveInet(ntapi.Handle(ctx.Arg(0)))
		if ih == nil {
			setErr(errInvalidHandle)
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
			return 0
		}
		old := ih.callback
		ih.callback = ctx.Arg(1)
		setErr(0)
		ctx.SetReturn(old)
		return 0
	}
	d.RegisterAutoStubHandler(dll, "InternetSetStatusCallbackW", sCB)
	d.RegisterAutoStubHandler(dll, "InternetSetStatusCallbackA", sCB)

	// InternetCrackUrlW/A
	crack := func(ctx *ntapi.TrapContext, raw string, comp uint64, wide bool) uint32 {
		if comp == 0 || raw == "" {
			setErr(errInetInvalidURL)
			ctx.SetReturn(0)
			return 0
		}
		p, err := url.Parse(raw)
		if err != nil {
			setErr(errInetInvalidURL)
			ctx.SetReturn(0)
			return 0
		}
		sc := p.Scheme
		ho := p.Hostname()
		pStr := p.Port()
		po := uint16(80)
		if pStr != "" {
			pv, _ := strconv.Atoi(pStr)
			po = uint16(pv)
		} else if sc == "https" {
			po = 443
		}
		pa := p.Path
		if pa == "" {
			pa = "/"
		}
		ex := ""
		if p.RawQuery != "" {
			ex = "?" + p.RawQuery
		}
		if p.Fragment != "" {
			ex += "#" + p.Fragment
		}
		ns := uint32(inetSchemeHTTP)
		if sc == "https" {
			ns = uint32(inetSchemeHTTPS)
		}
		usr := ""
		pw := ""
		if p.User != nil {
			usr = p.User.Username()
			pw, _ = p.User.Password()
		}
		wc := func(pOff, lOff uint64, val string) {
			ptr, _ := mem.Read64(comp + pOff)
			ml, _ := mem.Read32(comp + lOff)
			if ptr != 0 && ml > 0 {
				if wide {
					writeWide(ptr, val, int(ml))
				} else {
					writeAnsiStr(ptr, val, int(ml))
				}
			}
			mem.Write32(comp+lOff, uint32(len(val)))
		}
		wc(8, 16, sc)
		mem.Write32(comp+20, ns)
		wc(24, 32, ho)
		mem.Write16(comp+36, po)
		wc(40, 48, usr)
		wc(56, 64, pw)
		wc(72, 80, pa)
		wc(88, 96, ex)
		setErr(0)
		ctx.SetReturn(1)
		return 0
	}
	d.RegisterAutoStubHandler(dll, "InternetCrackUrlW", func(ctx *ntapi.TrapContext) uint32 {
		n := int(int32(ctx.Arg(1)))
		var u string
		if n > 0 {
			u = readWN(ctx.Arg(0), n)
		} else {
			u = readW(ctx.Arg(0))
		}
		return crack(ctx, u, ctx.Arg(3), true)
	})
	d.RegisterAutoStubHandler(dll, "InternetCrackUrlA", func(ctx *ntapi.TrapContext) uint32 {
		n := int(int32(ctx.Arg(1)))
		var u string
		if n > 0 {
			r, e := mem.ReadBytes(ctx.Arg(0), n)
			if e == nil {
				u = string(r)
			}
		} else {
			u = readA(ctx.Arg(0))
		}
		return crack(ctx, u, ctx.Arg(3), false)
	})

	// HttpAddRequestHeadersW/A
	d.RegisterAutoStubHandler(dll, "HttpAddRequestHeadersW", func(ctx *ntapi.TrapContext) uint32 {
		rq := resolveInet(ntapi.Handle(ctx.Arg(0)))
		if rq == nil || rq.kind != inetKindRequest {
			setErr(errInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		n := int(int32(ctx.Arg(2)))
		var h string
		if n < 0 {
			h = readW(ctx.Arg(1))
		} else {
			h = readWN(ctx.Arg(1), n)
		}
		for _, line := range strings.Split(h, "\r\n") {
			if idx := strings.Index(line, ":"); idx > 0 {
				rq.reqHeaders.Add(strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:]))
			}
		}
		setErr(0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "HttpAddRequestHeadersA", func(ctx *ntapi.TrapContext) uint32 {
		rq := resolveInet(ntapi.Handle(ctx.Arg(0)))
		if rq == nil || rq.kind != inetKindRequest {
			setErr(errInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		n := int(int32(ctx.Arg(2)))
		var h string
		if n < 0 {
			h = readA(ctx.Arg(1))
		} else {
			r, e := mem.ReadBytes(ctx.Arg(1), n)
			if e == nil {
				h = string(r)
			}
		}
		for _, line := range strings.Split(h, "\r\n") {
			if idx := strings.Index(line, ":"); idx > 0 {
				rq.reqHeaders.Add(strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:]))
			}
		}
		setErr(0)
		ctx.SetReturn(1)
		return 0
	})
}
