package main

import (
	"math"
	gorand "math/rand"
	"os"
	"strconv"
	"strings"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func registerMsvcrtHandlers(hctx *HandlerCtx) {
	argv := hctx.Argv
	crtStreamWriter := hctx.CrtStreamWriter
	d := hctx.Disp
	mem := hctx.Mem
	readGuestString := hctx.ReadGuestString
	readGuestUTF16 := hctx.ReadGuestUTF16
	sharedHeapAlloc := hctx.HeapAlloc
	sharedHeapFree := hctx.HeapFree
	wideprintf := hctx.Wideprintf

	msvcrt, ok := hctx.SynthByName["msvcrt.dll"]
	if !ok {
		return
	}
	_ = msvcrt

	msvcrtRng := gorand.New(gorand.NewSource(1))

	// _initterm: void _initterm(void (**begin)(void), void (**end)(void))
	// Walks an array of function pointers [begin, end) and calls each non-NULL one.
	d.RegisterAutoStubHandler(msvcrt, "_initterm", func(ctx *ntapi.TrapContext) uint32 {
		begin := ctx.Arg(0)
		end := ctx.Arg(1)
		var fns []uint64
		for ptr := begin; ptr < end; ptr += 8 {
			fp, _ := mem.Read64(ptr)
			if fp != 0 {
				fns = append(fns, fp)
			}
		}
		if len(fns) == 0 {
			return 0
		}
		_, ok := ctx.CPU.(ntapi.RegisterWriter)
		rr, ok2 := ctx.CPU.(ntapi.RegisterReader)
		if !ok || !ok2 {
			return 0
		}
		rsp := rr.ReadReg(4)
		retAddr, _ := mem.Read64(rsp)
		var queue []syncDispatch
		for _, fp := range fns[1:] {
			queue = append(queue, syncDispatch{wndProc: fp})
		}
		hctx.SyncStack = append(hctx.SyncStack, syncDispatchFrame{
			queue:   queue,
			retAddr: retAddr,
			hwnd:    0,
		})
		mem.Write64(rsp, hctx.SyncTrampoline)
		ctx.CPU.SetPC(fns[0])
		ctx.ReturnOverridden = true
		ctx.PCRedirected = true
		return 0
	})

	// __getmainargs: int __getmainargs(int *_Argc, char ***_Argv, char ***_Env, int _DoWildCard, _startupinfo *_StartInfo)
	d.RegisterAutoStubHandler(msvcrt, "__getmainargs", func(ctx *ntapi.TrapContext) uint32 {
		pArgc := ctx.Arg(0)
		pArgv := ctx.Arg(1)
		pEnv := ctx.Arg(2)

		// Allocate argv array in guest memory
		argc := len(argv)
		// argv needs: (argc+1) pointers + string data
		totalStrLen := 0
		for _, a := range argv {
			totalStrLen += len(a) + 1
		}
		argvBuf := mem.Mmap(0, uint64(8*(argc+1)+totalStrLen+64), mmu.PermRead|mmu.PermWrite)
		strOff := argvBuf + uint64(8*(argc+1))
		for i, a := range argv {
			mem.Write64(argvBuf+uint64(i*8), strOff)
			mem.WriteBytes(strOff, append([]byte(a), 0))
			strOff += uint64(len(a) + 1)
		}
		mem.Write64(argvBuf+uint64(argc*8), 0) // null terminator

		// Write results
		mem.Write32(pArgc, uint32(argc))
		mem.Write64(pArgv, argvBuf)

		// Empty environment
		envBuf := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
		mem.Write64(envBuf, 0) // null-terminated env array
		mem.Write64(pEnv, envBuf)

		return 0
	})

	// __set_app_type, __setusermatherr, __lconv_init: no-ops
	for _, name := range []string{"__set_app_type", "__setusermatherr", "__lconv_init", "_lock", "_unlock", "signal"} {
		d.RegisterAutoStubHandler(msvcrt, name, func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
	}

	// __C_specific_handler: SEH - return ExceptionContinueSearch (1)
	d.RegisterAutoStubHandler(msvcrt, "__C_specific_handler", func(ctx *ntapi.TrapContext) uint32 {
		return 1
	})

	// ___lc_codepage_func: returns pointer to int (code page)
	d.RegisterAutoStubHandler(msvcrt, "___lc_codepage_func", func(ctx *ntapi.TrapContext) uint32 {
		buf := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
		mem.Write32(buf, 65001) // UTF-8
		ctx.SetReturn(buf)
		return 0 // return value is in RAX, overridden above
	})

	// ___mb_cur_max_func: returns pointer to int (__mb_cur_max)
	d.RegisterAutoStubHandler(msvcrt, "___mb_cur_max_func", func(ctx *ntapi.TrapContext) uint32 {
		buf := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
		mem.Write32(buf, 1)
		ctx.SetReturn(buf)
		return 0
	})

	// __iob_func: returns pointer to FILE[3] (stdin, stdout, stderr)
	// MSVC FILE struct is 48 bytes on x64
	iobBuf := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
	iobBase := iobBuf
	const iobStride = 48 // sizeof(FILE) on MSVC x64
	d.RegisterAutoStubHandler(msvcrt, "__iob_func", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(iobBuf)
		return 0
	})

	// malloc / calloc / free / _onexit / _cexit / _amsg_exit / abort / exit
	d.RegisterAutoStubHandler(msvcrt, "malloc", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sharedHeapAlloc(ctx.Arg(0), false))
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "calloc", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sharedHeapAlloc(ctx.Arg(0)*ctx.Arg(1), true))
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "free", func(ctx *ntapi.TrapContext) uint32 {
		sharedHeapFree(ctx.Arg(0))
		return 0
	})

	d.RegisterAutoStubHandler(msvcrt, "_strdup", func(ctx *ntapi.TrapContext) uint32 {
		src := ctx.Arg(0)
		if src == 0 {
			ctx.SetReturn(0)
			return 0
		}
		var buf []byte
		for i := uint64(0); i < 0x100000; i++ {
			b, _ := mem.Read8(src + i)
			buf = append(buf, b)
			if b == 0 {
				break
			}
		}
		dst := sharedHeapAlloc(uint64(len(buf)+1), false)
		mem.WriteBytes(dst, buf)
		ctx.SetReturn(dst)
		return 0
	})

	// String functions that are safer to implement in Go
	d.RegisterAutoStubHandler(msvcrt, "strlen", func(ctx *ntapi.TrapContext) uint32 {
		s := ctx.Arg(0)
		n := uint64(0)
		for {
			b, err := ctx.Mem.Read8(s + n)
			if err != nil || b == 0 {
				break
			}
			n++
		}
		ctx.SetReturn(n)
		return 0
	})

	d.RegisterAutoStubHandler(msvcrt, "memcpy", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		n := ctx.Arg(2)
		for i := uint64(0); i < n; i++ {
			b, _ := ctx.Mem.Read8(src + i)
			ctx.Mem.Write8(dst+i, b)
		}
		ctx.SetReturn(dst)
		return 0
	})

	d.RegisterAutoStubHandler(msvcrt, "memset", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		val := byte(ctx.Arg(1))
		n := ctx.Arg(2)
		for i := uint64(0); i < n; i++ {
			ctx.Mem.Write8(dst+i, val)
		}
		ctx.SetReturn(dst)
		return 0
	})

	d.RegisterAutoStubHandler(msvcrt, "memcmp", func(ctx *ntapi.TrapContext) uint32 {
		s1 := ctx.Arg(0)
		s2 := ctx.Arg(1)
		n := ctx.Arg(2)
		for i := uint64(0); i < n; i++ {
			b1, _ := ctx.Mem.Read8(s1 + i)
			b2, _ := ctx.Mem.Read8(s2 + i)
			if b1 < b2 {
				ctx.SetReturn(^uint64(0)) // -1
				return 0
			}
			if b1 > b2 {
				ctx.SetReturn(1)
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(msvcrt, "exit", func(ctx *ntapi.TrapContext) uint32 {
		ctx.CPU.Stop()
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "abort", func(ctx *ntapi.TrapContext) uint32 {
		ctx.CPU.Stop()
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "_cexit", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "_amsg_exit", func(ctx *ntapi.TrapContext) uint32 {
		ctx.CPU.Stop()
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "_onexit", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(ctx.Arg(0))
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "_errno", func(ctx *ntapi.TrapContext) uint32 {
		buf := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
		ctx.SetReturn(buf)
		return 0
	})

	// strncpy: char* strncpy(char *dst, const char *src, size_t n)
	d.RegisterAutoStubHandler(msvcrt, "strncpy", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		n := ctx.Arg(2)
		i := uint64(0)
		for ; i < n; i++ {
			b, _ := ctx.Mem.Read8(src + i)
			ctx.Mem.Write8(dst+i, b)
			if b == 0 {
				i++
				break
			}
		}
		for ; i < n; i++ {
			ctx.Mem.Write8(dst+i, 0)
		}
		ctx.SetReturn(dst)
		return 0
	})

	// strncat: char* strncat(char *dst, const char *src, size_t n)
	d.RegisterAutoStubHandler(msvcrt, "strncat", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		n := ctx.Arg(2)
		// Find end of dst
		dstEnd := dst
		for {
			b, _ := ctx.Mem.Read8(dstEnd)
			if b == 0 {
				break
			}
			dstEnd++
		}
		for i := uint64(0); i < n; i++ {
			b, _ := ctx.Mem.Read8(src + i)
			if b == 0 {
				break
			}
			ctx.Mem.Write8(dstEnd+i, b)
			ctx.Mem.Write8(dstEnd+i+1, 0) // always null-terminate
		}
		ctx.SetReturn(dst)
		return 0
	})

	// strncmp: int strncmp(const char *s1, const char *s2, size_t n)
	d.RegisterAutoStubHandler(msvcrt, "strncmp", func(ctx *ntapi.TrapContext) uint32 {
		s1 := ctx.Arg(0)
		s2 := ctx.Arg(1)
		n := ctx.Arg(2)
		for i := uint64(0); i < n; i++ {
			b1, _ := ctx.Mem.Read8(s1 + i)
			b2, _ := ctx.Mem.Read8(s2 + i)
			if b1 < b2 {
				ctx.SetReturn(^uint64(0))
				return 0
			}
			if b1 > b2 {
				ctx.SetReturn(1)
				return 0
			}
			if b1 == 0 {
				break
			}
		}
		ctx.SetReturn(0)
		return 0
	})

	// strstr: char* strstr(const char *haystack, const char *needle)
	d.RegisterAutoStubHandler(msvcrt, "strstr", func(ctx *ntapi.TrapContext) uint32 {
		haystack := ctx.Arg(0)
		needle := ctx.Arg(1)
		// Get needle length
		nLen := uint64(0)
		for {
			b, _ := ctx.Mem.Read8(needle + nLen)
			if b == 0 {
				break
			}
			nLen++
		}
		if nLen == 0 {
			ctx.SetReturn(haystack)
			return 0
		}
		for i := uint64(0); ; i++ {
			b, _ := ctx.Mem.Read8(haystack + i)
			if b == 0 {
				break
			}
			match := true
			for j := uint64(0); j < nLen; j++ {
				h, _ := ctx.Mem.Read8(haystack + i + j)
				n, _ := ctx.Mem.Read8(needle + j)
				if h != n {
					match = false
					break
				}
			}
			if match {
				ctx.SetReturn(haystack + i)
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})

	// toupper
	d.RegisterAutoStubHandler(msvcrt, "toupper", func(ctx *ntapi.TrapContext) uint32 {
		c := ctx.Arg(0)
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		ctx.SetReturn(c)
		return 0
	})

	// fopen / fclose / fputs / fputc / fprintf / fwrite / vfprintf
	d.RegisterAutoStubHandler(msvcrt, "fopen", func(ctx *ntapi.TrapContext) uint32 {
		pathAddr := ctx.Arg(0)
		modeAddr := ctx.Arg(1)
		path := readGuestString(pathAddr)
		mode := readGuestString(modeAddr)
		hostPath := winPathToVFS(path)
		var flag int
		switch {
		case strings.HasPrefix(mode, "r+") || strings.HasPrefix(mode, "rb+"):
			flag = os.O_RDWR
		case strings.HasPrefix(mode, "w+") || strings.HasPrefix(mode, "wb+"):
			flag = os.O_RDWR | os.O_CREATE | os.O_TRUNC
		case strings.HasPrefix(mode, "a+") || strings.HasPrefix(mode, "ab+"):
			flag = os.O_RDWR | os.O_CREATE | os.O_APPEND
		case strings.HasPrefix(mode, "r") || strings.HasPrefix(mode, "rb"):
			flag = os.O_RDONLY
		case strings.HasPrefix(mode, "w") || strings.HasPrefix(mode, "wb"):
			flag = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
		case strings.HasPrefix(mode, "a") || strings.HasPrefix(mode, "ab"):
			flag = os.O_WRONLY | os.O_CREATE | os.O_APPEND
		default:
			flag = os.O_RDONLY
		}
		f, err := os.OpenFile(hostPath, flag, 0644)
		if err != nil {
			ctx.SetReturn(0)
			return 0
		}
		fp := hctx.CrtNextFP
		hctx.CrtNextFP += 64
		hctx.CrtFiles[fp] = f
		ctx.SetReturn(fp)
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "fclose", func(ctx *ntapi.TrapContext) uint32 {
		fp := ctx.Arg(0)
		if f, ok := hctx.CrtFiles[fp]; ok {
			f.Close()
			delete(hctx.CrtFiles, fp)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "fputs", func(ctx *ntapi.TrapContext) uint32 {
		str := readGuestString(ctx.Arg(0))
		stream := ctx.Arg(1)
		if stream == iobBase+iobStride*2 {
			os.Stderr.WriteString(str)
		} else if stream == iobBase+iobStride {
			os.Stdout.WriteString(str)
		} else if f, ok := hctx.CrtFiles[stream]; ok {
			f.WriteString(str)
		} else {
			os.Stdout.WriteString(str)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "fputc", func(ctx *ntapi.TrapContext) uint32 {
		c := byte(ctx.Arg(0))
		stream := ctx.Arg(1)
		switch {
		case stream == iobBase+iobStride*2:
			os.Stderr.Write([]byte{c})
		case stream == iobBase+iobStride:
			os.Stdout.Write([]byte{c})
		default:
			if f, ok := hctx.CrtFiles[stream]; ok {
				f.Write([]byte{c})
			} else {
				os.Stdout.Write([]byte{c})
			}
		}
		ctx.SetReturn(uint64(c))
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "fprintf", func(ctx *ntapi.TrapContext) uint32 {
		stream := ctx.Arg(0)
		fmtAddr := ctx.Arg(1)
		if fmtAddr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		fmtStr := readGuestString(fmtAddr)
		var args []uint64
		for i := 2; i < 10; i++ {
			args = append(args, ctx.Arg(i))
		}
		result := wideprintf(fmtStr, args)
		w := crtStreamWriter(stream, iobBase, iobStride)
		w.WriteString(result)
		ctx.SetReturn(uint64(len(result)))
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "vfprintf", func(ctx *ntapi.TrapContext) uint32 {
		stream := ctx.Arg(0)
		fmtAddr := ctx.Arg(1)
		// va_list is a pointer to the args on guest stack
		vaList := ctx.Arg(2)
		if fmtAddr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		fmtStr := readGuestString(fmtAddr)
		var args []uint64
		if vaList != 0 {
			for i := 0; i < 8; i++ {
				v, _ := mem.Read64(vaList + uint64(i)*8)
				args = append(args, v)
			}
		}
		result := wideprintf(fmtStr, args)
		w := crtStreamWriter(stream, iobBase, iobStride)
		w.WriteString(result)
		ctx.SetReturn(uint64(len(result)))
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "fwrite", func(ctx *ntapi.TrapContext) uint32 {
		bufAddr := ctx.Arg(0)
		size := ctx.Arg(1)
		count := ctx.Arg(2)
		stream := ctx.Arg(3)
		totalBytes := size * count
		if totalBytes > 0 && totalBytes < 0x100000 {
			data := make([]byte, totalBytes)
			for i := uint64(0); i < totalBytes; i++ {
				data[i], _ = mem.Read8(bufAddr + i)
			}
			if stream == iobBase+iobStride*2 {
				os.Stderr.Write(data)
			} else if stream == iobBase+iobStride || stream == iobBase {
				// stdin or unknown - skip
			} else {
				os.Stdout.Write(data)
			}
		}
		ctx.SetReturn(count)
		return 0
	})

	// rand / srand
	d.RegisterAutoStubHandler(msvcrt, "rand", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(msvcrtRng.Int31n(0x7FFF + 1))) // RAND_MAX = 0x7FFF
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "srand", func(ctx *ntapi.TrapContext) uint32 {
		seed := ctx.Arg(0)
		msvcrtRng = gorand.New(gorand.NewSource(int64(seed)))
		return 0
	})

	// getchar
	d.RegisterAutoStubHandler(msvcrt, "getchar", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(10) // newline
		return 0
	})

	// localeconv
	d.RegisterAutoStubHandler(msvcrt, "localeconv", func(ctx *ntapi.TrapContext) uint32 {
		buf := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
		// Write minimal lconv with "." as decimal point
		ctx.Mem.Write8(buf+0x100, '.')
		ctx.Mem.Write8(buf+0x101, 0)
		ctx.Mem.Write64(buf, buf+0x100) // decimal_point
		ctx.SetReturn(buf)
		return 0
	})

	// mbstowcs
	d.RegisterAutoStubHandler(msvcrt, "mbstowcs", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		n := ctx.Arg(2)
		i := uint64(0)
		for ; i < n; i++ {
			b, _ := ctx.Mem.Read8(src + i)
			if dst != 0 {
				ctx.Mem.Write16(dst+i*2, uint16(b))
			}
			if b == 0 {
				break
			}
		}
		ctx.SetReturn(i)
		return 0
	})

	// wcslen
	d.RegisterAutoStubHandler(msvcrt, "wcslen", func(ctx *ntapi.TrapContext) uint32 {
		s := ctx.Arg(0)
		n := uint64(0)
		for {
			w, _ := ctx.Mem.Read16(s + n*2)
			if w == 0 {
				break
			}
			n++
		}
		ctx.SetReturn(n)
		return 0
	})

	// wcsstr
	d.RegisterAutoStubHandler(msvcrt, "wcsstr", func(ctx *ntapi.TrapContext) uint32 {
		haystack := ctx.Arg(0)
		needle := ctx.Arg(1)
		nLen := uint64(0)
		for {
			w, _ := ctx.Mem.Read16(needle + nLen*2)
			if w == 0 {
				break
			}
			nLen++
		}
		if nLen == 0 {
			ctx.SetReturn(haystack)
			return 0
		}
		for i := uint64(0); ; i++ {
			w, _ := ctx.Mem.Read16(haystack + i*2)
			if w == 0 {
				break
			}
			match := true
			for j := uint64(0); j < nLen; j++ {
				h, _ := ctx.Mem.Read16(haystack + (i+j)*2)
				n, _ := ctx.Mem.Read16(needle + j*2)
				if h != n {
					match = false
					break
				}
			}
			if match {
				ctx.SetReturn(haystack + i*2)
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})

	// strerror
	d.RegisterAutoStubHandler(msvcrt, "strerror", func(ctx *ntapi.TrapContext) uint32 {
		buf := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
		msg := []byte("Unknown error\x00")
		ctx.Mem.WriteBytes(buf, msg)
		ctx.SetReturn(buf)
		return 0
	})

	// sprintf(buf, fmt, ...) - msvcrt uses cdecl with args on stack/registers
	d.RegisterAutoStubHandler(msvcrt, "sprintf", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		fmtAddr := ctx.Arg(1)
		if fmtAddr == 0 || buf == 0 {
			ctx.SetReturn(0)
			return 0
		}
		fmtStr := readGuestString(fmtAddr)
		var args []uint64
		for i := 2; i < 10; i++ {
			args = append(args, ctx.Arg(i))
		}
		result := wideprintf(fmtStr, args)
		for i := 0; i < len(result); i++ {
			mem.Write8(buf+uint64(i), result[i])
		}
		mem.Write8(buf+uint64(len(result)), 0)
		ctx.SetReturn(uint64(len(result)))
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "_snprintf", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		count := ctx.Arg(1)
		fmtAddr := ctx.Arg(2)
		if fmtAddr == 0 || buf == 0 || count == 0 {
			ctx.SetReturn(0)
			return 0
		}
		fmtStr := readGuestString(fmtAddr)
		var args []uint64
		for i := 3; i < 11; i++ {
			args = append(args, ctx.Arg(i))
		}
		result := wideprintf(fmtStr, args)
		n := len(result)
		if uint64(n) >= count {
			n = int(count) - 1
		}
		for i := 0; i < n; i++ {
			mem.Write8(buf+uint64(i), result[i])
		}
		mem.Write8(buf+uint64(n), 0)
		ctx.SetReturn(uint64(n))
		return 0
	})

	// --- msvcrt math functions (float64 in XMM0/XMM1, return in XMM0) ---
	mathUnary := func(name string, fn func(float64) float64) {
		d.RegisterAutoStubHandler(msvcrt, name, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetFloatReturn(fn(ctx.FloatArg(0)))
			return 0
		})
	}
	mathBinary := func(name string, fn func(float64, float64) float64) {
		d.RegisterAutoStubHandler(msvcrt, name, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetFloatReturn(fn(ctx.FloatArg(0), ctx.FloatArg(1)))
			return 0
		})
	}
	mathUnary("floor", math.Floor)
	mathUnary("ceil", math.Ceil)
	mathUnary("sqrt", math.Sqrt)
	mathUnary("sin", math.Sin)
	mathUnary("cos", math.Cos)
	mathUnary("tan", math.Tan)
	mathUnary("asin", math.Asin)
	mathUnary("acos", math.Acos)
	mathUnary("atan", math.Atan)
	mathUnary("log", math.Log)
	mathUnary("log10", math.Log10)
	mathUnary("log2", math.Log2)
	mathUnary("exp", math.Exp)
	mathUnary("fabs", math.Abs)
	mathUnary("round", math.Round)
	mathUnary("trunc", math.Trunc)
	mathBinary("pow", math.Pow)
	mathBinary("fmod", math.Mod)
	mathBinary("atan2", math.Atan2)
	d.RegisterAutoStubHandler(msvcrt, "ldexp", func(ctx *ntapi.TrapContext) uint32 {
		x := ctx.FloatArg(0)
		exp := int(int32(ctx.Arg(1))) // second arg is int, passed in RDX
		ctx.SetFloatReturn(math.Ldexp(x, exp))
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "frexp", func(ctx *ntapi.TrapContext) uint32 {
		x := ctx.FloatArg(0)
		expPtr := ctx.Arg(1) // int* passed in RDX
		frac, exp := math.Frexp(x)
		if expPtr != 0 {
			mem.Write32(expPtr, uint32(int32(exp)))
		}
		ctx.SetFloatReturn(frac)
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "modf", func(ctx *ntapi.TrapContext) uint32 {
		x := ctx.FloatArg(0)
		intPtr := ctx.Arg(1) // double* passed in RDX
		intPart, frac := math.Modf(x)
		if intPtr != 0 {
			mem.Write64(intPtr, math.Float64bits(intPart))
		}
		ctx.SetFloatReturn(frac)
		return 0
	})
	// Float versions (suffixed f)
	mathUnary("floorf", math.Floor)
	mathUnary("ceilf", math.Ceil)
	mathUnary("sqrtf", math.Sqrt)
	mathUnary("sinf", math.Sin)
	mathUnary("cosf", math.Cos)
	mathUnary("tanf", math.Tan)
	mathUnary("logf", math.Log)
	mathUnary("expf", math.Exp)
	mathUnary("fabsf", math.Abs)
	mathUnary("roundf", math.Round)
	mathUnary("truncf", math.Trunc)
	mathBinary("powf", math.Pow)
	mathBinary("fmodf", math.Mod)

	// Missing string/conversion functions in msvcrt
	d.RegisterAutoStubHandler(msvcrt, "atoi", func(ctx *ntapi.TrapContext) uint32 {
		s := readGuestString(ctx.Arg(0))
		v, _ := strconv.Atoi(s)
		ctx.SetReturn(uint64(int64(int32(v))))
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "atol", func(ctx *ntapi.TrapContext) uint32 {
		s := readGuestString(ctx.Arg(0))
		v, _ := strconv.Atoi(s)
		ctx.SetReturn(uint64(int64(int32(v))))
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "atof", func(ctx *ntapi.TrapContext) uint32 {
		s := readGuestString(ctx.Arg(0))
		v, _ := strconv.ParseFloat(s, 64)
		ctx.SetFloatReturn(v)
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "strtod", func(ctx *ntapi.TrapContext) uint32 {
		s := readGuestString(ctx.Arg(0))
		endPtr := ctx.Arg(1)
		v, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if endPtr != 0 {
			// Write pointer past consumed chars (simplified: point to end of string)
			mem.Write64(endPtr, ctx.Arg(0)+uint64(len(s)))
		}
		ctx.SetFloatReturn(v)
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "strtol", func(ctx *ntapi.TrapContext) uint32 {
		s := readGuestString(ctx.Arg(0))
		base := int(ctx.Arg(2))
		if base == 0 {
			base = 10
		}
		v, _ := strconv.ParseInt(strings.TrimSpace(s), base, 32)
		ctx.SetReturn(uint64(int64(int32(v))))
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "strtoul", func(ctx *ntapi.TrapContext) uint32 {
		s := readGuestString(ctx.Arg(0))
		base := int(ctx.Arg(2))
		if base == 0 {
			base = 10
		}
		v, _ := strconv.ParseUint(strings.TrimSpace(s), base, 32)
		ctx.SetReturn(uint64(uint32(v)))
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "strcmp", func(ctx *ntapi.TrapContext) uint32 {
		s1 := readGuestString(ctx.Arg(0))
		s2 := readGuestString(ctx.Arg(1))
		ctx.SetReturn(uint64(int64(int32(strings.Compare(s1, s2)))))
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "strcpy", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		s := readGuestString(src)
		for i := 0; i <= len(s); i++ {
			if i < len(s) {
				mem.Write8(dst+uint64(i), s[i])
			} else {
				mem.Write8(dst+uint64(i), 0)
			}
		}
		ctx.SetReturn(dst)
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "strcat", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		// Find end of dst
		end := dst
		for {
			b, _ := mem.Read8(end)
			if b == 0 {
				break
			}
			end++
		}
		s := readGuestString(src)
		for i := 0; i <= len(s); i++ {
			if i < len(s) {
				mem.Write8(end+uint64(i), s[i])
			} else {
				mem.Write8(end+uint64(i), 0)
			}
		}
		ctx.SetReturn(dst)
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "strchr", func(ctx *ntapi.TrapContext) uint32 {
		s := ctx.Arg(0)
		ch := byte(ctx.Arg(1))
		for {
			b, _ := mem.Read8(s)
			if b == ch {
				ctx.SetReturn(s)
				return 0
			}
			if b == 0 {
				ctx.SetReturn(0)
				return 0
			}
			s++
		}
	})
	d.RegisterAutoStubHandler(msvcrt, "strrchr", func(ctx *ntapi.TrapContext) uint32 {
		s := ctx.Arg(0)
		ch := byte(ctx.Arg(1))
		var last uint64
		for {
			b, _ := mem.Read8(s)
			if b == ch {
				last = s
			}
			if b == 0 {
				ctx.SetReturn(last)
				return 0
			}
			s++
		}
	})
	d.RegisterAutoStubHandler(msvcrt, "memchr", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		ch := byte(ctx.Arg(1))
		n := ctx.Arg(2)
		for i := uint64(0); i < n; i++ {
			b, _ := mem.Read8(buf + i)
			if b == ch {
				ctx.SetReturn(buf + i)
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "memmove", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		n := ctx.Arg(2)
		if n == 0 {
			ctx.SetReturn(dst)
			return 0
		}
		tmp := make([]byte, n)
		for i := uint64(0); i < n; i++ {
			tmp[i], _ = mem.Read8(src + i)
		}
		for i := uint64(0); i < n; i++ {
			mem.Write8(dst+i, tmp[i])
		}
		ctx.SetReturn(dst)
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "_stricmp", func(ctx *ntapi.TrapContext) uint32 {
		s1 := readGuestString(ctx.Arg(0))
		s2 := readGuestString(ctx.Arg(1))
		ctx.SetReturn(uint64(int64(int32(strings.Compare(strings.ToLower(s1), strings.ToLower(s2))))))
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "_strnicmp", func(ctx *ntapi.TrapContext) uint32 {
		s1 := readGuestString(ctx.Arg(0))
		s2 := readGuestString(ctx.Arg(1))
		n := int(ctx.Arg(2))
		if n < len(s1) {
			s1 = s1[:n]
		}
		if n < len(s2) {
			s2 = s2[:n]
		}
		ctx.SetReturn(uint64(int64(int32(strings.Compare(strings.ToLower(s1), strings.ToLower(s2))))))
		return 0
	})

	// ctype functions for msvcrt
	d.RegisterAutoStubHandler(msvcrt, "isalpha", func(ctx *ntapi.TrapContext) uint32 {
		c := byte(ctx.Arg(0))
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "isdigit", func(ctx *ntapi.TrapContext) uint32 {
		c := byte(ctx.Arg(0))
		if c >= '0' && c <= '9' {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "isalnum", func(ctx *ntapi.TrapContext) uint32 {
		c := byte(ctx.Arg(0))
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "isspace", func(ctx *ntapi.TrapContext) uint32 {
		c := byte(ctx.Arg(0))
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "isupper", func(ctx *ntapi.TrapContext) uint32 {
		c := byte(ctx.Arg(0))
		if c >= 'A' && c <= 'Z' {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "islower", func(ctx *ntapi.TrapContext) uint32 {
		c := byte(ctx.Arg(0))
		if c >= 'a' && c <= 'z' {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "tolower", func(ctx *ntapi.TrapContext) uint32 {
		c := byte(ctx.Arg(0))
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		ctx.SetReturn(uint64(c))
		return 0
	})

	// File I/O for msvcrt - real implementations using hctx.CrtFiles
	d.RegisterAutoStubHandler(msvcrt, "fread", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		size := ctx.Arg(1)
		count := ctx.Arg(2)
		fp := ctx.Arg(3)
		total := size * count
		if total == 0 || buf == 0 {
			ctx.SetReturn(0)
			return 0
		}
		f, ok := hctx.CrtFiles[fp]
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		tmp := make([]byte, total)
		n, _ := f.Read(tmp)
		if n > 0 {
			mem.WriteBytes(buf, tmp[:n])
		}
		if size > 0 {
			ctx.SetReturn(uint64(n) / size)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "fseek", func(ctx *ntapi.TrapContext) uint32 {
		fp := ctx.Arg(0)
		offset := int64(ctx.Arg(1))
		whence := int(ctx.Arg(2))
		f, ok := hctx.CrtFiles[fp]
		if !ok {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		_, err := f.Seek(offset, whence)
		if err != nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "ftell", func(ctx *ntapi.TrapContext) uint32 {
		fp := ctx.Arg(0)
		f, ok := hctx.CrtFiles[fp]
		if !ok {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		pos, _ := f.Seek(0, 1)
		ctx.SetReturn(uint64(pos))
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "fflush", func(ctx *ntapi.TrapContext) uint32 {
		fp := ctx.Arg(0)
		if f, ok := hctx.CrtFiles[fp]; ok {
			f.Sync()
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "feof", func(ctx *ntapi.TrapContext) uint32 {
		fp := ctx.Arg(0)
		f, ok := hctx.CrtFiles[fp]
		if !ok {
			ctx.SetReturn(1)
			return 0
		}
		cur, _ := f.Seek(0, 1)
		end, _ := f.Seek(0, 2)
		f.Seek(cur, 0)
		if cur >= end {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "ferror", func(ctx *ntapi.TrapContext) uint32 {
		fp := ctx.Arg(0)
		// CRT ferror checks the error indicator on the stream
		// We don't track per-stream error state; report no error if the file exists
		if _, ok := hctx.CrtFiles[fp]; ok {
			ctx.SetReturn(0)
		} else {
			ravelog.Logf("[msvcrt] ferror: unknown stream 0x%x\n", fp)
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "fgets", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		n := int(ctx.Arg(1))
		fp := ctx.Arg(2)
		if buf == 0 || n <= 0 {
			ctx.SetReturn(0)
			return 0
		}
		f, ok := hctx.CrtFiles[fp]
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		tmp := make([]byte, n-1)
		read, _ := f.Read(tmp)
		if read == 0 {
			ctx.SetReturn(0)
			return 0
		}
		end := read
		for i := 0; i < read; i++ {
			if tmp[i] == '\n' {
				end = i + 1
				break
			}
		}
		if end < read {
			f.Seek(int64(end-read), 1)
		}
		mem.WriteBytes(buf, tmp[:end])
		mem.Write8(buf+uint64(end), 0)
		ctx.SetReturn(buf)
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "_wfopen", func(ctx *ntapi.TrapContext) uint32 {
		pathAddr := ctx.Arg(0)
		modeAddr := ctx.Arg(1)
		path := readGuestUTF16(pathAddr)
		mode := readGuestUTF16(modeAddr)
		hostPath := winPathToVFS(path)
		var flag int
		switch {
		case strings.HasPrefix(mode, "r+") || strings.HasPrefix(mode, "rb+"):
			flag = os.O_RDWR
		case strings.HasPrefix(mode, "w+") || strings.HasPrefix(mode, "wb+"):
			flag = os.O_RDWR | os.O_CREATE | os.O_TRUNC
		case strings.HasPrefix(mode, "a+") || strings.HasPrefix(mode, "ab+"):
			flag = os.O_RDWR | os.O_CREATE | os.O_APPEND
		case strings.HasPrefix(mode, "r") || strings.HasPrefix(mode, "rb"):
			flag = os.O_RDONLY
		case strings.HasPrefix(mode, "w") || strings.HasPrefix(mode, "wb"):
			flag = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
		case strings.HasPrefix(mode, "a") || strings.HasPrefix(mode, "ab"):
			flag = os.O_WRONLY | os.O_CREATE | os.O_APPEND
		default:
			flag = os.O_RDONLY
		}
		f, err := os.OpenFile(hostPath, flag, 0644)
		if err != nil {
			ctx.SetReturn(0)
			return 0
		}
		fp := hctx.CrtNextFP
		hctx.CrtNextFP += 64
		hctx.CrtFiles[fp] = f
		ctx.SetReturn(fp)
		return 0
	})
	// setlocale - return pointer to "C" locale string
	d.RegisterAutoStubHandler(msvcrt, "setlocale", func(ctx *ntapi.TrapContext) uint32 {
		buf := mem.Mmap(0, 8, mmu.PermRead|mmu.PermWrite)
		mem.Write8(buf, 'C')
		mem.Write8(buf+1, 0)
		ctx.SetReturn(buf)
		return 0
	})
	// _configthreadlocale
	d.RegisterAutoStubHandler(msvcrt, "_configthreadlocale", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // _DISABLE_PER_THREAD_LOCALE
		return 0
	})
	// printf - print to stdout
	d.RegisterAutoStubHandler(msvcrt, "printf", func(ctx *ntapi.TrapContext) uint32 {
		fmtAddr := ctx.Arg(0)
		if fmtAddr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		fmtStr := readGuestString(fmtAddr)
		var args []uint64
		for i := 1; i < 10; i++ {
			args = append(args, ctx.Arg(i))
		}
		result := wideprintf(fmtStr, args)
		os.Stdout.WriteString(result)
		ctx.SetReturn(uint64(len(result)))
		return 0
	})
	// _snwprintf - wide-char snprintf
	d.RegisterAutoStubHandler(msvcrt, "_snwprintf", func(ctx *ntapi.TrapContext) uint32 {
		lpOut := ctx.Arg(0)
		count := ctx.Arg(1)
		lpFmt := ctx.Arg(2)
		if lpFmt == 0 || lpOut == 0 || count == 0 {
			ctx.SetReturn(0)
			return 0
		}
		fmtStr := readGuestUTF16(lpFmt)
		var args []uint64
		for i := 3; i < 10; i++ {
			args = append(args, ctx.Arg(i))
		}
		result := wideprintf(fmtStr, args)
		runes := []rune(result)
		maxChars := int(count)
		if maxChars > 0 && len(runes) >= maxChars {
			runes = runes[:maxChars-1]
		}
		for i, r := range runes {
			mem.Write16(lpOut+uint64(i)*2, uint16(r))
		}
		mem.Write16(lpOut+uint64(len(runes))*2, 0)
		ctx.SetReturn(uint64(len(runes)))
		return 0
	})

	// realloc: resize heap allocation
	d.RegisterAutoStubHandler(msvcrt, "realloc", func(ctx *ntapi.TrapContext) uint32 {
		ptr := ctx.Arg(0)
		newSize := ctx.Arg(1)
		if ptr == 0 {
			ctx.SetReturn(sharedHeapAlloc(newSize, false))
			return 0
		}
		if newSize == 0 {
			sharedHeapFree(ptr)
			ctx.SetReturn(0)
			return 0
		}
		oldBlockSize, _ := mem.Read64(ptr - 16)
		oldDataSize := oldBlockSize - 16
		if newSize <= oldDataSize {
			ctx.SetReturn(ptr)
			return 0
		}
		newPtr := sharedHeapAlloc(newSize, false)
		if newPtr != 0 {
			copyLen := oldDataSize
			if newSize < copyLen {
				copyLen = newSize
			}
			for i := uint64(0); i < copyLen; i++ {
				b, _ := mem.Read8(ptr + i)
				mem.Write8(newPtr+i, b)
			}
		}
		sharedHeapFree(ptr)
		ctx.SetReturn(newPtr)
		return 0
	})

	// _initterm_e: like _initterm but functions return int; return 0 on success
	d.RegisterAutoStubHandler(msvcrt, "_initterm_e", func(ctx *ntapi.TrapContext) uint32 {
		begin := ctx.Arg(0)
		end := ctx.Arg(1)
		for ptr := begin; ptr < end; ptr += 8 {
			fnPtr, _ := mem.Read64(ptr)
			if fnPtr != 0 {
				// Skip calling - assume all initializers succeed
			}
		}
		ctx.SetReturn(0)
		return 0
	})

	// _beginthread: create a new thread (stub - returns pseudo handle)
	d.RegisterAutoStubHandler(msvcrt, "_beginthread", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x1000)
		return 0
	})

	// _beginthreadex: create a new thread (stub - returns pseudo handle)
	d.RegisterAutoStubHandler(msvcrt, "_beginthreadex", func(ctx *ntapi.TrapContext) uint32 {
		thrdaddr := ctx.Arg(5)
		if thrdaddr != 0 {
			mem.Write32(thrdaddr, 0x2000)
		}
		ctx.SetReturn(0x1000)
		return 0
	})

	// _endthread / _endthreadex: end current thread (no-op in single-threaded emulator)
	d.RegisterAutoStubHandler(msvcrt, "_endthread", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "_endthreadex", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})

	// _seh_filter_exe / _seh_filter_dll: SEH exception filters
	d.RegisterAutoStubHandler(msvcrt, "_seh_filter_exe", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1) // EXCEPTION_EXECUTE_HANDLER
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "_seh_filter_dll", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1) // EXCEPTION_EXECUTE_HANDLER
		return 0
	})

	// _controlfp_s: control floating-point precision and rounding
	var msvcrtFpControl uint64 = 0x8001F // default: MCW_EM | _RC_NEAR
	d.RegisterAutoStubHandler(msvcrt, "_controlfp_s", func(ctx *ntapi.TrapContext) uint32 {
		currentControl := ctx.Arg(0)
		newControl := ctx.Arg(1)
		mask := ctx.Arg(2)
		msvcrtFpControl = (msvcrtFpControl &^ mask) | (newControl & mask)
		if currentControl != 0 {
			mem.Write32(currentControl, uint32(msvcrtFpControl))
		}
		ctx.SetReturn(0)
		return 0
	})

	// _set_fmode: set default file translation mode
	var msvcrtFmode uint32 = 0x8000 // _O_BINARY
	d.RegisterAutoStubHandler(msvcrt, "_set_fmode", func(ctx *ntapi.TrapContext) uint32 {
		msvcrtFmode = uint32(ctx.Arg(0))
		ctx.SetReturn(0)
		return 0
	})

	// __p__fmode: return pointer to static _fmode variable
	var msvcrtFmodeSlot uint64
	d.RegisterAutoStubHandler(msvcrt, "__p__fmode", func(ctx *ntapi.TrapContext) uint32 {
		if msvcrtFmodeSlot == 0 {
			msvcrtFmodeSlot = mem.Mmap(0, 8, mmu.PermRead|mmu.PermWrite)
		}
		mem.Write32(msvcrtFmodeSlot, msvcrtFmode)
		ctx.SetReturn(msvcrtFmodeSlot)
		return 0
	})

	// __p__acmdln: return char** pointer to _acmdln (ANSI command line)
	var acmdlnSlot uint64
	d.RegisterAutoStubHandler(msvcrt, "__p__acmdln", func(ctx *ntapi.TrapContext) uint32 {
		if acmdlnSlot == 0 {
			cmdBytes := append([]byte(hctx.CmdLine), 0)
			base := mem.Mmap(0, uint64(len(cmdBytes)+8), mmu.PermRead|mmu.PermWrite)
			if base != 0 {
				mem.WriteBytes(base, cmdBytes)
				strAddr := base
				acmdlnSlot = base + uint64(len(cmdBytes)+3)&^3
				if acmdlnSlot < 0x100000000 {
					mem.Write32(acmdlnSlot, uint32(strAddr))
				} else {
					mem.Write64(acmdlnSlot, strAddr)
				}
			}
		}
		ctx.SetReturn(acmdlnSlot)
		return 0
	})

	// __p__wcmdln: return wchar_t** pointer to _wcmdln (wide command line)
	var wcmdlnSlot uint64
	d.RegisterAutoStubHandler(msvcrt, "__p__wcmdln", func(ctx *ntapi.TrapContext) uint32 {
		if wcmdlnSlot == 0 {
			// encode command line as UTF-16LE + null terminator
			cmdW := make([]byte, (len(hctx.CmdLine)+1)*2)
			for i, c := range hctx.CmdLine {
				cmdW[i*2] = byte(c)
			}
			base := mem.Mmap(0, uint64(len(cmdW)+8), mmu.PermRead|mmu.PermWrite)
			if base != 0 {
				mem.WriteBytes(base, cmdW)
				strAddr := base
				wcmdlnSlot = base + uint64(len(cmdW)+3)&^3
				if wcmdlnSlot < 0x100000000 {
					mem.Write32(wcmdlnSlot, uint32(strAddr))
				} else {
					mem.Write64(wcmdlnSlot, strAddr)
				}
			}
		}
		ctx.SetReturn(wcmdlnSlot)
		return 0
	})

	// _ismbblead: returns non-zero if the byte is a DBCS lead byte.
	// For code page 932/936/949/950 only some byte ranges are lead bytes.
	// We emulate as code page 932 (Shift-JIS) for compatibility; standard
	// ASCII (0x00-0x7F) never qualifies.
	d.RegisterAutoStubHandler(msvcrt, "_ismbblead", func(ctx *ntapi.TrapContext) uint32 {
		c := ctx.Arg(0) & 0xFF
		// Shift-JIS lead byte ranges: 0x81-0x9F, 0xE0-0xFC
		if (c >= 0x81 && c <= 0x9F) || (c >= 0xE0 && c <= 0xFC) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(msvcrt, "_ismbbtrail", func(ctx *ntapi.TrapContext) uint32 {
		c := ctx.Arg(0) & 0xFF
		if c >= 0x40 && c <= 0xFC && c != 0x7F {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})

	// _register_thread_local_exe_atexit_callback: register a callback for thread-local
	// cleanup at exe exit. We store it but never invoke it since we don't have
	// a full CRT teardown sequence.
	var tlsAtexitCallback uint64
	d.RegisterAutoStubHandler(msvcrt, "_register_thread_local_exe_atexit_callback", func(ctx *ntapi.TrapContext) uint32 {
		tlsAtexitCallback = ctx.Arg(0)
		_ = tlsAtexitCallback // stored for potential future use
		ctx.SetReturn(0)
		return 0
	})

	registerCommonCRTOverrides(hctx, msvcrt, crtModuleConfig{
		iobBase:   func() uint64 { return iobBase },
		iobStride: iobStride,
	})
}
