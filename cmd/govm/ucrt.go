package main

import (
	"math"
	gorand "math/rand"
	"os"
	"strconv"
	"strings"
	gotime "time"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func registerUcrtHandlers(hctx *HandlerCtx) {
	argv := hctx.Argv
	crtStreamWriter := hctx.CrtStreamWriter
	d := hctx.Disp
	envVars := hctx.EnvVars
	mem := hctx.Mem
	readGuestString := hctx.ReadGuestString
	readGuestUTF16 := hctx.ReadGuestUTF16
	sharedHeapAlloc := hctx.HeapAlloc
	sharedHeapFree := hctx.HeapFree
	wideprintf := hctx.Wideprintf
	wlDisplay := hctx.WlDisplay

	ucrt, ok := hctx.SynthByName["ucrtbase.dll"]
	if !ok {
		return
	}
	_ = ucrt

	ucrtExit := func(ctx *ntapi.TrapContext) uint32 {
		code := ctx.Arg(0)
		ravelog.Logf("[win32] exit(%d)\n", code)
		if wlDisplay != nil {
			wlDisplay.Close()
		}
		os.Exit(int(code))
		return 0
	}
	d.RegisterAutoStubHandler(ucrt, "exit", ucrtExit)
	d.RegisterAutoStubHandler(ucrt, "_exit", ucrtExit)
	d.RegisterAutoStubHandler(ucrt, "_cexit", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "_configure_narrow_argv", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "_initialize_narrow_environment", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "_set_app_type", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "_get_initial_narrow_environment", func(ctx *ntapi.TrapContext) uint32 {
		// Return pointer to an empty environment (a NULL pointer)
		envBlock := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
		mem.Write64(envBlock, 0) // NULL terminator
		ctx.SetReturn(envBlock)
		return 0
	})
	// __p___argc: returns pointer to argc
	var argcSlot uint64
	d.RegisterAutoStubHandler(ucrt, "__p___argc", func(ctx *ntapi.TrapContext) uint32 {
		if argcSlot == 0 {
			argcSlot = mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
			mem.Write32(argcSlot, uint32(len(argv)))
		}
		ctx.SetReturn(argcSlot)
		return 0
	})
	// __p___argv: returns pointer to argv (array of char*)
	var argvSlot uint64
	d.RegisterAutoStubHandler(ucrt, "__p___argv", func(ctx *ntapi.TrapContext) uint32 {
		if argvSlot == 0 {
			page := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
			// Layout: [ptr to argv array] then [argv[0], argv[1], ..., NULL] then string data
			argvArrayAddr := page + 8
			strOff := argvArrayAddr + uint64((len(argv)+1)*8)
			for i, a := range argv {
				mem.Write64(argvArrayAddr+uint64(i)*8, strOff)
				mem.WriteBytes(strOff, append([]byte(a), 0))
				strOff += uint64(len(a)) + 1
			}
			mem.Write64(argvArrayAddr+uint64(len(argv))*8, 0) // NULL terminator
			mem.Write64(page, argvArrayAddr)
			argvSlot = page
		}
		ctx.SetReturn(argvSlot)
		return 0
	})

	// __stdio_common_vswprintf: wide printf with va_list
	d.RegisterAutoStubHandler(ucrt, "__stdio_common_vswprintf", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(1)
		bufCount := ctx.Arg(2)
		fmtAddr := ctx.Arg(3)
		vaList := ctx.Arg(5)

		if fmtAddr == 0 || buf == 0 || bufCount == 0 {
			if buf != 0 && bufCount > 0 {
				mem.Write16(buf, 0)
			}
			ctx.SetReturn(0)
			return 0
		}

		fmtStr := readGuestUTF16(fmtAddr)
		// Read va_list args (each 8 bytes)
		var args []uint64
		for i := 0; i < 16; i++ {
			v, _ := mem.Read64(vaList + uint64(i)*8)
			args = append(args, v)
		}
		result := wideprintf(fmtStr, args)

		// Write result as UTF-16 to buffer
		runes := []rune(result)
		n := len(runes)
		if bufCount > 0 && uint64(n) >= bufCount {
			n = int(bufCount) - 1
		}
		for i := 0; i < n; i++ {
			mem.Write16(buf+uint64(i)*2, uint16(runes[i]))
		}
		mem.Write16(buf+uint64(n)*2, 0)
		ctx.SetReturn(uint64(n))
		return 0
	})

	// __stdio_common_vsprintf: narrow printf with va_list
	d.RegisterAutoStubHandler(ucrt, "__stdio_common_vsprintf", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(1)
		bufCount := ctx.Arg(2)
		fmtAddr := ctx.Arg(3)
		vaList := ctx.Arg(5)

		if fmtAddr == 0 || buf == 0 || bufCount == 0 {
			if buf != 0 && bufCount > 0 {
				mem.Write8(buf, 0)
			}
			ctx.SetReturn(0)
			return 0
		}

		// Read narrow format string
		var fmtBytes []byte
		for i := 0; i < 4096; i++ {
			b, err := mem.Read8(fmtAddr + uint64(i))
			if err != nil || b == 0 {
				break
			}
			fmtBytes = append(fmtBytes, b)
		}
		fmtStr := string(fmtBytes)
		var args []uint64
		for i := 0; i < 16; i++ {
			v, _ := mem.Read64(vaList + uint64(i)*8)
			args = append(args, v)
		}
		// Reuse wideprintf for formatting (works for narrow too)
		result := wideprintf(fmtStr, args)

		n := len(result)
		if bufCount > 0 && uint64(n) >= bufCount {
			n = int(bufCount) - 1
		}
		for i := 0; i < n; i++ {
			mem.Write8(buf+uint64(i), result[i])
		}
		mem.Write8(buf+uint64(n), 0)
		ctx.SetReturn(uint64(n))
		return 0
	})

	// sprintf / _snprintf for ucrtbase (direct, not via __stdio_common)
	d.RegisterAutoStubHandler(ucrt, "sprintf", func(ctx *ntapi.TrapContext) uint32 {
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
	d.RegisterAutoStubHandler(ucrt, "_snprintf", func(ctx *ntapi.TrapContext) uint32 {
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

	// Wide-char CRT init stubs (same as narrow counterparts)
	d.RegisterAutoStubHandler(ucrt, "_configure_wide_argv", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "_initialize_wide_environment", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "_get_initial_wide_environment", func(ctx *ntapi.TrapContext) uint32 {
		envBlock := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
		mem.Write16(envBlock, 0) // empty wide env (double-null terminated)
		mem.Write16(envBlock+2, 0)
		ctx.SetReturn(envBlock)
		return 0
	})

	// __p___wargv: returns pointer to wide argv (WCHAR** pointer-to-pointer)
	var wargvSlot uint64
	d.RegisterAutoStubHandler(ucrt, "__p___wargv", func(ctx *ntapi.TrapContext) uint32 {
		if wargvSlot == 0 {
			page := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
			wargvArrayAddr := page + 8
			strOff := wargvArrayAddr + uint64((len(argv)+1)*8)
			for i, a := range argv {
				mem.Write64(wargvArrayAddr+uint64(i)*8, strOff)
				runes := []rune(a)
				for _, r := range runes {
					mem.Write16(strOff, uint16(r))
					strOff += 2
				}
				mem.Write16(strOff, 0) // null-terminate
				strOff += 2
			}
			mem.Write64(wargvArrayAddr+uint64(len(argv))*8, 0)
			mem.Write64(page, wargvArrayAddr)
			wargvSlot = page
		}
		ctx.SetReturn(wargvSlot)
		return 0
	})

	// wcslen: return length of wide string (in WCHARs)
	d.RegisterAutoStubHandler(ucrt, "wcslen", func(ctx *ntapi.TrapContext) uint32 {
		addr := ctx.Arg(0)
		n := uint64(0)
		for {
			w, err := mem.Read16(addr + n*2)
			if err != nil || w == 0 {
				break
			}
			n++
			if n > 0x100000 {
				break
			}
		}
		ctx.SetReturn(n)
		return 0
	})

	// strlen: return length of narrow string
	d.RegisterAutoStubHandler(ucrt, "strlen", func(ctx *ntapi.TrapContext) uint32 {
		addr := ctx.Arg(0)
		n := uint64(0)
		for {
			b, err := mem.Read8(addr + n)
			if err != nil || b == 0 {
				break
			}
			n++
			if n > 0x100000 {
				break
			}
		}
		ctx.SetReturn(n)
		return 0
	})

	// getenv: return NULL (no environment variables)
	d.RegisterAutoStubHandler(ucrt, "getenv", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(0)
		if namePtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		name := readGuestString(namePtr)
		var val string
		if v, ok := envVars[name]; ok {
			val = v
		} else {
			val = os.Getenv(name)
		}
		if val == "" {
			ctx.SetReturn(0) // NULL = not found
			return 0
		}
		// Allocate guest memory for the value string
		buf := mem.Mmap(0, uint64(len(val)+1), mmu.PermRead|mmu.PermWrite)
		for i := 0; i < len(val); i++ {
			mem.Write8(buf+uint64(i), val[i])
		}
		mem.Write8(buf+uint64(len(val)), 0)
		ctx.SetReturn(buf)
		return 0
	})

	// __acrt_iob_func: returns pointer to CRT FILE* for stdin/stdout/stderr
	var crtIOBBase uint64
	d.RegisterAutoStubHandler(ucrt, "__acrt_iob_func", func(ctx *ntapi.TrapContext) uint32 {
		idx := ctx.Arg(0)
		if crtIOBBase == 0 {
			// Allocate fake FILE structs (each 0x30 bytes = 48, typical UCRT _iobuf)
			crtIOBBase = mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
		}
		ctx.SetReturn(crtIOBBase + idx*0x30)
		return 0
	})

	// fwrite: write to FILE* - for stderr/stdout we print to host, otherwise discard
	d.RegisterAutoStubHandler(ucrt, "fwrite", func(ctx *ntapi.TrapContext) uint32 {
		ptr := ctx.Arg(0)
		size := ctx.Arg(1)
		count := ctx.Arg(2)
		total := size * count
		if total > 0 && total < 0x100000 {
			buf := make([]byte, total)
			for i := uint64(0); i < total; i++ {
				b, _ := mem.Read8(ptr + i)
				buf[i] = b
			}
			os.Stderr.Write(buf)
		}
		ctx.SetReturn(count)
		return 0
	})

	// fprintf/printf: handled via __stdio_common_vsprintf at lower level, but stub direct calls
	d.RegisterAutoStubHandler(ucrt, "_set_new_mode", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "_crt_atexit", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "_register_onexit_function", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "_initialize_onexit_table", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "_register_thread_local_exe_atexit_callback", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})

	// Memory functions
	d.RegisterAutoStubHandler(ucrt, "malloc", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sharedHeapAlloc(ctx.Arg(0), false))
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "calloc", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sharedHeapAlloc(ctx.Arg(0)*ctx.Arg(1), true))
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "free", func(ctx *ntapi.TrapContext) uint32 {
		sharedHeapFree(ctx.Arg(0))
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "realloc", func(ctx *ntapi.TrapContext) uint32 {
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

	// String functions
	d.RegisterAutoStubHandler(ucrt, "memset", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		val := byte(ctx.Arg(1))
		count := ctx.Arg(2)
		if count > 0x1000000 {
			count = 0x1000000
		}
		buf := make([]byte, count)
		for i := range buf {
			buf[i] = val
		}
		ctx.Mem.WriteBytes(dst, buf)
		ctx.SetReturn(dst)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "memcpy", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		count := ctx.Arg(2)
		if count > 0x1000000 {
			count = 0x1000000
		}
		buf, _ := ctx.Mem.ReadBytes(src, int(count))
		ctx.Mem.WriteBytes(dst, buf)
		ctx.SetReturn(dst)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "memmove", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		count := ctx.Arg(2)
		if count > 0x1000000 {
			count = 0x1000000
		}
		buf, _ := ctx.Mem.ReadBytes(src, int(count))
		ctx.Mem.WriteBytes(dst, buf)
		ctx.SetReturn(dst)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "memcmp", func(ctx *ntapi.TrapContext) uint32 {
		s1 := ctx.Arg(0)
		s2 := ctx.Arg(1)
		count := ctx.Arg(2)
		for i := uint64(0); i < count && i < 0x1000000; i++ {
			a, _ := mem.Read8(s1 + i)
			b, _ := mem.Read8(s2 + i)
			if a < b {
				ctx.SetReturn(^uint64(0)) // -1
				return 0
			}
			if a > b {
				ctx.SetReturn(1)
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "strcpy", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		i := uint64(0)
		for {
			b, _ := mem.Read8(src + i)
			mem.Write8(dst+i, b)
			if b == 0 {
				break
			}
			i++
			if i > 0x100000 {
				break
			}
		}
		ctx.SetReturn(dst)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "strncpy", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		count := ctx.Arg(2)
		i := uint64(0)
		for i < count {
			b, _ := mem.Read8(src + i)
			mem.Write8(dst+i, b)
			if b == 0 {
				// zero-fill remaining
				for i++; i < count; i++ {
					mem.Write8(dst+i, 0)
				}
				break
			}
			i++
		}
		ctx.SetReturn(dst)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "strcmp", func(ctx *ntapi.TrapContext) uint32 {
		s1 := ctx.Arg(0)
		s2 := ctx.Arg(1)
		for i := uint64(0); i < 0x100000; i++ {
			a, _ := mem.Read8(s1 + i)
			b, _ := mem.Read8(s2 + i)
			if a < b {
				ctx.SetReturn(^uint64(0))
				return 0
			}
			if a > b {
				ctx.SetReturn(1)
				return 0
			}
			if a == 0 {
				break
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "wcscpy", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		i := uint64(0)
		for {
			w, _ := mem.Read16(src + i*2)
			mem.Write16(dst+i*2, w)
			if w == 0 {
				break
			}
			i++
			if i > 0x100000 {
				break
			}
		}
		ctx.SetReturn(dst)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "wcsncpy", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		count := ctx.Arg(2)
		i := uint64(0)
		for i < count {
			w, _ := mem.Read16(src + i*2)
			mem.Write16(dst+i*2, w)
			if w == 0 {
				for i++; i < count; i++ {
					mem.Write16(dst+i*2, 0)
				}
				break
			}
			i++
		}
		ctx.SetReturn(dst)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "wcscmp", func(ctx *ntapi.TrapContext) uint32 {
		s1 := ctx.Arg(0)
		s2 := ctx.Arg(1)
		for i := uint64(0); i < 0x100000; i++ {
			a, _ := mem.Read16(s1 + i*2)
			b, _ := mem.Read16(s2 + i*2)
			if a < b {
				ctx.SetReturn(^uint64(0))
				return 0
			}
			if a > b {
				ctx.SetReturn(1)
				return 0
			}
			if a == 0 {
				break
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "wcscat", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		// Find end of dst
		end := dst
		for {
			w, _ := mem.Read16(end)
			if w == 0 {
				break
			}
			end += 2
		}
		// Copy src
		for {
			w, _ := mem.Read16(src)
			mem.Write16(end, w)
			if w == 0 {
				break
			}
			src += 2
			end += 2
		}
		ctx.SetReturn(dst)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "wcschr", func(ctx *ntapi.TrapContext) uint32 {
		s := ctx.Arg(0)
		c := uint16(ctx.Arg(1))
		for i := uint64(0); i < 0x100000; i++ {
			w, _ := mem.Read16(s + i*2)
			if w == c {
				ctx.SetReturn(s + i*2)
				return 0
			}
			if w == 0 {
				break
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "wcsrchr", func(ctx *ntapi.TrapContext) uint32 {
		s := ctx.Arg(0)
		c := uint16(ctx.Arg(1))
		last := uint64(0)
		for i := uint64(0); i < 0x100000; i++ {
			w, _ := mem.Read16(s + i*2)
			if w == c {
				last = s + i*2
			}
			if w == 0 {
				break
			}
		}
		ctx.SetReturn(last)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "_wcsicmp", func(ctx *ntapi.TrapContext) uint32 {
		s1 := ctx.Arg(0)
		s2 := ctx.Arg(1)
		toLower := func(c uint16) uint16 {
			if c >= 'A' && c <= 'Z' {
				return c + 32
			}
			return c
		}
		for i := uint64(0); i < 0x100000; i++ {
			a, _ := mem.Read16(s1 + i*2)
			b, _ := mem.Read16(s2 + i*2)
			la, lb := toLower(a), toLower(b)
			if la < lb {
				ctx.SetReturn(^uint64(0))
				return 0
			}
			if la > lb {
				ctx.SetReturn(1)
				return 0
			}
			if a == 0 {
				break
			}
		}
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(ucrt, "abort", ucrtExit)
	d.RegisterAutoStubHandler(ucrt, "terminate", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[win32] terminate() called - ignoring\n")
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "_c_exit", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})

	// Wide character classification and conversion
	d.RegisterAutoStubHandler(ucrt, "towlower", func(ctx *ntapi.TrapContext) uint32 {
		c := uint16(ctx.Arg(0))
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		ctx.SetReturn(uint64(c))
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "towupper", func(ctx *ntapi.TrapContext) uint32 {
		c := uint16(ctx.Arg(0))
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		ctx.SetReturn(uint64(c))
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "iswspace", func(ctx *ntapi.TrapContext) uint32 {
		c := uint16(ctx.Arg(0))
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "iswdigit", func(ctx *ntapi.TrapContext) uint32 {
		c := uint16(ctx.Arg(0))
		if c >= '0' && c <= '9' {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "iswalpha", func(ctx *ntapi.TrapContext) uint32 {
		c := uint16(ctx.Arg(0))
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "iswalnum", func(ctx *ntapi.TrapContext) uint32 {
		c := uint16(ctx.Arg(0))
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "iswxdigit", func(ctx *ntapi.TrapContext) uint32 {
		c := uint16(ctx.Arg(0))
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	// Narrow char classification
	d.RegisterAutoStubHandler(ucrt, "isspace", func(ctx *ntapi.TrapContext) uint32 {
		c := byte(ctx.Arg(0))
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "isdigit", func(ctx *ntapi.TrapContext) uint32 {
		c := byte(ctx.Arg(0))
		if c >= '0' && c <= '9' {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "tolower", func(ctx *ntapi.TrapContext) uint32 {
		c := byte(ctx.Arg(0))
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		ctx.SetReturn(uint64(c))
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "toupper", func(ctx *ntapi.TrapContext) uint32 {
		c := byte(ctx.Arg(0))
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		ctx.SetReturn(uint64(c))
		return 0
	})

	// String search/misc
	d.RegisterAutoStubHandler(ucrt, "strcat", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		end := dst
		for {
			b, _ := mem.Read8(end)
			if b == 0 {
				break
			}
			end++
		}
		for {
			b, _ := mem.Read8(src)
			mem.Write8(end, b)
			if b == 0 {
				break
			}
			src++
			end++
		}
		ctx.SetReturn(dst)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "strstr", func(ctx *ntapi.TrapContext) uint32 {
		haystack := ctx.Arg(0)
		needle := ctx.Arg(1)
		// Read needle string
		var needleBytes []byte
		for i := uint64(0); i < 0x10000; i++ {
			b, _ := mem.Read8(needle + i)
			if b == 0 {
				break
			}
			needleBytes = append(needleBytes, b)
		}
		if len(needleBytes) == 0 {
			ctx.SetReturn(haystack)
			return 0
		}
		for i := uint64(0); i < 0x100000; i++ {
			b, _ := mem.Read8(haystack + i)
			if b == 0 {
				break
			}
			if b == needleBytes[0] {
				match := true
				for j := 1; j < len(needleBytes); j++ {
					c, _ := mem.Read8(haystack + i + uint64(j))
					if c != needleBytes[j] {
						match = false
						break
					}
				}
				if match {
					ctx.SetReturn(haystack + i)
					return 0
				}
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "wcsstr", func(ctx *ntapi.TrapContext) uint32 {
		haystack := ctx.Arg(0)
		needle := ctx.Arg(1)
		var needleChars []uint16
		for i := uint64(0); i < 0x10000; i++ {
			w, _ := mem.Read16(needle + i*2)
			if w == 0 {
				break
			}
			needleChars = append(needleChars, w)
		}
		if len(needleChars) == 0 {
			ctx.SetReturn(haystack)
			return 0
		}
		for i := uint64(0); i < 0x100000; i++ {
			w, _ := mem.Read16(haystack + i*2)
			if w == 0 {
				break
			}
			if w == needleChars[0] {
				match := true
				for j := 1; j < len(needleChars); j++ {
					c, _ := mem.Read16(haystack + (i+uint64(j))*2)
					if c != needleChars[j] {
						match = false
						break
					}
				}
				if match {
					ctx.SetReturn(haystack + i*2)
					return 0
				}
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "_stricmp", func(ctx *ntapi.TrapContext) uint32 {
		s1 := ctx.Arg(0)
		s2 := ctx.Arg(1)
		toLower := func(c byte) byte {
			if c >= 'A' && c <= 'Z' {
				return c + 32
			}
			return c
		}
		for i := uint64(0); i < 0x100000; i++ {
			a, _ := mem.Read8(s1 + i)
			b, _ := mem.Read8(s2 + i)
			la, lb := toLower(a), toLower(b)
			if la < lb {
				ctx.SetReturn(^uint64(0))
				return 0
			}
			if la > lb {
				ctx.SetReturn(1)
				return 0
			}
			if a == 0 {
				break
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "_wcsnicmp", func(ctx *ntapi.TrapContext) uint32 {
		s1 := ctx.Arg(0)
		s2 := ctx.Arg(1)
		count := ctx.Arg(2)
		toLower := func(c uint16) uint16 {
			if c >= 'A' && c <= 'Z' {
				return c + 32
			}
			return c
		}
		for i := uint64(0); i < count; i++ {
			a, _ := mem.Read16(s1 + i*2)
			b, _ := mem.Read16(s2 + i*2)
			la, lb := toLower(a), toLower(b)
			if la < lb {
				ctx.SetReturn(^uint64(0))
				return 0
			}
			if la > lb {
				ctx.SetReturn(1)
				return 0
			}
			if a == 0 {
				break
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	// Number conversion
	d.RegisterAutoStubHandler(ucrt, "_wtoi", func(ctx *ntapi.TrapContext) uint32 {
		s := ctx.Arg(0)
		str := readGuestUTF16(s)
		val := int64(0)
		neg := false
		i := 0
		for i < len(str) && (str[i] == ' ' || str[i] == '\t') {
			i++
		}
		if i < len(str) && str[i] == '-' {
			neg = true
			i++
		} else if i < len(str) && str[i] == '+' {
			i++
		}
		for i < len(str) && str[i] >= '0' && str[i] <= '9' {
			val = val*10 + int64(str[i]-'0')
			i++
		}
		if neg {
			val = -val
		}
		ctx.SetReturn(uint64(val))
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "atoi", func(ctx *ntapi.TrapContext) uint32 {
		s := ctx.Arg(0)
		var str []byte
		for i := uint64(0); i < 32; i++ {
			b, _ := mem.Read8(s + i)
			if b == 0 {
				break
			}
			str = append(str, b)
		}
		val := int64(0)
		neg := false
		i := 0
		for i < len(str) && (str[i] == ' ' || str[i] == '\t') {
			i++
		}
		if i < len(str) && str[i] == '-' {
			neg = true
			i++
		} else if i < len(str) && str[i] == '+' {
			i++
		}
		for i < len(str) && str[i] >= '0' && str[i] <= '9' {
			val = val*10 + int64(str[i]-'0')
			i++
		}
		if neg {
			val = -val
		}
		ctx.SetReturn(uint64(val))
		return 0
	})
	// wcsncat
	d.RegisterAutoStubHandler(ucrt, "wcsncat", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		count := ctx.Arg(2)
		end := dst
		for {
			w, _ := mem.Read16(end)
			if w == 0 {
				break
			}
			end += 2
		}
		for i := uint64(0); i < count; i++ {
			w, _ := mem.Read16(src + i*2)
			mem.Write16(end+i*2, w)
			if w == 0 {
				break
			}
		}
		ctx.SetReturn(dst)
		return 0
	})
	// wcsncmp
	d.RegisterAutoStubHandler(ucrt, "wcsncmp", func(ctx *ntapi.TrapContext) uint32 {
		s1 := ctx.Arg(0)
		s2 := ctx.Arg(1)
		count := ctx.Arg(2)
		for i := uint64(0); i < count; i++ {
			a, _ := mem.Read16(s1 + i*2)
			b, _ := mem.Read16(s2 + i*2)
			if a < b {
				ctx.SetReturn(^uint64(0))
				return 0
			}
			if a > b {
				ctx.SetReturn(1)
				return 0
			}
			if a == 0 {
				break
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	// strchr / strrchr
	d.RegisterAutoStubHandler(ucrt, "strchr", func(ctx *ntapi.TrapContext) uint32 {
		s := ctx.Arg(0)
		c := byte(ctx.Arg(1))
		for i := uint64(0); i < 0x100000; i++ {
			b, _ := mem.Read8(s + i)
			if b == c {
				ctx.SetReturn(s + i)
				return 0
			}
			if b == 0 {
				break
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "strrchr", func(ctx *ntapi.TrapContext) uint32 {
		s := ctx.Arg(0)
		c := byte(ctx.Arg(1))
		last := uint64(0)
		for i := uint64(0); i < 0x100000; i++ {
			b, _ := mem.Read8(s + i)
			if b == c {
				last = s + i
			}
			if b == 0 {
				break
			}
		}
		ctx.SetReturn(last)
		return 0
	})
	// _errno: return pointer to thread-local errno
	var errnoStorage uint64
	d.RegisterAutoStubHandler(ucrt, "_errno", func(ctx *ntapi.TrapContext) uint32 {
		if errnoStorage == 0 {
			errnoStorage = mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
		}
		ctx.SetReturn(errnoStorage)
		return 0
	})
	// strtol / strtoul / _strtoi64
	d.RegisterAutoStubHandler(ucrt, "strtol", func(ctx *ntapi.TrapContext) uint32 {
		nptr := ctx.Arg(0)
		endptr := ctx.Arg(1)
		base := int(ctx.Arg(2))
		// Read string
		var str []byte
		for i := uint64(0); i < 64; i++ {
			b, _ := mem.Read8(nptr + i)
			if b == 0 {
				break
			}
			str = append(str, b)
		}
		s := strings.TrimSpace(string(str))
		val, _ := strconv.ParseInt(s, base, 64)
		if endptr != 0 {
			mem.Write64(endptr, nptr+uint64(len(str)))
		}
		ctx.SetReturn(uint64(val))
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "strtoul", func(ctx *ntapi.TrapContext) uint32 {
		nptr := ctx.Arg(0)
		endptr := ctx.Arg(1)
		base := int(ctx.Arg(2))
		var str []byte
		for i := uint64(0); i < 64; i++ {
			b, _ := mem.Read8(nptr + i)
			if b == 0 {
				break
			}
			str = append(str, b)
		}
		s := strings.TrimSpace(string(str))
		val, _ := strconv.ParseUint(s, base, 64)
		if endptr != 0 {
			mem.Write64(endptr, nptr+uint64(len(str)))
		}
		ctx.SetReturn(val)
		return 0
	})

	// _strdup / _wcsdup: duplicate a string into heap memory
	d.RegisterAutoStubHandler(ucrt, "_strdup", func(ctx *ntapi.TrapContext) uint32 {
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
	d.RegisterAutoStubHandler(ucrt, "_wcsdup", func(ctx *ntapi.TrapContext) uint32 {
		src := ctx.Arg(0)
		if src == 0 {
			ctx.SetReturn(0)
			return 0
		}
		var buf []uint16
		for i := uint64(0); i < 0x100000; i++ {
			w, _ := mem.Read16(src + i*2)
			buf = append(buf, w)
			if w == 0 {
				break
			}
		}
		dst := sharedHeapAlloc(uint64(len(buf)*2+2), false)
		for i, w := range buf {
			mem.Write16(dst+uint64(i)*2, w)
		}
		ctx.SetReturn(dst)
		return 0
	})

	// time / _time64: return current Unix timestamp
	d.RegisterAutoStubHandler(ucrt, "_time64", func(ctx *ntapi.TrapContext) uint32 {
		t := uint64(gotime.Now().Unix())
		ptr := ctx.Arg(0)
		if ptr != 0 {
			mem.Write64(ptr, t)
		}
		ctx.SetReturn(t)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "time", func(ctx *ntapi.TrapContext) uint32 {
		t := uint64(gotime.Now().Unix())
		ptr := ctx.Arg(0)
		if ptr != 0 {
			mem.Write64(ptr, t)
		}
		ctx.SetReturn(t)
		return 0
	})

	// srand / rand
	ucrtRng := gorand.New(gorand.NewSource(1))
	d.RegisterAutoStubHandler(ucrt, "srand", func(ctx *ntapi.TrapContext) uint32 {
		seed := ctx.Arg(0)
		ucrtRng = gorand.New(gorand.NewSource(int64(seed)))
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "rand", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(ucrtRng.Int31n(0x7FFF + 1))) // RAND_MAX = 0x7FFF
		return 0
	})

	// _dupenv_s: duplicate an environment variable string
	d.RegisterAutoStubHandler(ucrt, "_dupenv_s", func(ctx *ntapi.TrapContext) uint32 {
		// _dupenv_s(char **buf, size_t *sizeInBytes, const char *name)
		// On failure (not found): *buf=NULL, *sizeInBytes=0, return 0
		buf := ctx.Arg(0)
		sizePtr := ctx.Arg(1)
		if buf != 0 {
			mem.Write64(buf, 0)
		}
		if sizePtr != 0 {
			mem.Write64(sizePtr, 0)
		}
		ctx.SetReturn(0)
		return 0
	})

	// getenv_s(size_t *retsize, char *buf, size_t bufsize, const char *name)
	d.RegisterAutoStubHandler(ucrt, "getenv_s", func(ctx *ntapi.TrapContext) uint32 {
		sizeRet := ctx.Arg(0)
		bufPtr := ctx.Arg(1)
		bufSize := ctx.Arg(2)
		namePtr := ctx.Arg(3)
		if namePtr == 0 {
			if sizeRet != 0 {
				mem.Write64(sizeRet, 0)
			}
			ctx.SetReturn(22) // EINVAL
			return 0
		}
		name := readGuestString(namePtr)
		var val string
		if v, ok := envVars[name]; ok {
			val = v
		} else {
			val = os.Getenv(name)
		}
		if val == "" {
			if sizeRet != 0 {
				mem.Write64(sizeRet, 0)
			}
			ctx.SetReturn(0) // success, but empty
			return 0
		}
		needed := uint64(len(val) + 1)
		if sizeRet != 0 {
			mem.Write64(sizeRet, needed)
		}
		if bufPtr != 0 && bufSize >= needed {
			for i := 0; i < len(val); i++ {
				mem.Write8(bufPtr+uint64(i), val[i])
			}
			mem.Write8(bufPtr+uint64(len(val)), 0)
		}
		ctx.SetReturn(0) // success
		return 0
	})

	// --- ucrtbase math functions (float64 in XMM0/XMM1, return in XMM0) ---
	ucrtMathUnary := func(name string, fn func(float64) float64) {
		d.RegisterAutoStubHandler(ucrt, name, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetFloatReturn(fn(ctx.FloatArg(0)))
			return 0
		})
	}
	ucrtMathBinary := func(name string, fn func(float64, float64) float64) {
		d.RegisterAutoStubHandler(ucrt, name, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetFloatReturn(fn(ctx.FloatArg(0), ctx.FloatArg(1)))
			return 0
		})
	}
	ucrtMathUnary("floor", math.Floor)
	ucrtMathUnary("ceil", math.Ceil)
	ucrtMathUnary("sqrt", math.Sqrt)
	ucrtMathUnary("sin", math.Sin)
	ucrtMathUnary("cos", math.Cos)
	ucrtMathUnary("tan", math.Tan)
	ucrtMathUnary("asin", math.Asin)
	ucrtMathUnary("acos", math.Acos)
	ucrtMathUnary("atan", math.Atan)
	ucrtMathUnary("log", math.Log)
	ucrtMathUnary("log10", math.Log10)
	ucrtMathUnary("log2", math.Log2)
	ucrtMathUnary("exp", math.Exp)
	ucrtMathUnary("exp2", math.Exp2)
	ucrtMathUnary("fabs", math.Abs)
	ucrtMathUnary("round", math.Round)
	ucrtMathUnary("trunc", math.Trunc)
	ucrtMathUnary("cbrt", math.Cbrt)
	ucrtMathBinary("pow", math.Pow)
	ucrtMathBinary("fmod", math.Mod)
	ucrtMathBinary("atan2", math.Atan2)
	ucrtMathBinary("copysign", math.Copysign)
	ucrtMathBinary("fmax", math.Max)
	ucrtMathBinary("fmin", math.Min)
	ucrtMathBinary("remainder", math.Remainder)
	d.RegisterAutoStubHandler(ucrt, "ldexp", func(ctx *ntapi.TrapContext) uint32 {
		x := ctx.FloatArg(0)
		exp := int(int32(ctx.Arg(1)))
		ctx.SetFloatReturn(math.Ldexp(x, exp))
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "frexp", func(ctx *ntapi.TrapContext) uint32 {
		x := ctx.FloatArg(0)
		expPtr := ctx.Arg(1)
		frac, exp := math.Frexp(x)
		if expPtr != 0 {
			mem.Write32(expPtr, uint32(int32(exp)))
		}
		ctx.SetFloatReturn(frac)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "modf", func(ctx *ntapi.TrapContext) uint32 {
		x := ctx.FloatArg(0)
		intPtr := ctx.Arg(1)
		intPart, frac := math.Modf(x)
		if intPtr != 0 {
			mem.Write64(intPtr, math.Float64bits(intPart))
		}
		ctx.SetFloatReturn(frac)
		return 0
	})
	// Float versions (suffixed f)
	ucrtMathUnary("floorf", math.Floor)
	ucrtMathUnary("ceilf", math.Ceil)
	ucrtMathUnary("sqrtf", math.Sqrt)
	ucrtMathUnary("sinf", math.Sin)
	ucrtMathUnary("cosf", math.Cos)
	ucrtMathUnary("tanf", math.Tan)
	ucrtMathUnary("logf", math.Log)
	ucrtMathUnary("expf", math.Exp)
	ucrtMathUnary("fabsf", math.Abs)
	ucrtMathUnary("roundf", math.Round)
	ucrtMathUnary("truncf", math.Trunc)
	ucrtMathBinary("powf", math.Pow)
	ucrtMathBinary("fmodf", math.Mod)
	ucrtMathBinary("atan2f", math.Atan2)

	// Missing ucrt string functions
	d.RegisterAutoStubHandler(ucrt, "atof", func(ctx *ntapi.TrapContext) uint32 {
		s := readGuestString(ctx.Arg(0))
		v, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
		ctx.SetFloatReturn(v)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "atol", func(ctx *ntapi.TrapContext) uint32 {
		s := readGuestString(ctx.Arg(0))
		v, _ := strconv.Atoi(strings.TrimSpace(s))
		ctx.SetReturn(uint64(int64(int32(v))))
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "strtod", func(ctx *ntapi.TrapContext) uint32 {
		nptr := ctx.Arg(0)
		endptr := ctx.Arg(1)
		s := readGuestString(nptr)
		trimmed := strings.TrimSpace(s)
		v, _ := strconv.ParseFloat(trimmed, 64)
		if endptr != 0 {
			// Advance past consumed characters
			consumed := len(s) // default: consumed all
			trimStart := len(s) - len(strings.TrimLeft(s, " \t\n\r\v\f"))
			rest := s[trimStart:]
			// Try to find how much was parsed
			for i := len(rest); i >= 0; i-- {
				_, err := strconv.ParseFloat(rest[:i], 64)
				if err == nil && i > 0 {
					consumed = trimStart + i
					break
				}
			}
			mem.Write64(endptr, nptr+uint64(consumed))
		}
		ctx.SetFloatReturn(v)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "strtof", func(ctx *ntapi.TrapContext) uint32 {
		nptr := ctx.Arg(0)
		endptr := ctx.Arg(1)
		s := readGuestString(nptr)
		trimmed := strings.TrimSpace(s)
		v, _ := strconv.ParseFloat(trimmed, 32)
		if endptr != 0 {
			consumed := len(s)
			trimStart := len(s) - len(strings.TrimLeft(s, " \t\n\r\v\f"))
			rest := s[trimStart:]
			for i := len(rest); i >= 0; i-- {
				_, err := strconv.ParseFloat(rest[:i], 32)
				if err == nil && i > 0 {
					consumed = trimStart + i
					break
				}
			}
			mem.Write64(endptr, nptr+uint64(consumed))
		}
		ctx.SetFloatReturn(v)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "isalpha", func(ctx *ntapi.TrapContext) uint32 {
		c := byte(ctx.Arg(0))
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "isalnum", func(ctx *ntapi.TrapContext) uint32 {
		c := byte(ctx.Arg(0))
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "isupper", func(ctx *ntapi.TrapContext) uint32 {
		c := byte(ctx.Arg(0))
		if c >= 'A' && c <= 'Z' {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "islower", func(ctx *ntapi.TrapContext) uint32 {
		c := byte(ctx.Arg(0))
		if c >= 'a' && c <= 'z' {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "iswprint", func(ctx *ntapi.TrapContext) uint32 {
		c := uint16(ctx.Arg(0))
		if c >= 0x20 && c != 0x7F {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "memchr", func(ctx *ntapi.TrapContext) uint32 {
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
	d.RegisterAutoStubHandler(ucrt, "_strnicmp", func(ctx *ntapi.TrapContext) uint32 {
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
	d.RegisterAutoStubHandler(ucrt, "_strlwr", func(ctx *ntapi.TrapContext) uint32 {
		ptr := ctx.Arg(0)
		if ptr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		s := ptr
		for {
			b, _ := mem.Read8(s)
			if b == 0 {
				break
			}
			if b >= 'A' && b <= 'Z' {
				mem.Write8(s, b+32)
			}
			s++
		}
		ctx.SetReturn(ptr)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "_strupr", func(ctx *ntapi.TrapContext) uint32 {
		ptr := ctx.Arg(0)
		if ptr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		s := ptr
		for {
			b, _ := mem.Read8(s)
			if b == 0 {
				break
			}
			if b >= 'a' && b <= 'z' {
				mem.Write8(s, b-32)
			}
			s++
		}
		ctx.SetReturn(ptr)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "wcsstr", func(ctx *ntapi.TrapContext) uint32 {
		hay := ctx.Arg(0)
		needle := ctx.Arg(1)
		if hay == 0 || needle == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// Read needle
		var needleChars []uint16
		for p := needle; ; p += 2 {
			ch, _ := mem.Read16(p)
			if ch == 0 {
				break
			}
			needleChars = append(needleChars, ch)
		}
		if len(needleChars) == 0 {
			ctx.SetReturn(hay)
			return 0
		}
		for p := hay; ; p += 2 {
			ch, _ := mem.Read16(p)
			if ch == 0 {
				break
			}
			if ch == needleChars[0] {
				match := true
				for j := 1; j < len(needleChars); j++ {
					ch2, _ := mem.Read16(p + uint64(j)*2)
					if ch2 != needleChars[j] {
						match = false
						break
					}
				}
				if match {
					ctx.SetReturn(p)
					return 0
				}
			}
		}
		ctx.SetReturn(0)
		return 0
	})

	// File I/O stubs for ucrtbase
	d.RegisterAutoStubHandler(ucrt, "fopen", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // NULL
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "_wfopen", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // NULL
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "fclose", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "fread", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "fseek", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "ftell", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "fflush", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "feof", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "ferror", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "fgets", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // NULL (EOF)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "fputs", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "fprintf", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "__stdio_common_vfprintf", func(ctx *ntapi.TrapContext) uint32 {
		// options=Arg(0), stream=Arg(1), format=Arg(2), locale=Arg(3), arglist=Arg(4)
		stream := ctx.Arg(1)
		fmtAddr := ctx.Arg(2)
		vaList := ctx.Arg(4)
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
		w := crtStreamWriter(stream, crtIOBBase, 0x30)
		w.WriteString(result)
		ctx.SetReturn(uint64(len(result)))
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "__stdio_common_vfscanf", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "__p__commode", func(ctx *ntapi.TrapContext) uint32 {
		// Return pointer to a static int (commit mode = _IOCOMMIT)
		static := mem.Mmap(0, 8, mmu.PermRead|mmu.PermWrite)
		mem.Write32(static, 0x4000) // _IOCOMMIT
		ctx.SetReturn(static)
		return 0
	})
	// setlocale - return pointer to "C" locale string
	d.RegisterAutoStubHandler(ucrt, "setlocale", func(ctx *ntapi.TrapContext) uint32 {
		buf := mem.Mmap(0, 8, mmu.PermRead|mmu.PermWrite)
		mem.Write8(buf, 'C')
		mem.Write8(buf+1, 0)
		ctx.SetReturn(buf)
		return 0
	})
	// _configthreadlocale
	d.RegisterAutoStubHandler(ucrt, "_configthreadlocale", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // _DISABLE_PER_THREAD_LOCALE
		return 0
	})
	// printf - print to stdout
	d.RegisterAutoStubHandler(ucrt, "printf", func(ctx *ntapi.TrapContext) uint32 {
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
	d.RegisterAutoStubHandler(ucrt, "_snwprintf", func(ctx *ntapi.TrapContext) uint32 {
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

	// __stdio_common_vfwprintf: wide-char printf to stream
	d.RegisterAutoStubHandler(ucrt, "__stdio_common_vfwprintf", func(ctx *ntapi.TrapContext) uint32 {
		stream := ctx.Arg(1)
		fmtAddr := ctx.Arg(2)
		vaList := ctx.Arg(4)
		if fmtAddr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		fmtStr := readGuestUTF16(fmtAddr)
		var args []uint64
		if vaList != 0 {
			for i := 0; i < 8; i++ {
				v, _ := mem.Read64(vaList + uint64(i)*8)
				args = append(args, v)
			}
		}
		result := wideprintf(fmtStr, args)
		w := crtStreamWriter(stream, crtIOBBase, 0x30)
		w.WriteString(result)
		ctx.SetReturn(uint64(len(result)))
		return 0
	})

	// __stdio_common_vsscanf: scan from narrow string - stub returns 0 items
	d.RegisterAutoStubHandler(ucrt, "__stdio_common_vsscanf", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})

	// __stdio_common_vswscanf: scan from wide string - stub returns 0 items
	d.RegisterAutoStubHandler(ucrt, "__stdio_common_vswscanf", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})

	// _controlfp_s: control floating-point precision and rounding
	var ucrtFpControl uint64 = 0x8001F // default: MCW_EM | _RC_NEAR
	d.RegisterAutoStubHandler(ucrt, "_controlfp_s", func(ctx *ntapi.TrapContext) uint32 {
		currentControl := ctx.Arg(0)
		newControl := ctx.Arg(1)
		mask := ctx.Arg(2)
		ucrtFpControl = (ucrtFpControl &^ mask) | (newControl & mask)
		if currentControl != 0 {
			mem.Write32(currentControl, uint32(ucrtFpControl))
		}
		ctx.SetReturn(0)
		return 0
	})

	// __setusermatherr: register math error callback (stored, never invoked)
	d.RegisterAutoStubHandler(ucrt, "__setusermatherr", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})

	// _set_fmode / __p__fmode: default file translation mode
	var ucrtFmode uint32 = 0x8000 // _O_BINARY
	var ucrtFmodeSlot uint64
	d.RegisterAutoStubHandler(ucrt, "_set_fmode", func(ctx *ntapi.TrapContext) uint32 {
		ucrtFmode = uint32(ctx.Arg(0))
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "__p__fmode", func(ctx *ntapi.TrapContext) uint32 {
		if ucrtFmodeSlot == 0 {
			ucrtFmodeSlot = mem.Mmap(0, 8, mmu.PermRead|mmu.PermWrite)
		}
		mem.Write32(ucrtFmodeSlot, ucrtFmode)
		ctx.SetReturn(ucrtFmodeSlot)
		return 0
	})

	// _initterm: walk array of void(*)(void) between begin and end
	d.RegisterAutoStubHandler(ucrt, "_initterm", func(ctx *ntapi.TrapContext) uint32 {
		begin := ctx.Arg(0)
		end := ctx.Arg(1)
		for ptr := begin; ptr < end; ptr += 8 {
			fnPtr, _ := mem.Read64(ptr)
			if fnPtr != 0 {
				ravelog.Logf("[ucrt] _initterm: constructor at %#x (skipped)\n", fnPtr)
			}
		}
		return 0
	})

	// _initterm_e: like _initterm but functions return int; return 0 on success
	d.RegisterAutoStubHandler(ucrt, "_initterm_e", func(ctx *ntapi.TrapContext) uint32 {
		begin := ctx.Arg(0)
		end := ctx.Arg(1)
		for ptr := begin; ptr < end; ptr += 8 {
			fnPtr, _ := mem.Read64(ptr)
			if fnPtr != 0 {
				ravelog.Logf("[ucrt] _initterm_e: initializer at %#x (skipped)\n", fnPtr)
			}
		}
		ctx.SetReturn(0)
		return 0
	})

	// _seh_filter_exe / _seh_filter_dll: SEH exception filters
	d.RegisterAutoStubHandler(ucrt, "_seh_filter_exe", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1) // EXCEPTION_EXECUTE_HANDLER
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "_seh_filter_dll", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1) // EXCEPTION_EXECUTE_HANDLER
		return 0
	})

	// abs / labs: return absolute value
	d.RegisterAutoStubHandler(ucrt, "abs", func(ctx *ntapi.TrapContext) uint32 {
		v := int32(ctx.Arg(0))
		if v < 0 {
			v = -v
		}
		ctx.SetReturn(uint64(uint32(v)))
		return 0
	})
	d.RegisterAutoStubHandler(ucrt, "labs", func(ctx *ntapi.TrapContext) uint32 {
		v := int64(ctx.Arg(0))
		if v < 0 {
			v = -v
		}
		ctx.SetReturn(uint64(v))
		return 0
	})

	// clock: return processor time in CLOCKS_PER_SEC (1000 on Windows)
	d.RegisterAutoStubHandler(ucrt, "clock", func(ctx *ntapi.TrapContext) uint32 {
		ms := gotime.Since(hctx.BootTime).Milliseconds()
		ctx.SetReturn(uint64(ms)) // CLOCKS_PER_SEC = 1000 on MSVC
		return 0
	})

	// difftime: return difference between two time_t values as double
	d.RegisterAutoStubHandler(ucrt, "difftime", func(ctx *ntapi.TrapContext) uint32 {
		t1 := int64(ctx.Arg(0))
		t0 := int64(ctx.Arg(1))
		ctx.SetFloatReturn(float64(t1 - t0))
		return 0
	})

	// _strtoi64: 64-bit strtol
	d.RegisterAutoStubHandler(ucrt, "_strtoi64", func(ctx *ntapi.TrapContext) uint32 {
		nptr := ctx.Arg(0)
		endptr := ctx.Arg(1)
		base := int(ctx.Arg(2))
		var str []byte
		for i := uint64(0); i < 64; i++ {
			b, _ := mem.Read8(nptr + i)
			if b == 0 {
				break
			}
			str = append(str, b)
		}
		s := strings.TrimSpace(string(str))
		val, _ := strconv.ParseInt(s, base, 64)
		if endptr != 0 {
			mem.Write64(endptr, nptr+uint64(len(str)))
		}
		ctx.SetReturn(uint64(val))
		return 0
	})
}
