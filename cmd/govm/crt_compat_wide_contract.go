//go:build guest_windows

package main

import "github.com/mirkobrombin/Raven/pkg/mmu"

func registerCRTWideContractCases(semantic crtWideSemantic) {
	for _, module := range semantic.modules {
		for _, architecture := range []string{"i386", "win64"} {
			registerCRTContractCase(crtContractCase{
				CaseID:           semantic.id + ".contract",
				Module:           module,
				ExportName:       semantic.name,
				Architecture:     architecture,
				ImplementationID: semantic.id,
				Signature:        semantic.signature,
				Exercise: func(invocation *crtContractInvocation) {
					exerciseCRTWideContract(invocation, semantic.name)
				},
			})
		}
	}
}

func crtWideASCII(value string) []byte {
	units := make([]uint16, 0, len(value)+1)
	for index := 0; index < len(value); index++ {
		units = append(units, uint16(value[index]))
	}
	return crtWideBytes(units, true)
}

func exerciseCRTWideContract(invocation *crtContractInvocation, name string) {
	allocate := func(value []byte) (uint64, bool) {
		address := invocation.Mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
		if address == 0 {
			invocation.Failf("wide contract allocation failed")
			return 0, false
		}
		if err := invocation.Mem.WriteBytes(address, value); err != nil {
			invocation.Failf("write wide contract input: %v", err)
			return 0, false
		}
		return address, true
	}
	call := func(watches []crtContractMemoryWatch, args ...uint64) (crtContractResult, bool) {
		result, err := invocation.CallWatching(watches, args...)
		if err != nil {
			invocation.Failf("dispatch wide contract: %v", err)
			return crtContractResult{}, false
		}
		return result, true
	}
	for scenario := 0; scenario < 2; scenario++ {
		switch name {
		case "wcslen", "wcsnlen":
			values := []string{"cat", "raven"}
			sourceData := crtWideASCII(values[scenario])
			source, ok := allocate(sourceData)
			if !ok {
				return
			}
			args := []uint64{source}
			want := uint64(len(values[scenario]))
			if name == "wcsnlen" {
				limits := []uint64{2, 9}
				args = append(args, limits[scenario])
				want = []uint64{2, 5}[scenario]
			}
			result, ok := call([]crtContractMemoryWatch{{Address: source, Size: len(sourceData)}}, args...)
			if !ok {
				return
			}
			result.ExpectReturn(want)
		case "wcscpy", "wcsncpy":
			values := []string{"cat", "ox"}
			sourceData := crtWideASCII(values[scenario])
			source, ok := allocate(sourceData)
			if !ok {
				return
			}
			destination, ok := allocate(make([]byte, 16))
			if !ok {
				return
			}
			args := []uint64{destination, source}
			expected := sourceData
			if name == "wcsncpy" {
				limits := []uint64{5, 4}
				args = append(args, limits[scenario])
				expected = append(append([]byte(nil), sourceData...), make([]byte, int(limits[scenario])*2-len(sourceData))...)
			}
			result, ok := call([]crtContractMemoryWatch{{Address: destination, Size: len(expected)}}, args...)
			if !ok {
				return
			}
			result.ExpectReturn(destination)
			result.ExpectMemory(0, expected)
		case "wcscat", "wcsncat":
			prefixes := []string{"red", "go"}
			suffixes := []string{"wood", "pher"}
			destinationData := append(crtWideASCII(prefixes[scenario]), make([]byte, 16)...)
			destination, ok := allocate(destinationData)
			if !ok {
				return
			}
			source, ok := allocate(crtWideASCII(suffixes[scenario]))
			if !ok {
				return
			}
			args := []uint64{destination, source}
			expected := crtWideASCII(prefixes[scenario] + suffixes[scenario])
			if name == "wcsncat" {
				limits := []uint64{2, 3}
				args = append(args, limits[scenario])
				expected = crtWideASCII([]string{"redwo", "gophe"}[scenario])
			}
			result, ok := call([]crtContractMemoryWatch{{Address: destination, Size: len(expected)}}, args...)
			if !ok {
				return
			}
			result.ExpectReturn(destination)
			result.ExpectMemory(0, expected)
		case "wcscmp", "wcsncmp":
			leftValues := []string{"abc", "abe"}
			rightValues := []string{"abd", "abd"}
			leftData, rightData := crtWideASCII(leftValues[scenario]), crtWideASCII(rightValues[scenario])
			left, ok := allocate(leftData)
			if !ok {
				return
			}
			right, ok := allocate(rightData)
			if !ok {
				return
			}
			args := []uint64{left, right}
			if name == "wcsncmp" {
				args = append(args, 3)
			}
			result, ok := call([]crtContractMemoryWatch{{Address: left, Size: len(leftData)}, {Address: right, Size: len(rightData)}}, args...)
			if !ok {
				return
			}
			result.ExpectInt32Sign([]int{-1, 1}[scenario])
		case "wcschr", "wcsrchr":
			values := []string{"abaca", "xyz"}
			sourceData := crtWideASCII(values[scenario])
			source, ok := allocate(sourceData)
			if !ok {
				return
			}
			needles := []uint64{'a', 'q'}
			result, ok := call([]crtContractMemoryWatch{{Address: source, Size: len(sourceData)}}, source, needles[scenario])
			if !ok {
				return
			}
			want := uint64(0)
			if scenario == 0 {
				want = source
				if name == "wcsrchr" {
					want = source + 8
				}
			}
			result.ExpectReturn(want)
		case "wcsstr":
			haystacks := []string{"one-two-three", "abcdef"}
			needles := []string{"two", "xyz"}
			haystackData, needleData := crtWideASCII(haystacks[scenario]), crtWideASCII(needles[scenario])
			haystack, ok := allocate(haystackData)
			if !ok {
				return
			}
			needle, ok := allocate(needleData)
			if !ok {
				return
			}
			result, ok := call([]crtContractMemoryWatch{{Address: haystack, Size: len(haystackData)}, {Address: needle, Size: len(needleData)}}, haystack, needle)
			if !ok {
				return
			}
			want := uint64(0)
			if scenario == 0 {
				want = haystack + 8
			}
			result.ExpectReturn(want)
		case "wcspbrk":
			values, sets := []string{"raven", "code"}, []string{"xyv", "xyz"}
			valueData, setData := crtWideASCII(values[scenario]), crtWideASCII(sets[scenario])
			source, ok := allocate(valueData)
			if !ok {
				return
			}
			set, ok := allocate(setData)
			if !ok {
				return
			}
			result, ok := call([]crtContractMemoryWatch{{Address: source, Size: len(valueData)}, {Address: set, Size: len(setData)}}, source, set)
			if !ok {
				return
			}
			want := uint64(0)
			if scenario == 0 {
				want = source + 4
			}
			result.ExpectReturn(want)
		case "wcsspn", "wcscspn":
			values, sets, wants := []string{"aaabx", "xyzab"}, []string{"ab", "xyz"}, []uint64{4, 3}
			if name == "wcscspn" {
				values, sets, wants = []string{"abcx", "raven"}, []string{"x", "v"}, []uint64{3, 2}
			}
			valueData, setData := crtWideASCII(values[scenario]), crtWideASCII(sets[scenario])
			source, ok := allocate(valueData)
			if !ok {
				return
			}
			set, ok := allocate(setData)
			if !ok {
				return
			}
			result, ok := call([]crtContractMemoryWatch{{Address: source, Size: len(valueData)}, {Address: set, Size: len(setData)}}, source, set)
			if !ok {
				return
			}
			result.ExpectReturn(wants[scenario])
		default:
			invocation.Failf("unknown wide contract %q", name)
			return
		}
	}
}
