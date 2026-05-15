//go:build guest_windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/hostenv"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/vfs"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

var crtCorpusModules = []string{
	"msvcrt20", "msvcrt40", "msvcrt", "msvcr70", "msvcr71", "msvcr80",
	"msvcr90", "msvcr100", "msvcr110", "msvcr120", "msvcr120_app", "msvcrtd",
	"ucrtbase", "vcruntime140", "vcruntime140_1",
}

func parseCRTSpec(text, module string) []crtSpecRoute {
	return parseCRTSpecCorpus(text, module).Routes
}

func parseCRTSpecCorpus(text, module string) crtSpecCorpus {
	corpus := crtSpecCorpus{}
	uniqueNames := make(map[string]struct{})
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || fields[0] != "@" {
			continue
		}
		kind := fields[1]
		if kind == "stub" {
			corpus.Exclusions = append(corpus.Exclusions, crtRegistryIssue{Module: normalizeCRTModule(module), Reason: "Wine stub entry"})
			continue
		}
		corpus.NonStubEntries++
		if kind == "extern" {
			corpus.Exclusions = append(corpus.Exclusions, crtRegistryIssue{Module: normalizeCRTModule(module), Reason: "extern data symbol"})
			continue
		}
		if kind == "private" {
			corpus.Exclusions = append(corpus.Exclusions, crtRegistryIssue{Module: normalizeCRTModule(module), Reason: "private non-export"})
			continue
		}
		arch := ""
		symbolIndex := -1
		for i := 2; i < len(fields); i++ {
			if strings.HasPrefix(fields[i], "-arch=") {
				arch = strings.TrimPrefix(fields[i], "-arch=")
				continue
			}
			if strings.HasPrefix(fields[i], "-") {
				continue
			}
			if strings.Contains(fields[i], "(") {
				symbolIndex = i
				break
			}
		}
		if symbolIndex < 0 {
			corpus.Exclusions = append(corpus.Exclusions, crtRegistryIssue{Module: normalizeCRTModule(module), Reason: "unparseable non-stub entry"})
			continue
		}
		endIndex := symbolIndex
		for endIndex+1 < len(fields) && !strings.HasSuffix(fields[endIndex], ")") {
			endIndex++
		}
		symbol := strings.Join(fields[symbolIndex:endIndex+1], " ")
		open := strings.IndexByte(symbol, '(')
		if open <= 0 || !strings.HasSuffix(symbol, ")") {
			corpus.Exclusions = append(corpus.Exclusions, crtRegistryIssue{Module: normalizeCRTModule(module), Reason: "unparseable non-stub signature"})
			continue
		}
		name := symbol[:open]
		if isCRTMangledOrOrdinal(name) {
			reason := "ordinal export"
			if strings.HasPrefix(name, "?") {
				reason = "mangled C++ export"
			}
			corpus.Exclusions = append(corpus.Exclusions, crtRegistryIssue{Module: normalizeCRTModule(module), Name: name, Reason: reason})
			continue
		}
		uniqueNames[strings.ToLower(name)] = struct{}{}
		forwarder := ""
		sourceAlias := ""
		if endIndex+1 < len(fields) {
			if endIndex+2 != len(fields) {
				corpus.Exclusions = append(corpus.Exclusions, crtRegistryIssue{Module: normalizeCRTModule(module), Name: name, Reason: "unparseable implementation mapping"})
				continue
			}
			if strings.Contains(fields[endIndex+1], ".") {
				forwarder = fields[endIndex+1]
			} else {
				sourceAlias = fields[endIndex+1]
			}
		}
		signature := kind + symbol[open:]
		for _, routeArch := range crtSpecArchitectures(arch) {
			corpus.Routes = append(corpus.Routes, crtSpecRoute{
				Module:       normalizeCRTModule(module),
				Name:         name,
				Architecture: routeArch,
				Signature:    signature,
				Forwarder:    forwarder,
				SourceAlias:  sourceAlias,
			})
		}
		if len(crtSpecArchitectures(arch)) == 0 {
			corpus.Exclusions = append(corpus.Exclusions, crtRegistryIssue{Module: normalizeCRTModule(module), Name: name, Reason: "ARM-only route"})
		}
	}
	corpus.UniqueNames = len(uniqueNames)
	return corpus
}

func isCRTMangledOrOrdinal(name string) bool {
	if name == "" || strings.HasPrefix(name, "?") || strings.HasPrefix(name, "@") {
		return true
	}
	for _, r := range name {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func crtSpecArchitectures(qualifier string) []string {
	qualifier = strings.ToLower(strings.TrimSpace(qualifier))
	if qualifier == "" {
		return []string{"i386", "win64"}
	}
	allowed := map[string]bool{"i386": false, "win64": false}
	parts := strings.Split(qualifier, ",")
	negative := strings.HasPrefix(parts[0], "!")
	if negative {
		allowed["i386"], allowed["win64"] = true, true
	}
	for _, part := range parts {
		exclude := strings.HasPrefix(part, "!")
		part = strings.TrimPrefix(part, "!")
		var architecture string
		switch part {
		case "i386", "win32":
			architecture = "i386"
		case "win64", "x86_64":
			architecture = "win64"
		default:
			continue
		}
		allowed[architecture] = !exclude
	}
	var result []string
	for _, architecture := range []string{"i386", "win64"} {
		if allowed[architecture] {
			result = append(result, architecture)
		}
	}
	return result
}

func loadCRTCorpus(t *testing.T) []crtSpecRoute {
	return loadCRTCorpusData(t).Routes
}

func loadCRTCorpusData(t *testing.T) crtSpecCorpus {
	t.Helper()
	root := strings.TrimSpace(os.Getenv("RAVEN_WINE_API_CORPUS"))
	if root == "" {
		cacheDir, err := hostenv.CacheRoot()
		if err != nil {
			t.Fatalf("resolve Raven cache directory: %v", err)
		}
		root = filepath.Join(cacheDir, "wine-api-corpus")
	}
	const expectedCommit = "1012f3d99507b80d4869eabf0853567660a7ecbb"
	commit, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatalf("resolve Wine corpus commit: %v", err)
	}
	if strings.TrimSpace(string(commit)) != expectedCommit {
		t.Fatalf("Wine corpus commit is %s, want %s", strings.TrimSpace(string(commit)), expectedCommit)
	}
	corpus := crtSpecCorpus{}
	for _, module := range crtCorpusModules {
		path := filepath.Join(root, "dlls", module, module+".spec")
		text, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		parsed := parseCRTSpecCorpus(string(text), module)
		corpus.Routes = append(corpus.Routes, parsed.Routes...)
		corpus.NonStubEntries += parsed.NonStubEntries
		corpus.UniqueNames += parsed.UniqueNames
		corpus.Exclusions = append(corpus.Exclusions, parsed.Exclusions...)
	}
	uniqueNames := make(map[string]struct{})
	for _, route := range corpus.Routes {
		uniqueNames[strings.ToLower(route.Name)] = struct{}{}
	}
	corpus.UniqueNames = len(uniqueNames)
	return corpus
}

func executeCRTCertificateSuite(t *testing.T, corpus crtSpecCorpus) crtCertificate {
	t.Helper()
	definitions := crtSemanticDefinitions()
	registrations := make(map[string]map[string]ntapi.SemanticHandler)
	run := newCRTContractRun()
	for _, is32 := range []bool{true, false} {
		architecture := map[bool]string{true: "i386", false: "win64"}[is32]
		for _, moduleName := range crtCorpusModules {
			module := normalizeCRTModule(moduleName)
			seen := make(map[string]struct{})
			var exports []string
			for _, route := range corpus.Routes {
				if route.Module != module || route.Architecture != architecture {
					continue
				}
				for _, definition := range definitions {
					if !strings.EqualFold(route.Name, definition.ExportName) ||
						!crtAllowedModule(definition, module) ||
						!crtArchAllowed(definition, architecture) {
						continue
					}
					if _, exists := seen[route.Name]; !exists {
						seen[route.Name] = struct{}{}
						exports = append(exports, route.Name)
					}
					break
				}
			}
			if len(exports) == 0 {
				continue
			}
			mem := mmu.New()
			mem.Mode32 = is32
			state := &ntapi.ProcessState{Is32: is32}
			dispatcher := ntapi.NewDispatcher(mem, vfs.New(), ntapi.NewHandleTable(), nil, state, nil, nil)
			synth := ntapi.GenerateSynthDLL(mem, module, exports, ntapi.AutoSynthIDBase)
			hctx := &HandlerCtx{
				Disp:        dispatcher,
				Mem:         mem,
				ProcState:   state,
				SynthByName: map[string]*ntapi.SynthPE{module: synth},
			}
			registerCRTDefinitions(hctx, definitions)
			run.Execute(hctx)
			if registrations[module] == nil {
				registrations[module] = make(map[string]ntapi.SemanticHandler)
			}
			for name, registration := range dispatcher.SemanticHandlers()[module] {
				registrations[module][name] = registration
			}
		}
	}
	return crtCertificateForCorpus(corpus, registrations, definitions, run)
}

func TestCRTSpecCorpusReport(t *testing.T) {
	corpus := loadCRTCorpusData(t)
	t.Logf("CRT corpus parsed non-stub entries=%d applicable routes=%d unique names=%d exclusions=%d", corpus.NonStubEntries, len(corpus.Routes), corpus.UniqueNames, len(corpus.Exclusions))
}

func TestCRTCompatibilityCertificateReport(t *testing.T) {
	corpus := loadCRTCorpusData(t)
	certificate := executeCRTCertificateSuite(t, corpus)
	t.Logf(
		"CRT certificate parsed=%d unique=%d semantics=%d valid=%d duplicates=%d exclusions=%d",
		certificate.ParsedNonStub,
		certificate.UniqueNames,
		certificate.semanticImplementationCount(),
		certificate.validRouteCount(),
		len(certificate.Duplicates),
		len(certificate.Exclusions),
	)
}

func TestCRTRuntimeVersionForwardersExecute(t *testing.T) {
	corpus := loadCRTCorpusData(t)
	certificate := executeCRTCertificateSuite(t, corpus)
	required := map[string]bool{
		"msvcrt20.dll\x00strlen\x00i386":       false,
		"msvcr120_app.dll\x00wcslen\x00win64":  false,
		"vcruntime140.dll\x00strchr\x00i386":   false,
		"vcruntime140.dll\x00wcschr\x00win64":  false,
		"vcruntime140.dll\x00memmove\x00win64": false,
		"msvcrt40.dll\x00wcscspn\x00i386":      false,
		"msvcrtd.dll\x00strncpy\x00win64":      false,
		"ucrtbase.dll\x00wcsnlen\x00win64":     false,
	}
	for _, route := range certificate.ValidRoutes {
		key := route.Module + "\x00" + route.Name + "\x00" + route.Architecture
		if _, exists := required[key]; exists {
			required[key] = true
		}
	}
	for route, executed := range required {
		if !executed {
			t.Errorf("versioned route did not produce executable evidence: %q", route)
		}
	}
}

func TestCRTCompatibilityThresholdGate(t *testing.T) {
	if os.Getenv("RAVEN_CRT_COMPAT_GATE") != "1" {
		t.Skip("set RAVEN_CRT_COMPAT_GATE=1 for the explicit 10000-route gate")
	}
	corpus := loadCRTCorpusData(t)
	certificate := executeCRTCertificateSuite(t, corpus)
	if err := crtCompatibilityGate(certificate, 10000); err != nil {
		t.Fatal(err)
	}
}

func TestCRTSpecParserFiltersAndQualifiers(t *testing.T) {
	fixture := strings.Join([]string{
		"@ cdecl -arch=i386 good(ptr long)",
		"@ cdecl -arch=win64 good(ptr long)",
		"@ cdecl default_name(ptr)",
		"@ cdecl -arch=arm arm_only(ptr)",
		"@ cdecl -arch=arm,x86_64 x64_mixed(ptr)",
		"@ cdecl -arch=arm,arm64 arm_mixed(ptr)",
		"@ stub -arch=i386 stub_name(ptr)",
		"@ extern data_symbol",
		"@ cdecl -arch=i386 ?cpp@@YAXXZ()",
		"@ cdecl -arch=i386 12(ptr)",
		"@ cdecl -arch=i386 forwarded(ptr) ucrtbase.forwarded",
		"@ cdecl -arch=win64 internal(ptr) MSVCRT_internal",
	}, "\n")
	routes := parseCRTSpec(fixture, "msvcrt")
	if len(routes) != 7 {
		t.Fatalf("parsed %d routes, want 7", len(routes))
	}
	if routes[0].Architecture != "i386" || routes[1].Architecture != "win64" {
		t.Fatalf("architecture qualifiers were not preserved: %#v", routes)
	}
	if routes[2].Name != "default_name" || routes[3].Name != "default_name" {
		t.Fatalf("default architecture expansion was not preserved: %#v", routes)
	}
	if routes[4].Name != "x64_mixed" || routes[4].Architecture != "win64" {
		t.Fatalf("mixed architecture qualifier was not filtered: %#v", routes[4])
	}
	if routes[5].Forwarder != "ucrtbase.forwarded" {
		t.Fatalf("forwarder was not preserved: %#v", routes[5])
	}
	if routes[6].SourceAlias != "MSVCRT_internal" || routes[6].Architecture != "win64" {
		t.Fatalf("internal implementation alias was not preserved: %#v", routes[6])
	}
}

func newCRTDispatcher(t *testing.T, module, name string, is32 bool) (*ntapi.Dispatcher, *ntapi.SynthPE, *mmu.MMU) {
	t.Helper()
	mem := mmu.New()
	mem.Mode32 = is32
	state := &ntapi.ProcessState{Is32: is32}
	dispatcher := ntapi.NewDispatcher(mem, vfs.New(), ntapi.NewHandleTable(), nil, state, nil, nil)
	synth := ntapi.GenerateSynthDLL(mem, module, []string{name}, ntapi.AutoSynthIDBase)
	return dispatcher, synth, mem
}

func TestCRTRegistryExactRoutesAndCdeclCleanup(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		t.Run(fmt.Sprintf("PE%d", map[bool]int{true: 32, false: 64}[is32]), func(t *testing.T) {
			dispatcher, synth, mem := newCRTDispatcher(t, "msvcrt.dll", "positive", is32)
			hctx := &HandlerCtx{Disp: dispatcher, Mem: mem, SynthByName: map[string]*ntapi.SynthPE{"msvcrt.dll": synth}}
			handler := func(ctx *ntapi.TrapContext) uint32 {
				ctx.SetReturn(0x42)
				return 0
			}
			descriptions := []crtSemanticDefinition{{ExportName: "positive", ImplementationID: "test.mutating", Signature: "cdecl(ptr)", ContractCaseID: "test.positive.contract", AllowedModules: []string{"msvcrt.dll"}, AllowedArch: []string{"i386", "win64"}, Handler: handler}}
			registerCRTDefinitions(hctx, descriptions)
			if len(dispatcher.SemanticHandlers()["msvcrt.dll"]) != 1 {
				t.Fatalf("semantic route was not registered")
			}
			if is32 {
				cpu := x64.New(mem)
				cpu.Mode32 = true
				stack := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
				if err := mem.Write32(stack, 0x12345678); err != nil {
					t.Fatal(err)
				}
				if err := mem.Write32(stack+4, 0x99); err != nil {
					t.Fatal(err)
				}
				cpu.SetSP(stack)
				cpu.Regs[0] = uint64(synth.StubIDs[synth.Exports["positive"]])
				dispatcher.Handle(cpu)
				if cpu.Regs[0] != 0x42 || cpu.GetSP() != stack {
					t.Fatalf("PE32 cdecl contract failed: rax=%#x sp=%#x pc=%#x", cpu.Regs[0], cpu.GetSP(), cpu.GetPC())
				}
			}
		})
	}

	dispatcher, synth, mem := newCRTDispatcher(t, "msvcrt.dll", "present", false)
	hctx := &HandlerCtx{Disp: dispatcher, Mem: mem, SynthByName: map[string]*ntapi.SynthPE{"msvcrt.dll": synth}}
	registerCRTDefinitions(hctx, []crtSemanticDefinition{{ExportName: "absent", ImplementationID: "test.absent", Signature: "cdecl()", ContractCaseID: "test.absent.contract", AllowedModules: []string{"msvcrt.dll"}, AllowedArch: []string{"win64"}, Handler: func(*ntapi.TrapContext) uint32 { return 1 }}})
	if len(dispatcher.SemanticHandlers()["msvcrt.dll"]) != 0 || synth.Exports["absent"] != 0 {
		t.Fatal("registry invented an absent export")
	}
}

func TestCRTContractCaseExecutesThroughDispatcher(t *testing.T) {
	dispatcher, synth, mem := newCRTDispatcher(t, "msvcrt.dll", "mutating", true)
	hctx := &HandlerCtx{Disp: dispatcher, Mem: mem, SynthByName: map[string]*ntapi.SynthPE{"msvcrt.dll": synth}}
	handler := func(ctx *ntapi.TrapContext) uint32 {
		value := byte(ctx.Arg(1))
		if err := ctx.Mem.Write8(ctx.Arg(0), value); err != nil {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(uint64(value))
		return 0
	}
	definition := crtSemanticDefinition{
		ExportName:       "mutating",
		ImplementationID: "test.mutating.case",
		Signature:        "cdecl(ptr long)",
		ContractCaseID:   "test.mutating.contract",
		AllowedModules:   []string{"msvcrt.dll"},
		AllowedArch:      []string{"i386"},
		Handler:          handler,
	}
	registerCRTDefinitions(hctx, []crtSemanticDefinition{definition})
	if !registerCRTContractCase(crtContractCase{
		CaseID: "test.mutating.contract", Module: "msvcrt.dll", ExportName: "mutating", Architecture: "i386",
		ImplementationID: definition.ImplementationID, Signature: definition.Signature,
		Exercise: func(invocation *crtContractInvocation) {
			for _, value := range []byte{0xA5, 0x5A} {
				buffer := invocation.Mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
				if err := invocation.Mem.Write8(buffer, 0); err != nil {
					invocation.Failf("initialize contract buffer: %v", err)
					return
				}
				result, err := invocation.CallWatching([]crtContractMemoryWatch{{Address: buffer, Size: 1}}, buffer, uint64(value))
				if err != nil {
					invocation.Failf("dispatch mutating handler: %v", err)
					return
				}
				result.ExpectReturn(uint64(value))
				result.ExpectMemory(0, []byte{value})
			}
		},
	}) {
		t.Fatal("executable contract case was not registered")
	}
	run := newCRTContractRun()
	run.Execute(hctx)
	key := crtContractKey{Module: "msvcrt.dll", Name: "mutating", Architecture: "i386", ImplementationID: definition.ImplementationID, Signature: definition.Signature}
	evidence := run.evidence[key]
	if evidence.runID != run.id || !evidence.executed || !evidence.passed || evidence.callCount != 2 || evidence.distinctObservations != 2 {
		t.Fatalf("contract case did not produce passing evidence: run=%d evidence=%#v", run.id, evidence)
	}
	routes := []crtSpecRoute{{Module: "msvcrt.dll", Name: "mutating", Architecture: "i386", Signature: definition.Signature}}
	certificate := crtCertificateForRoutes(routes, dispatcher.SemanticHandlers(), []crtSemanticDefinition{definition}, run)
	if certificate.validRouteCount() != 1 {
		t.Fatalf("fresh dispatcher evidence was not accepted: %#v", certificate)
	}
}

func TestCRTCertificateRejectsAbsentUnrunAndConstantCases(t *testing.T) {
	constant := func(*ntapi.TrapContext) uint32 { return 7 }
	dispatcher, synth, mem := newCRTDispatcher(t, "msvcrt.dll", "constant_api", true)
	hctx := &HandlerCtx{Disp: dispatcher, Mem: mem, SynthByName: map[string]*ntapi.SynthPE{"msvcrt.dll": synth}}
	definition := crtSemanticDefinition{
		ExportName:       "constant_api",
		ImplementationID: "test.constant.clean-name",
		Signature:        "cdecl(long)",
		ContractCaseID:   "test.constant.semantic-contract",
		AllowedModules:   []string{"msvcrt.dll"},
		AllowedArch:      []string{"i386"},
		Handler:          constant,
	}
	registerCRTDefinitions(hctx, []crtSemanticDefinition{definition})
	routes := []crtSpecRoute{{Module: "msvcrt.dll", Name: "constant_api", Architecture: "i386", Signature: definition.Signature}}

	absentRun := newCRTContractRun()
	certificate := crtCertificateForRoutes(routes, dispatcher.SemanticHandlers(), []crtSemanticDefinition{definition}, absentRun)
	if certificate.validRouteCount() != 0 {
		t.Fatal("metadata created a valid route without an executable case")
	}
	if len(certificate.Exclusions) != 1 || !strings.Contains(certificate.Exclusions[0].Reason, "absent or was not run") {
		t.Fatalf("missing contract exclusion was not explicit: %#v", certificate.Exclusions)
	}

	if !registerCRTContractCase(crtContractCase{
		CaseID: "test.constant.semantic-contract", Module: "msvcrt.dll", ExportName: "constant_api", Architecture: "i386",
		ImplementationID: definition.ImplementationID, Signature: definition.Signature,
		Exercise: func(invocation *crtContractInvocation) {
			first, err := invocation.Call(11)
			if err != nil {
				invocation.Failf("first dispatch: %v", err)
				return
			}
			firstResult := crtContractResult{invocation: invocation, callIndex: len(invocation.calls) - 1, Return: first}
			firstResult.ExpectReturn(11)
			second, err := invocation.Call(29)
			if err != nil {
				invocation.Failf("second dispatch: %v", err)
				return
			}
			secondResult := crtContractResult{invocation: invocation, callIndex: len(invocation.calls) - 1, Return: second}
			secondResult.ExpectReturn(29)
		},
	}) {
		t.Fatal("constant rejection contract was not registered")
	}
	certificate = crtCertificateForRoutes(routes, dispatcher.SemanticHandlers(), []crtSemanticDefinition{definition}, newCRTContractRun())
	if certificate.validRouteCount() != 0 {
		t.Fatal("registered but unexecuted case created a valid route")
	}

	run := newCRTContractRun()
	run.Execute(hctx)
	certificate = crtCertificateForRoutes(routes, dispatcher.SemanticHandlers(), []crtSemanticDefinition{definition}, run)
	if certificate.validRouteCount() != 0 {
		t.Fatal("constant-return behavior passed input-dependent executable assertions")
	}
	if len(certificate.Exclusions) != 1 || !strings.Contains(certificate.Exclusions[0].Reason, "contract failed") {
		t.Fatalf("constant handler exclusion was not explicit: %#v", certificate.Exclusions)
	}
	key := crtContractKey{Module: "msvcrt.dll", Name: "constant_api", Architecture: "i386", ImplementationID: definition.ImplementationID, Signature: definition.Signature}
	if run.evidence[key].passed || len(run.evidence[key].errors) == 0 {
		t.Fatalf("constant handler was not rejected semantically: %#v", run.evidence[key])
	}
	if err := crtCompatibilityGate(certificate, 10000); err == nil {
		t.Fatal("threshold gate unexpectedly passed")
	}
}

func TestCRTCertificateRejectsNoOpWithVaryingReturn(t *testing.T) {
	noOp := func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(ctx.Arg(0))
		return 0
	}
	dispatcher, synth, mem := newCRTDispatcher(t, "msvcrt.dll", "fake_copy", true)
	hctx := &HandlerCtx{Disp: dispatcher, Mem: mem, SynthByName: map[string]*ntapi.SynthPE{"msvcrt.dll": synth}}
	definition := crtSemanticDefinition{
		ExportName:       "fake_copy",
		ImplementationID: "test.copy.clean-name",
		Signature:        "cdecl(ptr long)",
		ContractCaseID:   "test.copy.semantic-contract",
		AllowedModules:   []string{"msvcrt.dll"},
		AllowedArch:      []string{"i386"},
		Handler:          noOp,
	}
	registerCRTDefinitions(hctx, []crtSemanticDefinition{definition})
	if !registerCRTContractCase(crtContractCase{
		CaseID: "test.copy.semantic-contract", Module: "msvcrt.dll", ExportName: "fake_copy", Architecture: "i386",
		ImplementationID: definition.ImplementationID, Signature: definition.Signature,
		Exercise: func(invocation *crtContractInvocation) {
			for _, value := range []byte{0x21, 0x7E} {
				buffer := invocation.Mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
				if err := invocation.Mem.Write8(buffer, 0); err != nil {
					invocation.Failf("initialize no-op probe: %v", err)
					return
				}
				result, err := invocation.CallWatching([]crtContractMemoryWatch{{Address: buffer, Size: 1}}, buffer, uint64(value))
				if err != nil {
					invocation.Failf("dispatch no-op probe: %v", err)
					return
				}
				result.ExpectReturn(buffer)
				result.ExpectMemory(0, []byte{value})
			}
		},
	}) {
		t.Fatal("no-op rejection contract was not registered")
	}
	run := newCRTContractRun()
	run.Execute(hctx)
	route := crtSpecRoute{Module: "msvcrt.dll", Name: "fake_copy", Architecture: "i386", Signature: definition.Signature}
	certificate := crtCertificateForRoutes([]crtSpecRoute{route}, dispatcher.SemanticHandlers(), []crtSemanticDefinition{definition}, run)
	if certificate.validRouteCount() != 0 {
		t.Fatal("no-op handler passed a memory side-effect contract")
	}
}

func TestCRTCertificateRejectsDuplicateAndBadDefinitions(t *testing.T) {
	handler := func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(ctx.Arg(0))
		return 0
	}
	dispatcher, synth, mem := newCRTDispatcher(t, "msvcrt.dll", "foo", true)
	hctx := &HandlerCtx{Disp: dispatcher, Mem: mem, SynthByName: map[string]*ntapi.SynthPE{"msvcrt.dll": synth}}
	definition := crtSemanticDefinition{ExportName: "foo", ImplementationID: "test.foo", Signature: "cdecl(long)", ContractCaseID: "test.foo.contract", AllowedModules: []string{"msvcrt.dll"}, AllowedArch: []string{"i386"}, Handler: handler}
	registerCRTDefinitions(hctx, []crtSemanticDefinition{definition})
	if !registerCRTContractCase(crtContractCase{
		CaseID: "test.foo.contract", Module: "msvcrt.dll", ExportName: "foo", Architecture: "i386",
		ImplementationID: definition.ImplementationID, Signature: definition.Signature,
		Exercise: func(invocation *crtContractInvocation) {
			for _, value := range []uint64{3, 9} {
				got, err := invocation.Call(value)
				if err != nil {
					invocation.Failf("dispatch foo: %v", err)
					return
				}
				result := crtContractResult{invocation: invocation, callIndex: len(invocation.calls) - 1, Return: got}
				result.ExpectReturn(value)
			}
		},
	}) {
		t.Fatal("foo contract was not registered")
	}
	run := newCRTContractRun()
	run.Execute(hctx)
	routes := []crtSpecRoute{
		{Module: "msvcrt.dll", Name: "foo", Architecture: "i386", Signature: "cdecl(long)"},
		{Module: "msvcrt.dll", Name: "FOO", Architecture: "i386", Signature: "cdecl(long)"},
		{Module: "msvcrt.dll", Name: "foo", Architecture: "i386", Signature: "cdecl(long)"},
	}
	certificate := crtCertificateForRoutes(routes, dispatcher.SemanticHandlers(), []crtSemanticDefinition{definition}, run)
	if certificate.validRouteCount() != 1 || len(certificate.Duplicates) != 2 {
		t.Fatalf("duplicate route was not excluded: %#v", certificate)
	}
	badSignature := definition
	badSignature.Signature = "cdecl(ptr)"
	badSignature.ContractCaseID = ""
	certificate = crtCertificateForRoutes([]crtSpecRoute{{Module: "msvcrt.dll", Name: "foo", Architecture: "i386", Signature: "cdecl(ptr)"}}, dispatcher.SemanticHandlers(), []crtSemanticDefinition{badSignature}, run)
	if certificate.validRouteCount() != 0 {
		t.Fatal("bad signature or missing contract test was counted")
	}
}
