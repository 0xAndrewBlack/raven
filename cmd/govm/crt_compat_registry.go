//go:build guest_windows

package main

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/mirkobrombin/Raven/pkg/arch"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

// crtSemanticDefinition is the contract a family provider publishes for one
// exact export. The module and architecture sets are part of the definition;
// a handler is never copied to an unlisted DLL or export.
type crtSemanticDefinition struct {
	ExportName       string
	ImplementationID string
	Signature        string
	ContractCaseID   string
	AllowedModules   []string
	AllowedArch      []string
	Handler          ntapi.TrapHandler
}

type crtSemanticProvider func(*crtSemanticRegistry)

type crtSemanticRegistry struct {
	definitions []crtSemanticDefinition
}

func (r *crtSemanticRegistry) Define(def crtSemanticDefinition) {
	if r == nil {
		return
	}
	r.definitions = append(r.definitions, def)
}

var (
	crtProvidersMu sync.RWMutex
	crtProviders   []crtSemanticProvider
)

type crtErrnoKey struct {
	mem *mmu.MMU
	teb uint64
}

var crtErrnoSlots = struct {
	sync.Mutex
	values map[crtErrnoKey]uint64
}{values: make(map[crtErrnoKey]uint64)}

func crtErrnoAddress(ctx *ntapi.TrapContext) uint64 {
	teb := uint64(0)
	if ctx != nil && ctx.State != nil {
		teb = ctx.State.TEBAddr
	}
	return crtErrnoAddressAtTEB(ctx, teb)
}

func crtErrnoAddressAtTEB(ctx *ntapi.TrapContext, teb uint64) uint64 {
	if ctx == nil || ctx.Mem == nil {
		return 0
	}
	if ctx.State != nil && ctx.State.PEBAddr != 0 {
		return ctx.State.GetOrCreateRuntimePointer("crt.errno", teb, func() uint64 {
			return ctx.Mem.Mmap(0, 8, mmu.PermRead|mmu.PermWrite)
		})
	}
	key := crtErrnoKey{mem: ctx.Mem, teb: teb}
	crtErrnoSlots.Lock()
	defer crtErrnoSlots.Unlock()
	if address := crtErrnoSlots.values[key]; address != 0 {
		return address
	}
	address := ctx.Mem.Mmap(0, 8, mmu.PermRead|mmu.PermWrite)
	crtErrnoSlots.values[key] = address
	return address
}

func crtReleaseThreadRuntime(mem *mmu.MMU, state *ntapi.ProcessState, teb uint64) {
	if mem == nil || state == nil || teb == 0 {
		return
	}
	if address := state.SwapRuntimePointer("ucrt.gmtime", teb, 0); address != 0 {
		mem.Munmap(address, crtTimeTMSize)
	}
	if address := state.SwapRuntimePointer("crt.errno", teb, 0); address != 0 {
		mem.Munmap(address, 8)
	}
	state.SwapRuntimePointer(crtInvalidThreadNamespace, teb, 0)
}

func crtWriteErrno(ctx *ntapi.TrapContext, value uint32) bool {
	address := crtErrnoAddress(ctx)
	return address != 0 && ctx.Mem.Write32(address, value) == nil
}

func crtWriteErrnoAtTEB(ctx *ntapi.TrapContext, teb uint64, value uint32) bool {
	address := crtErrnoAddressAtTEB(ctx, teb)
	return address != 0 && ctx.Mem.Write32(address, value) == nil
}

func crtReadErrno(mem *mmu.MMU, teb uint64) uint32 {
	if mem == nil {
		return 0
	}
	crtErrnoSlots.Lock()
	address := crtErrnoSlots.values[crtErrnoKey{mem: mem, teb: teb}]
	crtErrnoSlots.Unlock()
	if address == 0 {
		return 0
	}
	value, _ := mem.Read32(address)
	return value
}

// registerCRTProvider lets a family add definitions in its own file without
// editing a central name list.
func registerCRTProvider(provider crtSemanticProvider) {
	if provider == nil {
		return
	}
	crtProvidersMu.Lock()
	crtProviders = append(crtProviders, provider)
	crtProvidersMu.Unlock()
}

func crtSemanticDefinitions() []crtSemanticDefinition {
	crtProvidersMu.RLock()
	providers := append([]crtSemanticProvider(nil), crtProviders...)
	crtProvidersMu.RUnlock()
	registry := &crtSemanticRegistry{}
	for _, provider := range providers {
		provider(registry)
	}
	return append([]crtSemanticDefinition(nil), registry.definitions...)
}

// registerCRTHandlers attaches only exports already present in the importing
// synthetic DLL. Missing imports remain unresolved and are not materialized.
func registerCRTHandlers(hctx *HandlerCtx) {
	if hctx == nil || hctx.Disp == nil {
		return
	}
	registerCRTDefinitions(hctx, crtSemanticDefinitions())
}

func registerCRTDefinitions(hctx *HandlerCtx, definitions []crtSemanticDefinition) {
	if hctx == nil || hctx.Disp == nil {
		return
	}
	architecture := "win64"
	if (hctx.Mem != nil && hctx.Mem.Mode32) || (hctx.ProcState != nil && hctx.ProcState.Is32) {
		architecture = "i386"
	}
	for _, synth := range hctx.SynthByName {
		module := normalizeCRTModule(synth.Name)
		if module == "" {
			continue
		}
		for _, def := range definitions {
			if !crtDefinitionValid(def) || !crtAllowedModule(def, module) || !crtArchAllowed(def, architecture) {
				continue
			}
			addr, ok := synth.Exports[def.ExportName]
			if !ok {
				continue
			}
			if _, ok := synth.StubIDs[addr]; !ok {
				continue
			}
			hctx.Disp.RegisterSemanticHandler(synth, def.ExportName, ntapi.SemanticHandler{
				ImplementationID: def.ImplementationID,
				Signature:        def.Signature,
				ContractCaseID:   def.ContractCaseID,
				Handler:          def.Handler,
			})
		}
	}
}

func normalizeCRTModule(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return ""
	}
	if !strings.HasSuffix(name, ".dll") {
		name += ".dll"
	}
	return name
}

func crtAllowedModule(def crtSemanticDefinition, module string) bool {
	module = normalizeCRTModule(module)
	for _, allowed := range def.AllowedModules {
		if normalizeCRTModule(allowed) == module {
			return true
		}
	}
	return false
}

func crtDefinitionValid(def crtSemanticDefinition) bool {
	if def.ExportName == "" || def.ImplementationID == "" || def.Signature == "" || def.ContractCaseID == "" || def.Handler == nil || len(def.AllowedModules) == 0 || len(def.AllowedArch) == 0 {
		return false
	}
	if strings.Contains(strings.ToLower(def.ImplementationID), "stub") || strings.Contains(strings.ToLower(def.ImplementationID), "noop") || strings.Contains(strings.ToLower(def.ImplementationID), "placeholder") || strings.Contains(strings.ToLower(def.ImplementationID), "unimplemented") {
		return false
	}
	return true
}

type crtRegistryIssue struct {
	Module string
	Name   string
	Reason string
}

type crtRegisteredRoute struct {
	Module       string
	Name         string
	Architecture string
	Signature    string
	Definition   crtSemanticDefinition
}

type crtSpecRoute struct {
	Module       string
	Name         string
	Architecture string
	Signature    string
	Forwarder    string
	SourceAlias  string
}

type crtSpecCorpus struct {
	Routes         []crtSpecRoute
	NonStubEntries int
	UniqueNames    int
	Exclusions     []crtRegistryIssue
}

type crtCertificate struct {
	ParsedNonStub int
	UniqueNames   int
	ValidRoutes   []crtRegisteredRoute
	Duplicates    []crtRegistryIssue
	Exclusions    []crtRegistryIssue
}

func (c crtCertificate) validRouteCount() int { return len(c.ValidRoutes) }

func (c crtCertificate) semanticImplementationCount() int {
	implementations := make(map[string]struct{})
	for _, route := range c.ValidRoutes {
		implementations[route.Definition.ImplementationID] = struct{}{}
	}
	return len(implementations)
}

type crtContractKey struct {
	Module           string
	Name             string
	Architecture     string
	ImplementationID string
	Signature        string
}

type crtContractEvidence struct {
	runID                uint64
	caseID               string
	executed             bool
	passed               bool
	callCount            int
	assertionCount       int
	distinctInputs       int
	distinctObservations int
	memoryChanged        bool
	handlerPointer       uintptr
	errors               []string
}

type crtContractMemoryWatch struct {
	Address uint64
	Size    int
}

type crtContractCall struct {
	args           []uint64
	before         [][]byte
	after          [][]byte
	returnValue    uint64
	abortCode      int
	abortAsserted  bool
	handlerPointer uintptr
	stackPreserved bool
	assertions     int
	failed         bool
}

type crtContractResult struct {
	invocation *crtContractInvocation
	callIndex  int
	Return     uint64
}

type crtContractInvocation struct {
	Dispatcher *ntapi.Dispatcher
	Synth      *ntapi.SynthPE
	Mem        *mmu.MMU
	Is32       bool
	Module     string
	Name       string
	calls      []crtContractCall
	errors     []string
}

func (inv *crtContractInvocation) Call(args ...uint64) (uint64, error) {
	result, err := inv.CallWatching(nil, args...)
	return result.Return, err
}

func (inv *crtContractInvocation) CallWatching(watches []crtContractMemoryWatch, args ...uint64) (crtContractResult, error) {
	return inv.callWatching(watches, false, args...)
}

func (inv *crtContractInvocation) CallReturn64(args ...uint64) (uint64, error) {
	result, err := inv.callWatching(nil, true, args...)
	return result.Return, err
}

func (inv *crtContractInvocation) CallWatchingReturn64(watches []crtContractMemoryWatch, args ...uint64) (crtContractResult, error) {
	return inv.callWatching(watches, true, args...)
}

func (inv *crtContractInvocation) callWatching(watches []crtContractMemoryWatch, return64 bool, args ...uint64) (crtContractResult, error) {
	result := crtContractResult{invocation: inv, callIndex: -1}
	if inv == nil || inv.Dispatcher == nil || inv.Synth == nil || inv.Mem == nil {
		return result, fmt.Errorf("invalid CRT contract invocation")
	}
	addr, ok := inv.Synth.Exports[inv.Name]
	if !ok {
		return result, fmt.Errorf("missing export %s!%s", inv.Module, inv.Name)
	}
	id, ok := inv.Synth.StubIDs[addr]
	if !ok {
		return result, fmt.Errorf("export %s!%s is not a trap route", inv.Module, inv.Name)
	}
	registration, ok := inv.Dispatcher.SemanticHandlers()[inv.Module][inv.Name]
	if !ok || registration.Handler == nil {
		return result, fmt.Errorf("missing semantic registration for %s!%s", inv.Module, inv.Name)
	}
	call := crtContractCall{args: append([]uint64(nil), args...), handlerPointer: reflect.ValueOf(registration.Handler).Pointer()}
	for _, watch := range watches {
		if watch.Size < 0 {
			return result, fmt.Errorf("negative memory watch size")
		}
		value, err := inv.Mem.ReadBytes(watch.Address, watch.Size)
		if err != nil {
			return result, fmt.Errorf("read contract input at %#x: %w", watch.Address, err)
		}
		call.before = append(call.before, value)
	}
	stackBase := inv.Mem.Mmap(0, 2*mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	if stackBase == 0 {
		return result, fmt.Errorf("unable to allocate contract stack")
	}
	defer inv.Mem.Munmap(stackBase, 2*mmu.PageSize)
	stack := stackBase + mmu.PageSize
	ret := uint64(0x7F000001)
	cpu := x64.New(inv.Mem)
	cpu.Mode32 = inv.Is32
	cpu.SetVmcallHandler(inv.Dispatcher.Handle)
	if inv.Is32 {
		if err := inv.Mem.Write32(stack, uint32(ret)); err != nil {
			return result, err
		}
		for i, arg := range args {
			if err := inv.Mem.Write32(stack+4+uint64(i*4), uint32(arg)); err != nil {
				return result, err
			}
		}
	} else {
		if err := inv.Mem.Write64(stack, ret); err != nil {
			return result, err
		}
		registers := []int{1, 2, 8, 9}
		for i, arg := range args {
			if i < len(registers) {
				cpu.Regs[registers[i]] = arg
				continue
			}
			if err := inv.Mem.Write64(stack+0x28+uint64((i-4)*8), arg); err != nil {
				return result, err
			}
		}
	}
	cpu.SetSP(stack)
	cpu.Regs[0] = uint64(id)
	inv.Dispatcher.Handle(cpu)
	call.returnValue = cpu.Regs[0]
	if exitError, ok := cpu.AbortError().(*arch.ExitError); ok {
		call.abortCode = exitError.Code
	}
	if inv.Is32 && return64 {
		call.returnValue = uint64(uint32(cpu.Regs[0])) | uint64(uint32(cpu.Regs[2]))<<32
	}
	call.stackPreserved = cpu.GetSP() == stack
	for _, watch := range watches {
		value, err := inv.Mem.ReadBytes(watch.Address, watch.Size)
		if err != nil {
			return result, fmt.Errorf("read contract output at %#x: %w", watch.Address, err)
		}
		call.after = append(call.after, value)
	}
	inv.calls = append(inv.calls, call)
	result.callIndex = len(inv.calls) - 1
	result.Return = call.returnValue
	return result, nil
}

func (result crtContractResult) recordAssertion(ok bool, format string, args ...any) {
	if result.invocation == nil || result.callIndex < 0 || result.callIndex >= len(result.invocation.calls) {
		return
	}
	call := &result.invocation.calls[result.callIndex]
	call.assertions++
	if ok {
		return
	}
	call.failed = true
	result.invocation.errors = append(result.invocation.errors, fmt.Sprintf(format, args...))
}

func (result crtContractResult) ExpectReturn(want uint64) {
	result.recordAssertion(result.Return == want, "return value %#x, want %#x", result.Return, want)
}

func (result crtContractResult) ExpectAbort(want int) {
	if result.invocation == nil || result.callIndex < 0 || result.callIndex >= len(result.invocation.calls) {
		return
	}
	got := result.invocation.calls[result.callIndex].abortCode
	result.invocation.calls[result.callIndex].abortAsserted = true
	result.recordAssertion(got == want, "abort code %#x, want %#x", got, want)
}

func (result crtContractResult) ExpectInt32Sign(want int) {
	got := int32(result.Return)
	ok := (want < 0 && got < 0) || (want == 0 && got == 0) || (want > 0 && got > 0)
	result.recordAssertion(ok, "signed return value %d has unexpected sign %d", got, want)
}

func (result crtContractResult) ExpectMemory(watch int, want []byte) {
	if result.invocation == nil || result.callIndex < 0 || result.callIndex >= len(result.invocation.calls) {
		return
	}
	call := &result.invocation.calls[result.callIndex]
	if watch < 0 || watch >= len(call.after) {
		result.recordAssertion(false, "memory watch %d is absent", watch)
		return
	}
	result.recordAssertion(bytes.Equal(call.after[watch], want), "memory watch %d is %x, want %x", watch, call.after[watch], want)
}

func (inv *crtContractInvocation) Failf(format string, args ...any) {
	if inv != nil {
		inv.errors = append(inv.errors, fmt.Sprintf(format, args...))
	}
}

var crtContractRunID atomic.Uint64

type crtContractCase struct {
	CaseID           string
	Module           string
	ExportName       string
	Architecture     string
	ImplementationID string
	Signature        string
	Exercise         func(*crtContractInvocation)
}

var (
	crtContractCasesMu sync.RWMutex
	crtContractCases   = make(map[crtContractKey]crtContractCase)
)

// registerCRTContractCase publishes an executable contract for one exact
// route. Metadata without a registered exercise can never produce evidence.
func registerCRTContractCase(contractCase crtContractCase) bool {
	if contractCase.CaseID == "" || contractCase.Exercise == nil {
		return false
	}
	key := crtContractKey{
		Module:           normalizeCRTModule(contractCase.Module),
		Name:             contractCase.ExportName,
		Architecture:     contractCase.Architecture,
		ImplementationID: contractCase.ImplementationID,
		Signature:        contractCase.Signature,
	}
	crtContractCasesMu.Lock()
	defer crtContractCasesMu.Unlock()
	if existing, exists := crtContractCases[key]; exists {
		return existing.CaseID == contractCase.CaseID
	}
	contractCase.Module = key.Module
	crtContractCases[key] = contractCase
	return true
}

type crtContractRun struct {
	id       uint64
	evidence map[crtContractKey]crtContractEvidence
}

func newCRTContractRun() *crtContractRun {
	return &crtContractRun{
		id:       crtContractRunID.Add(1),
		evidence: make(map[crtContractKey]crtContractEvidence),
	}
}

func (run *crtContractRun) Execute(hctx *HandlerCtx) {
	if run == nil || hctx == nil || hctx.Disp == nil || hctx.Mem == nil {
		return
	}
	architecture := "win64"
	if hctx.Mem.Mode32 {
		architecture = "i386"
	}
	crtContractCasesMu.RLock()
	cases := make(map[crtContractKey]crtContractCase, len(crtContractCases))
	for key, contractCase := range crtContractCases {
		cases[key] = contractCase
	}
	crtContractCasesMu.RUnlock()
	registrations := hctx.Disp.SemanticHandlers()
	for key, contractCase := range cases {
		if key.Architecture != architecture {
			continue
		}
		registration, registered := registrations[key.Module][key.Name]
		if !registered || registration.Handler == nil ||
			registration.ImplementationID != key.ImplementationID ||
			registration.Signature != key.Signature ||
			registration.ContractCaseID != contractCase.CaseID {
			continue
		}
		var synth *ntapi.SynthPE
		for _, candidate := range hctx.SynthByName {
			if normalizeCRTModule(candidate.Name) == key.Module {
				synth = candidate
				break
			}
		}
		if synth == nil {
			continue
		}
		invocation := &crtContractInvocation{
			Dispatcher: hctx.Disp,
			Synth:      synth,
			Mem:        hctx.Mem,
			Is32:       hctx.Mem.Mode32,
			Module:     key.Module,
			Name:       key.Name,
		}
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					invocation.Failf("contract panic: %v", recovered)
				}
			}()
			contractCase.Exercise(invocation)
		}()
		run.evidence[key] = invocation.buildEvidence(run.id, contractCase.CaseID, reflect.ValueOf(registration.Handler).Pointer())
	}
}

func (inv *crtContractInvocation) buildEvidence(runID uint64, caseID string, registeredPointer uintptr) crtContractEvidence {
	evidence := crtContractEvidence{
		runID:          runID,
		caseID:         caseID,
		executed:       true,
		callCount:      len(inv.calls),
		handlerPointer: registeredPointer,
		errors:         append([]string(nil), inv.errors...),
	}
	inputs := make(map[string]struct{})
	observations := make(map[string]struct{})
	returns := make(map[uint64]struct{})
	allExpectedAborted := len(inv.calls) > 0
	for i, call := range inv.calls {
		evidence.assertionCount += call.assertions
		if call.assertions == 0 {
			evidence.errors = append(evidence.errors, fmt.Sprintf("call %d has no executable assertion", i))
		}
		if call.failed {
			continue
		}
		if call.handlerPointer != registeredPointer {
			evidence.errors = append(evidence.errors, fmt.Sprintf("call %d dispatched a different handler", i))
		}
		if !call.stackPreserved {
			evidence.errors = append(evidence.errors, fmt.Sprintf("call %d violated cdecl stack ownership", i))
		}
		if call.abortCode == 0 || !call.abortAsserted {
			allExpectedAborted = false
		}
		var input strings.Builder
		fmt.Fprintf(&input, "%x", call.args)
		for _, value := range call.before {
			fmt.Fprintf(&input, ":%x", value)
		}
		inputs[input.String()] = struct{}{}

		var observation strings.Builder
		fmt.Fprintf(&observation, "%x:%x", call.returnValue, call.abortCode)
		returns[call.returnValue] = struct{}{}
		for watch := range call.before {
			if bytes.Equal(call.before[watch], call.after[watch]) {
				continue
			}
			evidence.memoryChanged = true
			fmt.Fprintf(&observation, ":%d:%x", watch, call.after[watch])
		}
		observations[observation.String()] = struct{}{}
	}
	evidence.distinctInputs = len(inputs)
	evidence.distinctObservations = len(observations)
	if evidence.callCount < 2 {
		evidence.errors = append(evidence.errors, "contract requires at least two dispatched calls")
	}
	if evidence.distinctInputs < 2 {
		evidence.errors = append(evidence.errors, "contract inputs did not vary")
	}
	if evidence.distinctObservations < 2 && !allExpectedAborted {
		evidence.errors = append(evidence.errors, "handler behavior did not vary with the contract inputs")
	}
	if !evidence.memoryChanged && len(returns) < 2 && !allExpectedAborted {
		evidence.errors = append(evidence.errors, "handler is observationally constant")
	}
	evidence.passed = len(evidence.errors) == 0
	return evidence
}

func crtCertificateForRoutes(routes []crtSpecRoute, registrations map[string]map[string]ntapi.SemanticHandler, definitions []crtSemanticDefinition, run *crtContractRun) crtCertificate {
	certificate := crtCertificate{ParsedNonStub: len(routes)}
	seenNames := make(map[string]struct{})
	seenRoutes := make(map[string]struct{})
	corpusRoutes := make(map[string]struct{})
	byKey := make(map[string][]crtSemanticDefinition)
	for _, def := range definitions {
		for _, module := range def.AllowedModules {
			key := normalizeCRTModule(module) + "\x00" + strings.ToLower(def.ExportName)
			byKey[key] = append(byKey[key], def)
		}
	}
	for _, route := range routes {
		key := route.Module + "\x00" + strings.ToLower(route.Name) + "\x00" + route.Architecture + "\x00" + route.Signature
		corpusRoutes[key] = struct{}{}
	}
	for _, route := range routes {
		if route.Name != "" {
			seenNames[strings.ToLower(route.Name)] = struct{}{}
		}
		key := route.Module + "\x00" + strings.ToLower(route.Name) + "\x00" + route.Architecture
		if _, duplicate := seenRoutes[key]; duplicate {
			certificate.Duplicates = append(certificate.Duplicates, crtRegistryIssue{Module: route.Module, Name: route.Name, Reason: "duplicate module/name/architecture route"})
			continue
		}
		seenRoutes[key] = struct{}{}
		defs := byKey[route.Module+"\x00"+strings.ToLower(route.Name)]
		if len(defs) == 0 {
			certificate.Exclusions = append(certificate.Exclusions, crtRegistryIssue{Module: route.Module, Name: route.Name, Reason: "no exact semantic definition"})
			continue
		}
		registration, registered := registrations[route.Module][route.Name]
		if !registered || registration.Handler == nil {
			certificate.Exclusions = append(certificate.Exclusions, crtRegistryIssue{Module: route.Module, Name: route.Name, Reason: "missing executable handler"})
			continue
		}
		matched := false
		reason := "no ABI-compatible semantic definition"
		for _, def := range defs {
			if !crtDefinitionValid(def) {
				reason = "invalid semantic definition"
				continue
			}
			if def.Signature != route.Signature || registration.Signature != def.Signature {
				reason = "ABI signature mismatch"
				continue
			}
			if !crtArchAllowed(def, route.Architecture) {
				reason = "architecture not implemented"
				continue
			}
			if registration.ImplementationID != def.ImplementationID ||
				registration.ContractCaseID != def.ContractCaseID ||
				reflect.ValueOf(def.Handler).Pointer() != reflect.ValueOf(registration.Handler).Pointer() {
				reason = "dispatcher registration does not match semantic definition"
				continue
			}
			if route.Forwarder != "" && !crtForwarderMatches(route, def, byKey, corpusRoutes) {
				reason = "forwarder target is absent or not ABI-compatible"
				continue
			}
			if run == nil {
				reason = "executable contract suite was not run"
				continue
			}
			key := crtContractKey{Module: route.Module, Name: route.Name, Architecture: route.Architecture, ImplementationID: def.ImplementationID, Signature: def.Signature}
			caseEvidence, hasEvidence := run.evidence[key]
			if !hasEvidence {
				reason = "named executable contract case is absent or was not run"
				continue
			}
			if caseEvidence.runID != run.id || caseEvidence.caseID != def.ContractCaseID || !caseEvidence.executed {
				reason = "contract evidence is stale or belongs to a different case"
				continue
			}
			if !caseEvidence.passed {
				reason = "executable contract failed: " + strings.Join(caseEvidence.errors, "; ")
				continue
			}
			if caseEvidence.callCount < 2 || caseEvidence.assertionCount < caseEvidence.callCount ||
				caseEvidence.distinctInputs < 2 || caseEvidence.distinctObservations < 2 {
				reason = "contract lacks input-dependent executable assertions"
				continue
			}
			if caseEvidence.handlerPointer != reflect.ValueOf(registration.Handler).Pointer() {
				reason = "contract dispatched a different handler"
				continue
			}
			certificate.ValidRoutes = append(certificate.ValidRoutes, crtRegisteredRoute{Module: route.Module, Name: route.Name, Architecture: route.Architecture, Signature: route.Signature, Definition: def})
			matched = true
			break
		}
		if !matched {
			certificate.Exclusions = append(certificate.Exclusions, crtRegistryIssue{Module: route.Module, Name: route.Name, Reason: reason})
		}
	}
	certificate.UniqueNames = len(seenNames)
	return certificate
}

func crtForwarderMatches(route crtSpecRoute, def crtSemanticDefinition, definitions map[string][]crtSemanticDefinition, corpusRoutes map[string]struct{}) bool {
	separator := strings.LastIndexByte(route.Forwarder, '.')
	if separator <= 0 || separator == len(route.Forwarder)-1 {
		return false
	}
	targetModule := normalizeCRTModule(route.Forwarder[:separator])
	targetName := route.Forwarder[separator+1:]
	if !strings.EqualFold(targetName, route.Name) {
		return false
	}
	targetRoute := targetModule + "\x00" + strings.ToLower(targetName) + "\x00" + route.Architecture + "\x00" + route.Signature
	if _, exists := corpusRoutes[targetRoute]; !exists {
		return false
	}
	for _, targetDefinition := range definitions[targetModule+"\x00"+strings.ToLower(targetName)] {
		if targetDefinition.ImplementationID == def.ImplementationID &&
			targetDefinition.Signature == def.Signature &&
			reflect.ValueOf(targetDefinition.Handler).Pointer() == reflect.ValueOf(def.Handler).Pointer() &&
			crtArchAllowed(targetDefinition, route.Architecture) {
			return true
		}
	}
	return false
}

func crtCertificateForCorpus(corpus crtSpecCorpus, registrations map[string]map[string]ntapi.SemanticHandler, definitions []crtSemanticDefinition, run *crtContractRun) crtCertificate {
	certificate := crtCertificateForRoutes(corpus.Routes, registrations, definitions, run)
	certificate.ParsedNonStub = corpus.NonStubEntries
	certificate.UniqueNames = corpus.UniqueNames
	certificate.Exclusions = append(corpus.Exclusions, certificate.Exclusions...)
	return certificate
}

func crtCompatibilityGate(certificate crtCertificate, threshold int) error {
	if certificate.validRouteCount() < threshold {
		return fmt.Errorf("CRT compatibility gate: %d valid routes, need %d", certificate.validRouteCount(), threshold)
	}
	return nil
}

func crtArchAllowed(def crtSemanticDefinition, arch string) bool {
	for _, allowed := range def.AllowedArch {
		if strings.EqualFold(allowed, arch) {
			return true
		}
	}
	return false
}

func crtRegistryDefinitionError(def crtSemanticDefinition) error {
	if crtDefinitionValid(def) {
		return nil
	}
	return fmt.Errorf("invalid CRT semantic definition for %q", def.ExportName)
}
