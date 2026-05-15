package jit

import (
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"golang.org/x/sys/unix"
)

const nativeCoverageVersion = 5

type nativeCoverageReport struct {
	Version         int                     `json:"version"`
	CorpusID        string                  `json:"corpus_id"`
	ConfigHash      string                  `json:"config_hash"`
	SampleStride    int                     `json:"sample_stride"`
	SamplingModel   string                  `json:"sampling_model"`
	MaxStarts       int                     `json:"max_starts_per_fixture"`
	HotnessModel    string                  `json:"hotness_model"`
	HotnessSource   string                  `json:"hotness_source"`
	HotnessClamp    int                     `json:"hotness_max_weight"`
	NativeAvailable bool                    `json:"native_available"`
	FixtureHashes   map[string]string       `json:"fixture_hashes"`
	Fixtures        []nativeCoverageFixture `json:"fixtures"`
	Totals          nativeCoverageTotals    `json:"totals"`
	TopUnsupported  []nativeCoverageGap     `json:"top_unsupported_families"`
}

type nativeCoverageFixture struct {
	Name                         string         `json:"name"`
	Mode                         string         `json:"mode"`
	RealBinary                   bool           `json:"real_binary"`
	Usable                       bool           `json:"usable"`
	SamplingConfidence           string         `json:"sampling_confidence"`
	UnusableReason               string         `json:"unusable_reason,omitempty"`
	NativeMemoryCapability       string         `json:"native_memory_capability"`
	FixtureHash                  string         `json:"fixture_hash"`
	EntryRVA                     uint32         `json:"entry_rva"`
	EntryVA                      uint64         `json:"entry_va"`
	EntryFileOffset              uint32         `json:"entry_file_offset"`
	EntryBytes                   string         `json:"entry_bytes"`
	EntryDecode                  string         `json:"entry_decode"`
	Sections                     int            `json:"executable_sections"`
	RawExecutableBytes           int            `json:"raw_executable_bytes"`
	VirtualTailBytes             int            `json:"virtual_tail_bytes"`
	Starts                       int            `json:"sampled_starts"`
	WeightedStarts               int            `json:"weighted_starts"`
	SeedCounts                   map[string]int `json:"seed_source_counts"`
	DecodedBlocks                int            `json:"decoded_blocks"`
	WeightedDecodedBlocks        int            `json:"weighted_decoded_blocks"`
	DecodedInstructions          int            `json:"decoded_instructions"`
	WeightedInstructions         int            `json:"weighted_instructions"`
	NativeWholeBlocks            int            `json:"native_whole_blocks"`
	WeightedWholeBlocks          int            `json:"weighted_whole_blocks"`
	NativePrefixInstructions     int            `json:"native_prefix_instructions"`
	WeightedPrefixInstructions   int            `json:"weighted_prefix_instructions"`
	DecoderErrors                int            `json:"decoder_errors"`
	WeightedDecoderErrors        int            `json:"weighted_decoder_errors"`
	FirstOpEndRejections         int            `json:"first_op_end_rejections"`
	WeightedFirstOpEndRejections int            `json:"weighted_first_op_end_rejections"`
	ArenaExhaustions             int            `json:"arena_exhaustions"`
	WeightedArenaExhaustions     int            `json:"weighted_arena_exhaustions"`
	OpKinds                      map[string]int `json:"op_kind_frequency"`
	WeightedOpKinds              map[string]int `json:"weighted_op_kind_frequency"`
	OperandForms                 map[string]int `json:"operand_form_frequency"`
	WeightedOperandForms         map[string]int `json:"weighted_operand_form_frequency"`
	FallbackOpKinds              map[string]int `json:"fallback_op_kind"`
	WeightedFallbackOpKinds      map[string]int `json:"weighted_fallback_op_kind"`
	FallbackInstructions         map[string]int `json:"fallback_instruction"`
	WeightedFallbackInstructions map[string]int `json:"weighted_fallback_instruction"`
	CompilerRejections           map[string]int `json:"compiler_rejection_family"`
	WeightedCompilerRejections   map[string]int `json:"weighted_compiler_rejection_family"`
	Categories                   map[string]int `json:"categories"`
	WeightedCategories           map[string]int `json:"weighted_categories"`
	PrefixHistogram              map[string]int `json:"native_prefix_length"`
	WeightedPrefixHistogram      map[string]int `json:"weighted_native_prefix_length"`
}

type nativeCoverageTotals struct {
	Starts                       int            `json:"sampled_starts_raw"`
	WeightedStarts               int            `json:"sampled_starts_weighted"`
	DecodedBlocks                int            `json:"decoded_blocks_raw"`
	WeightedDecodedBlocks        int            `json:"decoded_blocks_weighted"`
	DecodedInstructions          int            `json:"decoded_instructions_raw"`
	WeightedInstructions         int            `json:"decoded_instructions_weighted"`
	NativeWholeBlocks            int            `json:"native_whole_blocks_raw"`
	WeightedWholeBlocks          int            `json:"native_whole_blocks_weighted"`
	NativePrefixInstructions     int            `json:"native_prefix_instructions_raw"`
	WeightedPrefixInstructions   int            `json:"native_prefix_instructions_weighted"`
	DecoderErrors                int            `json:"decoder_errors_raw"`
	WeightedDecoderErrors        int            `json:"decoder_errors_weighted"`
	FirstOpEndRejections         int            `json:"first_op_end_rejections_raw"`
	WeightedFirstOpEndRejections int            `json:"first_op_end_rejections_weighted"`
	ArenaExhaustions             int            `json:"arena_exhaustions_raw"`
	WeightedArenaExhaustions     int            `json:"arena_exhaustions_weighted"`
	OpKinds                      map[string]int `json:"op_kind_frequency_raw"`
	WeightedOpKinds              map[string]int `json:"op_kind_frequency_weighted"`
	OperandForms                 map[string]int `json:"operand_form_frequency_raw"`
	WeightedOperandForms         map[string]int `json:"operand_form_frequency_weighted"`
	FallbackOpKinds              map[string]int `json:"fallback_op_kind_raw"`
	WeightedFallbackOpKinds      map[string]int `json:"fallback_op_kind_weighted"`
	FallbackInstructions         map[string]int `json:"fallback_instruction_raw"`
	WeightedFallbackInstructions map[string]int `json:"fallback_instruction_weighted"`
	CompilerRejections           map[string]int `json:"compiler_rejection_family_raw"`
	WeightedCompilerRejections   map[string]int `json:"compiler_rejection_family_weighted"`
	Categories                   map[string]int `json:"categories_raw"`
	WeightedCategories           map[string]int `json:"categories_weighted"`
	PrefixHistogram              map[string]int `json:"native_prefix_length_raw"`
	WeightedPrefixHistogram      map[string]int `json:"native_prefix_length_weighted"`
}

type nativeCoverageGap struct {
	OpKind       string `json:"op_kind"`
	Fallbacks    int    `json:"fallbacks"`
	Instructions int    `json:"instructions"`
	Family       string `json:"family"`
	Weighted     bool   `json:"weighted"`
}

type coverageStart struct {
	rva    uint32
	source string
}
type coverageSection struct {
	rva  uint32
	data []byte
	end  uint32
}

type coverageHotnessKey struct {
	fixture string
	address uint64
}

type coverageHotness map[coverageHotnessKey]int

var nativeCoverageMaxStarts = flag.Int("native-coverage-max-starts", 20000, "maximum sampled starts per real fixture")

func TestNativeJITCoverageAggregation(t *testing.T) {
	g := newCoverageFixture("test", "PE32")
	addCoverageInstruction(&g, insn{kind: opMovRegImm, size: 8, dst: 0}, 2)
	addCoverageInstruction(&g, insn{kind: opX87, size: 8}, 1)
	if g.OpKinds["mov_reg_imm"] != 1 || g.WeightedOpKinds["mov_reg_imm"] != 2 || g.Categories["x87"] != 1 || g.WeightedInstructions != 3 {
		t.Fatalf("aggregation = %+v", g)
	}
}

func TestNativeJITCoverageDeterministicHelpers(t *testing.T) {
	starts := discoverStarts([]coverageStart{{2, "fallthrough"}, {1, "entrypoint"}, {2, "pdata"}})
	if len(starts) != 2 || starts[0].rva != 1 || starts[1].source != "pdata" {
		t.Fatalf("starts = %+v", starts)
	}
	if got := classifyCompilerRejection([]insn{{kind: opMovRegMem, memBase: 0}}, false); got != "memory_disabled:mov_reg_mem" {
		t.Fatalf("rejection = %q", got)
	}
	if got := ratioPP(0, 0); got != 0 {
		t.Fatalf("zero ratio = %d", got)
	}
	if err := compareNativeCoverage(nativeCoverageReport{Version: 1}, nativeCoverageReport{Version: 1}, 0); err == nil {
		t.Fatal("malformed baseline accepted")
	}
}

func TestNativeJITCoverageStaticControlTargets(t *testing.T) {
	section := coverageSection{
		rva:  0x1000,
		end:  0x1020,
		data: []byte{0xe8, 0x0b, 0, 0, 0, 0x75, 0x09, 0x90, 0xeb, 0x06, 0x0f, 0x85, 0, 0, 0, 0, 0xc3},
	}
	got := staticControlTargetStarts([]coverageSection{section})
	want := []coverageStart{{0x1010, "static_call_target"}}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("static targets = %+v, want %+v", got, want)
	}
}

func TestNativeJITCoverageBlockSuccessors(t *testing.T) {
	got := decodedBlockSuccessors([]insn{
		{kind: opNop, nextRIP: 0x401001},
		{kind: opJcc, target: 0x401020, nextRIP: 0x401003},
	}, 0x400000)
	want := []coverageStart{{0x1020, "branch_target"}, {0x1003, "fallthrough"}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("successors = %+v, want %+v", got, want)
	}
}

func TestNativeJITCoverageRejectsEmptyRealFixture(t *testing.T) {
	fixture := newCoverageFixture("DX-Ball", "PE32")
	fixture.RealBinary = true
	fixture.EntryRVA = 0x31e0
	fixture.EntryVA = 0x4031e0
	fixture.EntryFileOffset = 0x25e0
	fixture.EntryBytes = "64a100000000"
	fixture.EntryDecode = "op_end:byte_0x64:segment_prefix"
	if err := validateRealFixture(fixture); err == nil || !strings.Contains(err.Error(), "0x4031e0") {
		t.Fatalf("empty real fixture error = %v", err)
	}
	fixture.Usable = true
	fixture.DecodedBlocks = 1
	fixture.DecodedInstructions = 1
	if err := validateRealFixture(fixture); err != nil {
		t.Fatalf("measurable zero native acceptance rejected: %v", err)
	}
}

func TestNativeJITCoverageBaselineValidation(t *testing.T) {
	fixture := newCoverageFixture("NPP", "PE64")
	fixture.RealBinary = true
	fixture.Usable = true
	fixture.FixtureHash = "fixture"
	fixture.DecodedBlocks = 10
	fixture.DecodedInstructions = 100
	fixture.NativePrefixInstructions = 80
	fixture.WeightedInstructions = 100
	fixture.WeightedPrefixInstructions = 80
	base := nativeCoverageReport{Version: nativeCoverageVersion, CorpusID: "corpus", ConfigHash: "config", MaxStarts: 10, HotnessSource: "default:1", FixtureHashes: map[string]string{"NPP": "fixture"}, Fixtures: []nativeCoverageFixture{fixture}}
	current := base
	current.Fixtures = []nativeCoverageFixture{fixture}
	current.Fixtures[0].NativePrefixInstructions = 75
	current.Fixtures[0].WeightedPrefixInstructions = 75
	if err := compareNativeCoverage(current, base, 5); err != nil {
		t.Fatalf("exact threshold rejected: %v", err)
	}
	current.Fixtures[0].DecodedInstructions = 0
	current.Fixtures[0].WeightedInstructions = 0
	current.Fixtures[0].WeightedPrefixInstructions = 0
	if err := compareNativeCoverage(current, base, 0); err == nil {
		t.Fatal("zero denominator accepted")
	}
	current = base
	current.Fixtures = []nativeCoverageFixture{fixture}
	current.Fixtures[0].WeightedInstructions = 0
	current.Fixtures[0].WeightedPrefixInstructions = 0
	if err := compareNativeCoverage(current, base, 0); err == nil || !strings.Contains(err.Error(), "weighted denominator") {
		t.Fatalf("one-sided weighted denominator error = %v", err)
	}
	base.Fixtures[0].WeightedInstructions = 0
	base.Fixtures[0].WeightedPrefixInstructions = 0
	if err := compareNativeCoverage(current, base, 0); err != nil {
		t.Fatalf("matching zero-weight samples rejected: %v", err)
	}
	bad := base
	bad.CorpusID = "other"
	if err := compareNativeCoverage(bad, base, 0); err == nil {
		t.Fatal("corpus mismatch accepted")
	}
	first, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("report serialization is nondeterministic")
	}
}

func BenchmarkNativeJITCoverage(b *testing.B) {
	if os.Getenv("RAVEN_NATIVE_JIT_COVERAGE") != "1" {
		b.Skip("set RAVEN_NATIVE_JIT_COVERAGE=1 for real-binary coverage")
	}
	for i := 0; i < b.N; i++ {
		if _, err := collectNativeCoverage(*nativeCoverageMaxStarts, os.Getenv("RAVEN_NATIVE_JIT_HOTNESS")); err != nil {
			b.Fatal(err)
		}
	}
}

func TestNativeJITCoverageWeightedFallbackAndGaps(t *testing.T) {
	g := newCoverageFixture("test", "PE32")
	m := mmu.New()
	cache := NewCacheMode(m, true)
	if !cache.EnableNativeCodegen() {
		t.Skip("native codegen unavailable")
	}
	if err := analyzeCoverageInsns(&g, cache, []insn{{kind: opNop}, {kind: opX87}, {kind: opRet}}, 3); err != nil {
		t.Fatal(err)
	}
	if g.WeightedPrefixInstructions != 3 || g.WeightedFallbackOpKinds["x87"] != 3 {
		t.Fatalf("weighted fallback = %+v", g)
	}
	if cache.exec.used != 0 {
		t.Fatalf("probe modified shared arena: used=%d", cache.exec.used)
	}
	weights := coverageHotness{{"NPP", 0x1000}: 7, {"DX-Ball", 0x1000}: 11}
	if got := weightFor("NPP", 0x1000, 0, weights); got != 7 {
		t.Fatalf("NPP hotness = %d", got)
	}
	if got := weightFor("DX-Ball", 0x1000, 0, weights); got != 11 {
		t.Fatalf("DX-Ball hotness = %d", got)
	}
	late := newCoverageFixture("late-rejection", "PE64")
	if err := analyzeCoverageInsns(&late, cache, []insn{{kind: opNop}, {kind: opDiv, size: 3, src: 1}, {kind: opRet}}, 1); err != nil {
		t.Fatal(err)
	}
	if late.NativePrefixInstructions != 1 || late.FallbackInstructions["div:register:size3"] != 1 {
		t.Fatalf("late rejection attribution = %+v", late)
	}
	g.CompilerRejections["form:x87"] = 2
	g.WeightedCompilerRejections["form:x87"] = 6
	g.FallbackOpKinds["x87"] = 2
	g.WeightedFallbackOpKinds["x87"] = 6
	var totals nativeCoverageTotals
	mergeCoverageTotals(&totals, g)
	gap := rankCoverageGaps(totals)
	if len(gap) == 0 || gap[0].Family == "" {
		t.Fatalf("gaps = %+v", gap)
	}
}

func TestNativeJITCoverageReport(t *testing.T) {
	if os.Getenv("RAVEN_NATIVE_JIT_COVERAGE") != "1" {
		t.Skip("set RAVEN_NATIVE_JIT_COVERAGE=1 for real-binary coverage")
	}
	maxStarts := *nativeCoverageMaxStarts
	if value := os.Getenv("RAVEN_NATIVE_JIT_MAX_STARTS"); value != "" {
		v, err := strconv.Atoi(value)
		if err != nil || v <= 0 {
			t.Fatalf("invalid max starts %q", value)
		}
		maxStarts = v
	}
	hotness := os.Getenv("RAVEN_NATIVE_JIT_HOTNESS")
	report, err := collectNativeCoverage(maxStarts, hotness)
	if err != nil {
		t.Fatal(err)
	}
	baseline := os.Getenv("RAVEN_NATIVE_JIT_BASELINE")
	thresholdValue := os.Getenv("RAVEN_NATIVE_JIT_MAX_REGRESSION_PP")
	if thresholdValue != "" && baseline == "" {
		t.Fatal("RAVEN_NATIVE_JIT_MAX_REGRESSION_PP requires RAVEN_NATIVE_JIT_BASELINE")
	}
	if baseline != "" {
		data, err := os.ReadFile(baseline)
		if err != nil {
			t.Fatalf("read baseline %q: %v", baseline, err)
		}
		var base nativeCoverageReport
		if err := json.Unmarshal(data, &base); err != nil {
			t.Fatalf("read baseline %q: %v", baseline, err)
		}
		if err := validateCoverageCompatibility(report, base); err != nil {
			t.Fatal(err)
		}
		if thresholdValue != "" {
			threshold, err := strconv.Atoi(thresholdValue)
			if err != nil || threshold < 0 {
				t.Fatalf("invalid regression threshold %q", thresholdValue)
			}
			if err := compareNativeCoverage(report, base, threshold); err != nil {
				t.Fatal(err)
			}
		}
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("RAVEN_NATIVE_JIT_FORMAT") == "text" {
		data = []byte(formatNativeCoverageText(report))
	} else {
		data = append(data, '\n')
	}
	out := os.Getenv("RAVEN_NATIVE_JIT_OUT")
	if out == "" {
		t.Log(string(data))
		return
	}
	if err := os.WriteFile(out, data, 0o644); err != nil {
		t.Fatalf("write report %q: %v", out, err)
	}
	t.Logf("native JIT coverage report: %s", out)
}

func collectNativeCoverage(maxStarts int, hotnessPath string) (nativeCoverageReport, error) {
	if maxStarts <= 0 {
		return nativeCoverageReport{}, fmt.Errorf("max starts must be positive: %d", maxStarts)
	}
	weights, source, err := readHotness(hotnessPath)
	if err != nil {
		return nativeCoverageReport{}, err
	}
	report := nativeCoverageReport{
		Version:       nativeCoverageVersion,
		SampleStride:  0,
		SamplingModel: "metadata-recursive-with-conservative-static-upper-bound-v3",
		MaxStarts:     maxStarts,
		HotnessModel:  "fixture address=count, clamped",
		HotnessSource: source,
		HotnessClamp:  maxHotnessWeight,
		FixtureHashes: map[string]string{},
	}
	paths := []struct{ name, path string }{{"NPP", findFixture("testdata/npp/notepad++.exe")}, {"DX-Ball", findFixture("testdata/games/DXBall.EXE")}}
	for _, fixture := range paths {
		if fixture.path == "" {
			return report, fmt.Errorf("fixture not found: %s", fixture.name)
		}
		got, err := scanPECoverage(fixture.name, fixture.path, maxStarts, weights)
		if err != nil {
			return report, err
		}
		if err := validateRealFixture(got); err != nil {
			return report, err
		}
		report.Fixtures = append(report.Fixtures, got)
		report.FixtureHashes[got.Name] = got.FixtureHash
		mergeCoverageTotals(&report.Totals, got)
	}
	synthetic, err := scanSyntheticCoverage(weights)
	if err != nil {
		return report, err
	}
	report.Fixtures = append(report.Fixtures, synthetic)
	mergeCoverageTotals(&report.Totals, synthetic)
	report.NativeAvailable = true
	report.ConfigHash = coverageConfigHash(report)
	report.CorpusID = coverageCorpusID(report)
	report.TopUnsupported = rankCoverageGaps(report.Totals)
	return report, nil
}

func findFixture(path string) string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		candidate := filepath.Join(dir, path)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		for _, match := range globCaseInsensitive(filepath.Dir(candidate), filepath.Base(path)) {
			return match
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

func globCaseInsensitive(dir, name string) []string {
	matches, _ := filepath.Glob(filepath.Join(dir, "*"))
	sort.Strings(matches)
	for _, match := range matches {
		if strings.EqualFold(filepath.Base(match), name) {
			return []string{match}
		}
	}
	return nil
}

func scanPECoverage(name, path string, maxStarts int, weights coverageHotness) (nativeCoverageFixture, error) {
	f, err := os.Open(path)
	if err != nil {
		return nativeCoverageFixture{}, err
	}
	defer f.Close()
	p, err := pe.NewFile(f)
	if err != nil {
		return nativeCoverageFixture{}, err
	}
	defer p.Close()
	mode32 := false
	if _, ok := p.OptionalHeader.(*pe.OptionalHeader32); ok {
		mode32 = true
	}
	base, mode := peImageBase(p), "PE64"
	if mode32 {
		mode = "PE32"
	}
	m := mmu.New()
	if mode32 {
		if err := m.EnableFlatBacking(); err != nil {
			return nativeCoverageFixture{}, err
		}
	}
	report := newCoverageFixture(name, mode)
	report.RealBinary = true
	report.SamplingConfidence = "metadata"
	report.NativeMemoryCapability = "disabled: PE64 has no flat backing"
	if mode32 {
		report.NativeMemoryCapability = "enabled: PE32 flat backing"
	}
	dataHash, err := fileHash(path)
	if err != nil {
		return report, err
	}
	report.FixtureHash = dataHash
	cache := NewCacheMode(m, mode32)
	if !cache.EnableNativeCodegen() {
		return report, errors.New("native codegen unavailable")
	}
	sections := make([]coverageSection, 0)
	seeds := []coverageStart{}
	for _, section := range p.Sections {
		if section.Characteristics&0x20000000 == 0 || section.Size == 0 {
			continue
		}
		data, err := readSection(section)
		if err != nil {
			return report, fmt.Errorf("read section %s: %w", section.Name, err)
		}
		rva := section.VirtualAddress
		sections = append(sections, coverageSection{rva, data, rva + uint32(len(data))})
		report.Sections++
		report.RawExecutableBytes += len(data)
		if section.VirtualSize > uint32(len(data)) {
			report.VirtualTailBytes += int(section.VirtualSize) - len(data)
		}
		addr := base + uint64(rva)
		mapSize := (uint64(len(data)) + mmu.PageSize - 1) & mmu.PageMask
		m.MapRange(addr&mmu.PageMask, mapSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
		if err := m.WriteBytes(addr, data); err != nil {
			return report, err
		}
		seeds = append(seeds, coverageStart{rva, "section_entry"})
	}
	entry := peEntryRVA(p)
	report.EntryRVA = entry
	report.EntryVA = base + uint64(entry)
	report.EntryFileOffset = peFileOffset(p, entry)
	report.EntryBytes = entryBytes(sections, entry, 8)
	report.EntryDecode = entryDecodeStatus(cache, m, report.EntryVA)
	if inSections(entry, sections) {
		seeds = append(seeds, coverageStart{entry, "entrypoint"})
	}
	metadataSeeds := 0
	for _, rva := range pdataStarts(p) {
		if inSections(rva, sections) {
			seeds = append(seeds, coverageStart{rva, "pdata"})
			metadataSeeds++
		}
	}
	for _, sym := range p.COFFSymbols {
		if sym.SectionNumber > 0 && int(sym.SectionNumber) <= len(p.Sections) {
			rva := p.Sections[sym.SectionNumber-1].VirtualAddress + sym.Value
			if inSections(rva, sections) {
				seeds = append(seeds, coverageStart{rva, "coff_symbol"})
				metadataSeeds++
			}
		}
	}
	if metadataSeeds == 0 {
		report.SamplingConfidence = "static-recovery-unverified"
		seeds = append(seeds, staticControlTargetStarts(sections)...)
	}
	seeds = append(seeds, linearSweepStarts(cache, sections, base)...)
	starts := discoverStarts(seeds)
	sources := map[uint32]string{}
	queue := make([]uint32, 0, len(starts))
	fallback := make([]coverageStart, 0, len(starts))
	knownSources := map[uint32]bool{}
	for _, s := range starts {
		if coverageStartPriority(s.source) <= coverageStartPriority("static_call_target") {
			queue = append(queue, s.rva)
			knownSources[s.rva] = true
			sources[s.rva] = s.source
		} else {
			fallback = append(fallback, s)
		}
	}
	seen := map[uint32]bool{}
	addTarget := func(target uint32, source string) {
		if !inSections(target, sections) || seen[target] {
			return
		}
		if knownSources[target] {
			if isStaticControlRecoverySource(sources[target]) {
				sources[target] = source
			}
			return
		}
		queue = append(queue, target)
		knownSources[target] = true
		sources[target] = source
	}
	for (len(queue) > 0 || len(fallback) > 0) && report.Starts < maxStarts {
		if len(queue) == 0 {
			next := fallback[0]
			fallback = fallback[1:]
			if seen[next.rva] || knownSources[next.rva] {
				continue
			}
			knownSources[next.rva] = true
			sources[next.rva] = next.source
			queue = append(queue, next.rva)
		}
		rva := queue[0]
		queue = queue[1:]
		if seen[rva] {
			continue
		}
		addr := base + uint64(rva)
		insns, _, err := cache.decode(addr)
		seen[rva] = true
		report.SeedCounts[sources[rva]]++
		report.Starts++
		weight := weightFor(name, addr, uint64(rva), weights)
		report.WeightedStarts += weight
		if err != nil {
			report.DecoderErrors++
			report.WeightedDecoderErrors += weight
			recordDecoderError(&report, m, addr, err, weight)
			continue
		}
		if len(insns) == 0 || insns[0].kind == opEnd {
			report.FirstOpEndRejections++
			report.WeightedFirstOpEndRejections += weight
			continue
		}
		count := realInsnCount(insns)
		if count == 0 {
			continue
		}
		if err := analyzeDecodedBlock(&report, cache, insns, weight); err != nil {
			return report, err
		}
		for _, successor := range decodedBlockSuccessors(insns, base) {
			addTarget(successor.rva, successor.source)
		}
	}
	report.Usable = report.DecodedBlocks > 0 && report.DecodedInstructions > 0
	if !report.Usable {
		report.UnusableReason = fmt.Sprintf("no decoded blocks; entry=0x%x bytes=%s decode=%s", report.EntryVA, report.EntryBytes, report.EntryDecode)
	}
	return report, nil
}

func scanSyntheticCoverage(weights coverageHotness) (nativeCoverageFixture, error) {
	report := newCoverageFixture("synthetic-edge-blocks", "PE32/PE64")
	report.SamplingConfidence = "synthetic"
	report.NativeMemoryCapability = "enabled: synthetic PE32 probe"
	m := mmu.New()
	if err := m.EnableFlatBacking(); err != nil {
		return report, err
	}
	cache := NewCacheMode(m, true)
	if !cache.EnableNativeCodegen() {
		return report, errors.New("native codegen unavailable")
	}
	blocks := [][]insn{{{kind: opNop}, {kind: opMovRegImm, size: 4, dst: 0}, {kind: opALURegImm, size: 4, dst: 0, alu: aluADD}, {kind: opRet}}, {{kind: opDiv, size: 4, src: 1}, {kind: opRet}}, {{kind: opMovRegMem, size: 4, dst: 0, memBase: 1, useRIP: true}, {kind: opRet}}, {{kind: opX87, size: 1}, {kind: opRet}}, {{kind: opMMX, opcode: 0x6f, size: 1, dst: 0, src: 1}, {kind: opMMX, opcode: 0x77}, {kind: opRet}}, {{kind: opMovRegMem, size: 4, dst: 0, memBase: 4}, {kind: opRet}}}
	for i, code := range blocks {
		addr := uint64(0x200000 + i*0x1000)
		m.MapRange(addr, mmu.PageSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
		report.Starts++
		weight := weightFor(report.Name, addr, addr, weights)
		report.WeightedStarts += weight
		if err := analyzeCoverageInsns(&report, cache, code, weight); err != nil {
			return report, err
		}
	}
	report.Usable = report.DecodedBlocks > 0 && report.DecodedInstructions > 0
	return report, nil
}

func analyzeDecodedBlock(report *nativeCoverageFixture, cache *Cache, decoded []insn, weight int) error {
	count := realInsnCount(decoded)
	return analyzeCoverageBlock(report, cache, decoded[:count], decoded, weight)
}

func analyzeCoverageInsns(report *nativeCoverageFixture, cache *Cache, insns []insn, weight int) error {
	return analyzeCoverageBlock(report, cache, insns, insns, weight)
}

func analyzeCoverageBlock(report *nativeCoverageFixture, cache *Cache, insns, compileInsns []insn, weight int) error {
	if len(insns) == 0 {
		return nil
	}
	report.DecodedBlocks++
	report.WeightedDecodedBlocks += weight
	for _, in := range insns {
		addCoverageInstruction(report, in, weight)
	}
	if cache == nil {
		return nil
	}
	prefix, whole, exhausted, err := probeNativePrefix(cache, insns, compileInsns)
	if err != nil {
		return err
	}
	if exhausted {
		report.ArenaExhaustions++
		report.WeightedArenaExhaustions += weight
	}
	report.NativePrefixInstructions += prefix
	report.WeightedPrefixInstructions += prefix * weight
	report.PrefixHistogram[strconv.Itoa(prefix)]++
	report.WeightedPrefixHistogram[strconv.Itoa(prefix)] += weight
	if whole {
		report.NativeWholeBlocks++
		report.WeightedWholeBlocks += weight
	} else if prefix < len(insns) {
		recordFallback(report, insns[prefix], weight)
		recordCompilerFallback(report, insns[prefix], cache.nativeMem, weight)
	}
	return nil
}

func probeNativePrefix(cache *Cache, insns, compileInsns []insn) (int, bool, bool, error) {
	accepted, prefix, exhausted, err := compileNativeProbe(cache, compileInsns)
	if err != nil {
		return 0, false, exhausted, err
	}
	if accepted {
		if prefix > len(insns) {
			prefix = len(insns)
		}
		return prefix, prefix == len(insns), exhausted, nil
	}
	low, high := 0, len(insns)
	for low < high {
		mid := (low + high + 1) / 2
		probe := make([]insn, mid, mid+1)
		copy(probe, insns[:mid])
		nextRIP := probe[mid-1].nextRIP
		probe = append(probe, insn{kind: opEnd, rip: nextRIP, nextRIP: nextRIP})
		ok, retired, full, probeErr := compileNativeProbe(cache, probe)
		if probeErr != nil {
			return 0, false, exhausted || full, probeErr
		}
		exhausted = exhausted || full
		if ok && retired == mid {
			low = mid
		} else {
			high = mid - 1
		}
	}
	return low, false, exhausted, nil
}

func compileNativeProbe(cache *Cache, insns []insn) (bool, int, bool, error) {
	probe, err := newExecBuf()
	if err != nil {
		return false, 0, false, err
	}
	old := cache.exec
	cache.exec = probe
	entry, prefix, _, _ := cache.compileNative(insns)
	cache.exec = old
	exhausted := entry == 0 && probe.used >= len(probe.mem)
	if err := unix.Munmap(probe.mem); err != nil {
		return false, 0, exhausted, err
	}
	return entry != 0, prefix, exhausted, nil
}

func recordCompilerFallback(report *nativeCoverageFixture, in insn, nativeMemory bool, weight int) {
	family := classifyCompilerRejection([]insn{in}, nativeMemory)
	report.CompilerRejections[family]++
	report.WeightedCompilerRejections[family] += weight
}
func classifyCompilerRejection(insns []insn, nativeMemory bool) string {
	for _, in := range insns {
		if hasMemoryOperand(in) && !nativeMemory {
			return "memory_disabled:" + opKindName(in.kind)
		}
	}
	if len(insns) > 0 {
		return "form:" + opKindName(insns[0].kind)
	}
	return "form:empty"
}

func recordFallback(report *nativeCoverageFixture, in insn, weight int) {
	kind := opKindName(in.kind)
	instruction := fmt.Sprintf("%s:%s:size%d", kind, operandForm(in), in.size)
	if in.opcode != 0 {
		instruction += fmt.Sprintf(":opcode0x%02x", in.opcode)
	}
	if in.kind == opX87 {
		instruction += fmt.Sprintf(":opcode0x%02x:group%d:rip0x%x", byte(in.imm), in.dst, in.rip)
	}
	report.FallbackOpKinds[kind]++
	report.WeightedFallbackOpKinds[kind] += weight
	report.FallbackInstructions[instruction]++
	report.WeightedFallbackInstructions[instruction] += weight
}

func addCoverageInstruction(report *nativeCoverageFixture, in insn, weight int) {
	name := opKindName(in.kind)
	report.OpKinds[name]++
	report.WeightedOpKinds[name] += weight
	report.OperandForms[operandForm(in)]++
	report.WeightedOperandForms[operandForm(in)] += weight
	report.DecodedInstructions++
	report.WeightedInstructions += weight
	categories := []struct {
		name string
		yes  bool
	}{
		{"x87", in.kind == opX87},
		{"mmx", in.kind == opMMX},
		{"rip_relative", in.useRIP},
		{"memory", hasMemoryOperand(in)},
		{"high_byte", usesHighByteForm(in)},
	}
	for _, category := range categories {
		if category.yes {
			report.Categories[category.name]++
			report.WeightedCategories[category.name] += weight
		}
	}
}

func operandForm(in insn) string {
	if in.kind == opPush || in.kind == opPop {
		return "stack"
	}
	if in.kind == opCall || in.kind == opJmp || in.kind == opJcc || in.kind == opRet {
		return "branch"
	}
	if hasMemoryOperand(in) {
		return "memory"
	}
	switch in.kind {
	case opMovRegImm, opALURegImm, opALUMemImm, opTestImm, opIMul3:
		return "immediate"
	case opX87, opMMX:
		return "vector_or_fp"
	default:
		return "register"
	}
}

func hasMemoryOperand(in insn) bool {
	switch in.kind {
	case opMovRegMem, opMovMemReg, opMovMemImm,
		opALURegMem, opALUMemReg, opALUMemImm, opLea:
		return true
	case opMovzx, opMovsx:
		return in.src < 0
	case opX87:
		return in.size != 1
	case opMMX:
		return in.opcode != 0x77 && in.size != 1
	default:
		return false
	}
}

func usesHighByteForm(in insn) bool {
	if in.size != 1 {
		return false
	}
	switch in.kind {
	case opMovRegImm, opMovRegReg, opMovRegMem, opMovMemReg, opMovMemImm,
		opALURegReg, opALURegImm, opALURegMem, opALUMemReg, opALUMemImm,
		opTest, opTestImm, opXchg, opMovzx, opMovsx, opSetcc,
		opShift, opNot, opNeg, opInc, opDec:
		return in.dst >= 4 && in.dst <= 7 || in.src >= 4 && in.src <= 7
	default:
		return false
	}
}

func opKindName(kind opKind) string {
	names := []string{"nop", "mov_reg_imm", "mov_reg_reg", "mov_reg_mem", "mov_mem_reg", "mov_mem_imm", "alu_reg_reg", "alu_reg_imm", "alu_reg_mem", "alu_mem_reg", "alu_mem_imm", "lea", "push", "pop", "call", "ret", "jmp", "jcc", "test", "test_imm", "xchg", "cdq", "movzx", "movsx", "setcc", "cmovcc", "imul", "imul3", "div", "idiv", "shift", "not", "neg", "inc", "dec", "x87", "mmx", "syscall", "vmcall", "end"}
	if int(kind) < len(names) {
		return names[kind]
	}
	return fmt.Sprintf("op_%d", kind)
}

func newCoverageFixture(name, mode string) nativeCoverageFixture {
	return nativeCoverageFixture{Name: name, Mode: mode, SeedCounts: map[string]int{}, OpKinds: map[string]int{}, WeightedOpKinds: map[string]int{}, OperandForms: map[string]int{}, WeightedOperandForms: map[string]int{}, FallbackOpKinds: map[string]int{}, WeightedFallbackOpKinds: map[string]int{}, FallbackInstructions: map[string]int{}, WeightedFallbackInstructions: map[string]int{}, CompilerRejections: map[string]int{}, WeightedCompilerRejections: map[string]int{}, Categories: map[string]int{}, WeightedCategories: map[string]int{}, PrefixHistogram: map[string]int{}, WeightedPrefixHistogram: map[string]int{}}
}

func mergeCoverageTotals(total *nativeCoverageTotals, f nativeCoverageFixture) {
	total.Starts += f.Starts
	total.WeightedStarts += f.WeightedStarts
	total.DecodedBlocks += f.DecodedBlocks
	total.WeightedDecodedBlocks += f.WeightedDecodedBlocks
	total.DecodedInstructions += f.DecodedInstructions
	total.WeightedInstructions += f.WeightedInstructions
	total.NativeWholeBlocks += f.NativeWholeBlocks
	total.WeightedWholeBlocks += f.WeightedWholeBlocks
	total.NativePrefixInstructions += f.NativePrefixInstructions
	total.WeightedPrefixInstructions += f.WeightedPrefixInstructions
	total.DecoderErrors += f.DecoderErrors
	total.WeightedDecoderErrors += f.WeightedDecoderErrors
	total.FirstOpEndRejections += f.FirstOpEndRejections
	total.WeightedFirstOpEndRejections += f.WeightedFirstOpEndRejections
	total.ArenaExhaustions += f.ArenaExhaustions
	total.WeightedArenaExhaustions += f.WeightedArenaExhaustions
	mergeMap(&total.OpKinds, f.OpKinds)
	mergeMap(&total.WeightedOpKinds, f.WeightedOpKinds)
	mergeMap(&total.OperandForms, f.OperandForms)
	mergeMap(&total.WeightedOperandForms, f.WeightedOperandForms)
	mergeMap(&total.FallbackOpKinds, f.FallbackOpKinds)
	mergeMap(&total.WeightedFallbackOpKinds, f.WeightedFallbackOpKinds)
	mergeMap(&total.FallbackInstructions, f.FallbackInstructions)
	mergeMap(&total.WeightedFallbackInstructions, f.WeightedFallbackInstructions)
	mergeMap(&total.CompilerRejections, f.CompilerRejections)
	mergeMap(&total.WeightedCompilerRejections, f.WeightedCompilerRejections)
	mergeMap(&total.Categories, f.Categories)
	mergeMap(&total.WeightedCategories, f.WeightedCategories)
	mergeMap(&total.PrefixHistogram, f.PrefixHistogram)
	mergeMap(&total.WeightedPrefixHistogram, f.WeightedPrefixHistogram)
}
func mergeMap(dst *map[string]int, src map[string]int) {
	if *dst == nil {
		*dst = map[string]int{}
	}
	for k, v := range src {
		(*dst)[k] += v
	}
}

func rankCoverageGaps(total nativeCoverageTotals) []nativeCoverageGap {
	result := []nativeCoverageGap{}
	weightedAvailable := total.WeightedInstructions != total.DecodedInstructions || total.WeightedStarts != total.Starts
	families := map[string]bool{}
	for family := range total.CompilerRejections {
		families[family] = true
	}
	for family := range total.WeightedCompilerRejections {
		families[family] = true
	}
	for family := range families {
		count, weighted := total.CompilerRejections[family], false
		if weightedAvailable && total.WeightedCompilerRejections[family] != count {
			count, weighted = total.WeightedCompilerRejections[family], true
		}
		kind := strings.TrimPrefix(family, "form:")
		kind = strings.TrimPrefix(kind, "memory_disabled:")
		instructions := total.OpKinds[kind]
		if weighted {
			instructions = total.WeightedOpKinds[kind]
		}
		result = append(result, nativeCoverageGap{OpKind: family, Fallbacks: count, Instructions: instructions, Family: family, Weighted: weighted})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Fallbacks != result[j].Fallbacks {
			return result[i].Fallbacks > result[j].Fallbacks
		}
		if result[i].Family != result[j].Family {
			return result[i].Family < result[j].Family
		}
		return result[i].OpKind < result[j].OpKind
	})
	if len(result) > 10 {
		result = result[:10]
	}
	return result
}

func compareNativeCoverage(current, baseline nativeCoverageReport, maxRegressionPP int) error {
	if maxRegressionPP < 0 {
		return fmt.Errorf("regression threshold must be nonnegative")
	}
	if err := validateCoverageCompatibility(current, baseline); err != nil {
		return err
	}
	byName := map[string]nativeCoverageFixture{}
	for _, f := range baseline.Fixtures {
		byName[f.Name] = f
	}
	for _, f := range current.Fixtures {
		b := byName[f.Name]
		pairs := []struct {
			name              string
			currentNumerator  int
			currentDenom      int
			baselineNumerator int
			baselineDenom     int
		}{
			{"raw", f.NativePrefixInstructions, f.DecodedInstructions, b.NativePrefixInstructions, b.DecodedInstructions},
			{"weighted", f.WeightedPrefixInstructions, f.WeightedInstructions, b.WeightedPrefixInstructions, b.WeightedInstructions},
		}
		for _, pair := range pairs {
			if pair.currentDenom == 0 || pair.baselineDenom == 0 {
				if pair.name == "weighted" && pair.currentDenom == 0 && pair.baselineDenom == 0 {
					continue
				}
				return fmt.Errorf("%s denominator is zero in %s: current=%d baseline=%d", pair.name, f.Name, pair.currentDenom, pair.baselineDenom)
			}
			currentRatio := ratioPP(pair.currentNumerator, pair.currentDenom)
			baselineRatio := ratioPP(pair.baselineNumerator, pair.baselineDenom)
			if currentRatio+maxRegressionPP*100 < baselineRatio {
				return fmt.Errorf("native prefix regression in %s: current %.2f%%, baseline %.2f%%, allowed %d pp", f.Name, float64(currentRatio)/100, float64(baselineRatio)/100, maxRegressionPP)
			}
		}
	}
	return nil
}

func validateCoverageCompatibility(current, baseline nativeCoverageReport) error {
	if current.Version != nativeCoverageVersion || baseline.Version != nativeCoverageVersion {
		return fmt.Errorf("incompatible coverage schema: current=%d baseline=%d want=%d", current.Version, baseline.Version, nativeCoverageVersion)
	}
	if current.CorpusID == "" || current.CorpusID != baseline.CorpusID ||
		current.ConfigHash != baseline.ConfigHash ||
		current.SamplingModel != baseline.SamplingModel ||
		current.SampleStride != baseline.SampleStride ||
		current.MaxStarts != baseline.MaxStarts ||
		current.HotnessModel != baseline.HotnessModel ||
		current.HotnessSource != baseline.HotnessSource ||
		current.HotnessClamp != baseline.HotnessClamp ||
		!equalStringMap(current.FixtureHashes, baseline.FixtureHashes) ||
		len(current.Fixtures) != len(baseline.Fixtures) {
		return errors.New("incompatible coverage baseline: corpus identity, fixture hashes, configuration, or sampling differs")
	}
	byName := map[string]nativeCoverageFixture{}
	for _, f := range baseline.Fixtures {
		byName[f.Name] = f
	}
	for _, f := range current.Fixtures {
		b, ok := byName[f.Name]
		if !ok {
			return fmt.Errorf("incompatible coverage baseline: missing fixture %q", f.Name)
		}
		if f.Mode != b.Mode || f.RealBinary != b.RealBinary || f.SamplingConfidence != b.SamplingConfidence || f.NativeMemoryCapability != b.NativeMemoryCapability || f.FixtureHash != b.FixtureHash {
			return fmt.Errorf("incompatible coverage baseline: fixture %q mode or hash differs", f.Name)
		}
		if err := validateRealFixture(f); err != nil {
			return fmt.Errorf("current report: %w", err)
		}
		if err := validateRealFixture(b); err != nil {
			return fmt.Errorf("baseline report: %w", err)
		}
	}
	return nil
}

func validateRealFixture(f nativeCoverageFixture) error {
	if !f.RealBinary {
		return nil
	}
	if !f.Usable || f.DecodedBlocks == 0 || f.DecodedInstructions == 0 {
		return fmt.Errorf("unusable real fixture %s: entry=0x%x rva=0x%x file_offset=0x%x bytes=%s decode=%s blocks=%d instructions=%d", f.Name, f.EntryVA, f.EntryRVA, f.EntryFileOffset, f.EntryBytes, f.EntryDecode, f.DecodedBlocks, f.DecodedInstructions)
	}
	return nil
}

func ratioPP(n, d int) int {
	if d <= 0 {
		return 0
	}
	return n * 10000 / d
}
func equalStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func formatNativeCoverageText(report nativeCoverageReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "native JIT coverage schema=%d corpus=%s sampler=%s\n", report.Version, report.CorpusID, report.SamplingModel)
	for _, f := range report.Fixtures {
		unverifiedStatic := f.SeedCounts["static_call_target"] + f.SeedCounts["static_branch_target"]
		fmt.Fprintf(&b, "%s mode=%s real=%t usable=%t confidence=%s unverified_static_starts=%d entry_va=0x%x entry_rva=0x%x file_offset=0x%x bytes=%s entry_decode=%s memory=%s raw_blocks=%d raw_prefix=%d/%d weighted_blocks=%d weighted_prefix=%d/%d decoder_errors=%d first_op_end=%d\n", f.Name, f.Mode, f.RealBinary, f.Usable, f.SamplingConfidence, unverifiedStatic, f.EntryVA, f.EntryRVA, f.EntryFileOffset, f.EntryBytes, f.EntryDecode, f.NativeMemoryCapability, f.DecodedBlocks, f.NativePrefixInstructions, f.DecodedInstructions, f.WeightedDecodedBlocks, f.WeightedPrefixInstructions, f.WeightedInstructions, f.DecoderErrors, f.FirstOpEndRejections)
	}
	for _, gap := range report.TopUnsupported {
		fmt.Fprintf(&b, "gap family=%s impact=%d frequency=%d weighted=%t\n", gap.Family, gap.Fallbacks, gap.Instructions, gap.Weighted)
	}
	return b.String()
}

func discoverStarts(in []coverageStart) []coverageStart {
	by := map[uint32]string{}
	for _, s := range in {
		if old, ok := by[s.rva]; !ok || coverageStartPriority(s.source) < coverageStartPriority(old) {
			by[s.rva] = s.source
		}
	}
	out := make([]coverageStart, 0, len(by))
	for rva, source := range by {
		out = append(out, coverageStart{rva, source})
	}
	sort.Slice(out, func(i, j int) bool {
		pi, pj := coverageStartPriority(out[i].source), coverageStartPriority(out[j].source)
		if pi != pj {
			return pi < pj
		}
		return out[i].rva < out[j].rva
	})
	return out
}

func coverageStartPriority(source string) int {
	switch source {
	case "entrypoint":
		return 0
	case "pdata":
		return 1
	case "coff_symbol":
		return 2
	case "static_call_target":
		return 3
	case "linear_sweep":
		return 4
	case "section_entry":
		return 5
	case "static_branch_target":
		return 6
	case "call_target":
		return 7
	case "branch_target":
		return 8
	case "fallthrough":
		return 9
	default:
		return 10
	}
}

func isStaticControlRecoverySource(source string) bool {
	return source == "static_call_target" || source == "static_branch_target"
}

func realInsnCount(insns []insn) int {
	for i, in := range insns {
		if in.kind == opEnd {
			return i
		}
	}
	return len(insns)
}

func decodedBlockSuccessors(insns []insn, base uint64) []coverageStart {
	count := realInsnCount(insns)
	if count == 0 {
		return nil
	}
	last := insns[count-1]
	result := []coverageStart{}
	if last.target >= base && last.target-base <= 0xffffffff {
		source := "branch_target"
		if last.kind == opCall {
			source = "call_target"
		}
		result = append(result, coverageStart{uint32(last.target - base), source})
	}
	if (last.kind == opCall || last.kind == opJcc) && last.nextRIP >= base && last.nextRIP-base <= 0xffffffff {
		result = append(result, coverageStart{uint32(last.nextRIP - base), "fallthrough"})
	}
	return result
}

func inSections(rva uint32, sections []coverageSection) bool {
	for _, s := range sections {
		if rva >= s.rva && rva < s.end {
			return true
		}
	}
	return false
}
func peEntryRVA(p *pe.File) uint32 {
	switch h := p.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return h.AddressOfEntryPoint
	case *pe.OptionalHeader64:
		return h.AddressOfEntryPoint
	}
	return 0
}

func peImageBase(p *pe.File) uint64 {
	switch h := p.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return uint64(h.ImageBase)
	case *pe.OptionalHeader64:
		return h.ImageBase
	default:
		return 0
	}
}

func peFileOffset(p *pe.File, rva uint32) uint32 {
	for _, section := range p.Sections {
		size := section.VirtualSize
		if section.Size > size {
			size = section.Size
		}
		if rva >= section.VirtualAddress && rva < section.VirtualAddress+size {
			return section.Offset + rva - section.VirtualAddress
		}
	}
	return 0
}

func pdataStarts(p *pe.File) []uint32 {
	var dir pe.DataDirectory
	switch h := p.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dir = h.DataDirectory[3]
	case *pe.OptionalHeader64:
		dir = h.DataDirectory[3]
	}
	if dir.VirtualAddress == 0 || dir.Size < 12 {
		return nil
	}
	for _, s := range p.Sections {
		if dir.VirtualAddress < s.VirtualAddress || dir.VirtualAddress >= s.VirtualAddress+uint32(s.Size) {
			continue
		}
		data, err := s.Data()
		if err != nil {
			return nil
		}
		off := dir.VirtualAddress - s.VirtualAddress
		out := []uint32{}
		for off+12 <= uint32(len(data)) && off < dir.VirtualAddress-s.VirtualAddress+dir.Size {
			begin := binary.LittleEndian.Uint32(data[off:])
			if begin != 0 {
				out = append(out, begin)
			}
			off += 12
		}
		return out
	}
	return nil
}

func staticControlTargetStarts(sections []coverageSection) []coverageStart {
	starts := []coverageStart{}
	addRelative := func(next uint32, rel int64, source string) {
		target := int64(next) + rel
		if target < 0 || target > 0xffffffff || !inSections(uint32(target), sections) {
			return
		}
		starts = append(starts, coverageStart{uint32(target), source})
	}
	for _, section := range sections {
		for offset := 0; offset < len(section.data); offset++ {
			op := section.data[offset]
			rva := section.rva + uint32(offset)
			switch {
			case (op == 0xe8 || op == 0xe9) && offset+5 <= len(section.data):
				source := "static_branch_target"
				if op == 0xe8 {
					source = "static_call_target"
				}
				addRelative(rva+5, int64(int32(binary.LittleEndian.Uint32(section.data[offset+1:]))), source)
			case (op == 0xeb || op >= 0x70 && op <= 0x7f) && offset+2 <= len(section.data):
				addRelative(rva+2, int64(int8(section.data[offset+1])), "static_branch_target")
			case op == 0x0f && offset+6 <= len(section.data) && section.data[offset+1] >= 0x80 && section.data[offset+1] <= 0x8f:
				addRelative(rva+6, int64(int32(binary.LittleEndian.Uint32(section.data[offset+2:]))), "static_branch_target")
			}
		}
	}
	return discoverStarts(starts)
}

func entryBytes(sections []coverageSection, rva uint32, count int) string {
	for _, section := range sections {
		if rva < section.rva || rva >= section.end {
			continue
		}
		offset := int(rva - section.rva)
		end := offset + count
		if end > len(section.data) {
			end = len(section.data)
		}
		return hex.EncodeToString(section.data[offset:end])
	}
	return ""
}

func entryDecodeStatus(cache *Cache, m *mmu.MMU, addr uint64) string {
	insns, _, err := cache.decode(addr)
	if err != nil {
		return "decoder_error:" + err.Error()
	}
	if len(insns) == 0 || insns[0].kind == opEnd {
		b, readErr := m.Read8(addr)
		if readErr != nil {
			return "op_end"
		}
		return fmt.Sprintf("op_end:byte_0x%02x:%s", b, decoderByteFamily(b))
	}
	return "decoded:" + opKindName(insns[0].kind)
}

func linearSweepStarts(cache *Cache, sections []coverageSection, base uint64) []coverageStart {
	result := []coverageStart{}
	for _, section := range sections {
		current := base + uint64(section.rva)
		end := base + uint64(section.end)
		for current < end {
			insns, _, err := cache.decode(current)
			if err != nil || len(insns) == 0 || insns[0].kind == opEnd {
				break
			}
			result = append(result, coverageStart{uint32(current - base), "linear_sweep"})
			count := realInsnCount(insns)
			if count == 0 || insns[count-1].nextRIP <= current || insns[count-1].nextRIP > end {
				break
			}
			current = insns[count-1].nextRIP
		}
	}
	return result
}

func recordDecoderError(report *nativeCoverageFixture, m *mmu.MMU, addr uint64, err error, weight int) {
	b, readErr := m.Read8(addr)
	key := "error"
	if readErr == nil {
		key = fmt.Sprintf("byte_0x%02x:%s", b, decoderByteFamily(b))
	}
	report.CompilerRejections["decoder:"+key]++
	report.WeightedCompilerRejections["decoder:"+key] += weight
	_ = err
}
func decoderByteFamily(b byte) string {
	switch {
	case b == 0x0f:
		return "escape_0f"
	case b == 0x26 || b == 0x2e || b == 0x36 || b == 0x3e || b == 0x64 || b == 0x65:
		return "segment_prefix"
	case b == 0x66 || b == 0x67:
		return "size_prefix"
	case b == 0xf0 || b == 0xf2 || b == 0xf3:
		return "lock_or_repeat_prefix"
	case b >= 0xd8 && b <= 0xdf:
		return "x87"
	case b >= 0x40 && b <= 0x4f:
		return "rex_or_inc_dec"
	default:
		return "primary"
	}
}

const maxHotnessWeight = 1000

func readHotness(path string) (coverageHotness, string, error) {
	if path == "" {
		return coverageHotness{}, "default:1", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read hotness %q: %w", path, err)
	}
	result := coverageHotness{}
	for lineNo, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if len(fields) != 3 {
			return nil, "", fmt.Errorf("hotness %q line %d: want FIXTURE ADDRESS COUNT", path, lineNo+1)
		}
		fixture := fields[0]
		addr, err := strconv.ParseUint(strings.TrimPrefix(fields[1], "0x"), 16, 64)
		if err != nil {
			return nil, "", fmt.Errorf("hotness %q line %d address: %w", path, lineNo+1, err)
		}
		count, err := strconv.Atoi(fields[2])
		if err != nil || count < 0 {
			return nil, "", fmt.Errorf("hotness %q line %d count must be nonnegative", path, lineNo+1)
		}
		if count > maxHotnessWeight {
			count = maxHotnessWeight
		}
		result[coverageHotnessKey{fixture, addr}] = count
	}
	sum := sha256.Sum256(data)
	return result, "sha256:" + hex.EncodeToString(sum[:]), nil
}
func weightFor(fixture string, addr, rva uint64, weights coverageHotness) int {
	if w, ok := weights[coverageHotnessKey{fixture, addr}]; ok {
		return w
	}
	if w, ok := weights[coverageHotnessKey{fixture, rva}]; ok {
		return w
	}
	return 1
}
func fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readSection(section *pe.Section) ([]byte, error) {
	if section == nil {
		return nil, errors.New("nil PE section")
	}
	return section.Data()
}
func coverageConfigHash(r nativeCoverageReport) string {
	h := sha256.New()
	fmt.Fprintf(h, "v=%d sampler=%s max=%d hot=%s clamp=%d", r.Version, r.SamplingModel, r.MaxStarts, r.HotnessSource, r.HotnessClamp)
	for _, fixture := range r.Fixtures {
		fmt.Fprintf(h, "|%s:%s:%s", fixture.Name, fixture.Mode, fixture.SamplingConfidence)
	}
	return hex.EncodeToString(h.Sum(nil))
}
func coverageCorpusID(r nativeCoverageReport) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%d|%d", r.ConfigHash, r.FixtureHashes["NPP"], r.MaxStarts, r.SampleStride)
	fmt.Fprintf(h, "|%s", r.FixtureHashes["DX-Ball"])
	return hex.EncodeToString(h.Sum(nil))
}
