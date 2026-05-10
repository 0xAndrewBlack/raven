package compat

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseLog(t *testing.T) {
	input := strings.Join([]string{
		"[resolve] notepad++.exe: 10 imports, 9 resolved, 1 unresolved, exports=3",
		"[resolve] plugin.dll: 4 delay-imports, 2 resolved, 2 unresolved",
		"[resolve] UNRESOLVED: shell32.dll!MissingCall (ord=0) for notepad++.exe IAT=0x1000",
		"[resolve] DLL NOT FOUND: absent.dll (for plugin.dll)",
		"[MISSING] auto-synth!shell32.dll!SHGetStockIconInfo (id=0x208E)",
		"[MISSING] auto-synth!shell32.dll!SHGetStockIconInfo (id=0x208E)",
		"[ntapi] UNIMPLEMENTED: user32.dll!RawInput (id=0x2001)",
		"[cpu-fault] #1 RIP=0x140001000 err=unimplemented opcode",
		"govm: PE runtime error: execution stopped",
		"[win32] ExitProcess(7)",
		"[auto] script complete",
	}, "\n")

	summary, err := ParseLog("npp.log", strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if summary.SourceLog != "npp.log" {
		t.Fatalf("SourceLog = %q", summary.SourceLog)
	}
	if summary.Imports.Resolved != 11 || summary.Imports.Unresolved != 3 {
		t.Fatalf("Imports = %+v", summary.Imports)
	}
	if len(summary.Imports.Observations) != 2 {
		t.Fatalf("Import observations = %+v", summary.Imports.Observations)
	}
	if got := strings.Join(summary.Imports.Details, ","); got != "absent.dll,shell32.dll!MissingCall" {
		t.Fatalf("Import details = %q", got)
	}
	if len(summary.Calls) != 2 ||
		summary.Calls[0] != (CallSummary{Kind: "auto_stub", Name: "shell32.dll!SHGetStockIconInfo", Count: 2}) ||
		summary.Calls[1] != (CallSummary{Kind: "unimplemented", Name: "user32.dll!RawInput", Count: 1}) {
		t.Fatalf("Calls = %+v", summary.Calls)
	}
	if summary.CPUFaults.Count != 1 || len(summary.CPUFaults.Messages) != 1 {
		t.Fatalf("CPUFaults = %+v", summary.CPUFaults)
	}
	if summary.RuntimeErrors.Count != 1 || len(summary.RuntimeErrors.Messages) != 1 {
		t.Fatalf("RuntimeErrors = %+v", summary.RuntimeErrors)
	}
	if summary.ExitProcessCode == nil || *summary.ExitProcessCode != 7 {
		t.Fatalf("ExitProcessCode = %v", summary.ExitProcessCode)
	}
	if !summary.AutomationCompleted {
		t.Fatal("AutomationCompleted = false")
	}
}

func TestParseLogAggregatesAndSorts(t *testing.T) {
	input := strings.Join([]string{
		"[resolve] z.dll: 1 imports, 1 resolved, 0 unresolved, exports=0",
		"[resolve] a.dll: 2 imports, 1 resolved, 1 unresolved, exports=0",
		"[resolve] a.dll: 2 imports, 1 resolved, 1 unresolved, exports=0",
		"[ntapi] UNIMPLEMENTED: z.dll!Call (id=0x2002)",
		"[MISSING] auto-synth!a.dll!Call (id=0x2001)",
		"[cpu-fault] repeated",
		"[cpu-fault] repeated",
		"[win32] ExitProcess(1)",
		"[win32] ExitProcess(0)",
	}, "\n")

	summary, err := ParseLog("run.log", strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if summary.Imports.Resolved != 3 || summary.Imports.Unresolved != 2 {
		t.Fatalf("Imports = %+v", summary.Imports)
	}
	if len(summary.Imports.Observations) != 2 ||
		summary.Imports.Observations[0].Module != "a.dll" ||
		summary.Imports.Observations[0].Occurrences != 2 {
		t.Fatalf("Import observations = %+v", summary.Imports.Observations)
	}
	if summary.CPUFaults.Count != 2 || len(summary.CPUFaults.Messages) != 1 {
		t.Fatalf("CPUFaults = %+v", summary.CPUFaults)
	}
	if summary.ExitProcessCode == nil || *summary.ExitProcessCode != 0 {
		t.Fatalf("ExitProcessCode = %v", summary.ExitProcessCode)
	}
}

func TestParseLogRecognizesRuntimeFailures(t *testing.T) {
	input := strings.Join([]string{
		"panic: invalid memory address",
		"fatal error: concurrent map writes",
		"govm: runtime error: unsupported binary",
		"[cpu-recover] #1 call to unmapped 0x1234",
		"[govm] thread 7 crashed: access violation (PC=0x10 SP=0x20 TLS=0x30)",
	}, "\n")

	summary, err := ParseLog("failure.log", strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if summary.RuntimeErrors.Count != 3 || len(summary.RuntimeErrors.Messages) != 3 {
		t.Fatalf("RuntimeErrors = %+v", summary.RuntimeErrors)
	}
	if summary.CPUFaults.Count != 2 || len(summary.CPUFaults.Messages) != 2 {
		t.Fatalf("CPUFaults = %+v", summary.CPUFaults)
	}
}

func TestParseFilesProducesDeterministicJSON(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "a.log")
	second := filepath.Join(dir, "b.log")
	if err := os.WriteFile(first, []byte("[auto] script complete\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("[win32] ExitProcess(0)\n"), 0644); err != nil {
		t.Fatal(err)
	}

	report, err := ParseFiles([]string{second, first})
	if err != nil {
		t.Fatal(err)
	}
	if report.Logs[0].SourceLog != first || report.Logs[1].SourceLog != second {
		t.Fatalf("Logs = %+v", report.Logs)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"observations", "details", "calls", "messages"} {
		if strings.Contains(string(data), `"`+field+`":null`) {
			t.Fatalf("JSON contains null %s: %s", field, data)
		}
	}
}
