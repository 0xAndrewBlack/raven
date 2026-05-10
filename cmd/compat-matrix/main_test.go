package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mirkobrombin/Raven/internal/compat"
)

func TestRunPositionalExpectedExitIsOptIn(t *testing.T) {
	reportPath := writeReport(t, "exit.json", `{
		"logs": [{
			"source_log": "fixture.log",
			"imports": {"resolved": 1, "unresolved": 0, "observations": [], "details": []},
			"calls": [],
			"cpu_faults": {"count": 0, "messages": []},
			"runtime_errors": {"count": 0, "messages": []},
			"exit_process_code": 7,
			"automation_completed": false
		}]
	}`)

	matrix := runMatrix(t, "-target", "raven", "-scenario", "fixture/exit", reportPath)
	assertRowState(t, matrix, compat.StatePass)
}

func TestRunPositionalExpectedExitIsEnforced(t *testing.T) {
	reportPath := writeReport(t, "exit.json", `{
		"logs": [{
			"source_log": "fixture.log",
			"imports": {"resolved": 1, "unresolved": 0, "observations": [], "details": []},
			"calls": [],
			"cpu_faults": {"count": 0, "messages": []},
			"runtime_errors": {"count": 0, "messages": []},
			"exit_process_code": 7,
			"automation_completed": false
		}]
	}`)

	tests := []struct {
		name string
		code string
		want compat.MatrixState
	}{
		{name: "matching", code: "7", want: compat.StatePass},
		{name: "different", code: "0", want: compat.StateMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matrix := runMatrix(
				t,
				"-target", "raven",
				"-scenario", "fixture/exit",
				"-expected-exit", test.code,
				reportPath,
			)
			assertRowState(t, matrix, test.want)
		})
	}
}

func TestRunAutomationOnlyGUIReportPasses(t *testing.T) {
	reportPath := writeReport(t, "gui.json", `{
		"logs": [{
			"source_log": "gui.log",
			"imports": {"resolved": 42, "unresolved": 0, "observations": [], "details": []},
			"calls": [],
			"cpu_faults": {"count": 0, "messages": []},
			"runtime_errors": {"count": 0, "messages": []},
			"exit_process_code": null,
			"automation_completed": true
		}]
	}`)

	matrix := runMatrix(
		t,
		"-target", "raven",
		"-scenario", "npp/open",
		"-require-automation",
		reportPath,
	)
	assertRowState(t, matrix, compat.StatePass)
}

func TestRunTruncatedReportDoesNotPass(t *testing.T) {
	tests := []struct {
		name   string
		report string
	}{
		{
			name: "log without success marker",
			report: `{
				"logs": [{
					"source_log": "truncated.log",
					"imports": {"resolved": 42, "unresolved": 0, "observations": [], "details": []},
					"calls": [],
					"cpu_faults": {"count": 0, "messages": []},
					"runtime_errors": {"count": 0, "messages": []},
					"exit_process_code": null,
					"automation_completed": false
				}]
			}`,
		},
		{name: "no logs", report: `{"logs":[]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reportPath := writeReport(t, "truncated.json", test.report)
			matrix := runMatrix(t, "-target", "raven", "-scenario", "npp/open", reportPath)
			if got := matrix.Rows[0].State; got == compat.StatePass {
				t.Fatalf("truncated report state = %q, want non-pass", got)
			}
		})
	}
}

func TestRunManifestResolvesRelativeReportPaths(t *testing.T) {
	dir := t.TempDir()
	reportDir := filepath.Join(dir, "reports")
	if err := os.Mkdir(reportDir, 0o755); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(reportDir, "open.json")
	writeFile(t, reportPath, `{
		"logs": [{
			"source_log": "open.log",
			"imports": {"resolved": 2, "unresolved": 0, "observations": [], "details": []},
			"calls": [],
			"cpu_faults": {"count": 0, "messages": []},
			"runtime_errors": {"count": 0, "messages": []},
			"exit_process_code": null,
			"automation_completed": true
		}]
	}`)
	manifestPath := filepath.Join(dir, "manifest.json")
	writeFile(t, manifestPath, `{
		"runs": [{
			"target": "raven",
			"scenario": "npp/open",
			"report": "reports/open.json",
			"require_automation": true
		}]
	}`)

	matrix := runMatrix(t, "-manifest", manifestPath)
	assertRowState(t, matrix, compat.StatePass)
}

func TestRunRejectsMalformedOrExtraJSON(t *testing.T) {
	tests := []struct {
		name     string
		manifest string
		report   string
	}{
		{
			name:     "malformed report",
			manifest: `{"runs":[{"target":"raven","scenario":"open","report":"report.json"}]}`,
			report:   `{"logs":[`,
		},
		{
			name:     "unknown manifest field",
			manifest: `{"runs":[],"unexpected":true}`,
			report:   `{"logs":[]}`,
		},
		{
			name:     "unknown report field",
			manifest: `{"runs":[{"target":"raven","scenario":"open","report":"report.json"}]}`,
			report:   `{"logs":[],"unexpected":true}`,
		},
		{
			name:     "multiple report values",
			manifest: `{"runs":[{"target":"raven","scenario":"open","report":"report.json"}]}`,
			report:   `{"logs":[]} {"logs":[]}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			manifestPath := filepath.Join(dir, "manifest.json")
			writeFile(t, manifestPath, test.manifest)
			writeFile(t, filepath.Join(dir, "report.json"), test.report)

			var stdout, stderr bytes.Buffer
			if err := run([]string{"-manifest", manifestPath}, &stdout, &stderr); err == nil {
				t.Fatalf("run accepted invalid JSON; output = %s", stdout.String())
			}
		})
	}
}

func TestRunProducesDeterministicJSON(t *testing.T) {
	first := writeReport(t, "first.json", `{
		"logs": [{
			"source_log": "first.log",
			"imports": {"resolved": 1, "unresolved": 0, "observations": [], "details": []},
			"calls": [],
			"cpu_faults": {"count": 0, "messages": []},
			"runtime_errors": {"count": 0, "messages": []},
			"exit_process_code": 0,
			"automation_completed": true
		}]
	}`)
	second := writeReport(t, "second.json", `{
		"logs": [{
			"source_log": "second.log",
			"imports": {"resolved": 2, "unresolved": 0, "observations": [], "details": []},
			"calls": [],
			"cpu_faults": {"count": 0, "messages": []},
			"runtime_errors": {"count": 0, "messages": []},
			"exit_process_code": 0,
			"automation_completed": true
		}]
	}`)

	dir := t.TempDir()
	forwardManifest := filepath.Join(dir, "forward.json")
	reverseManifest := filepath.Join(dir, "reverse.json")
	writeFile(t, forwardManifest, `{
		"runs": [
			{"target":"wine","scenario":"fixture/b","report":"`+first+`"},
			{"target":"raven","scenario":"fixture/a","report":"`+second+`"}
		]
	}`)
	writeFile(t, reverseManifest, `{
		"runs": [
			{"target":"raven","scenario":"fixture/a","report":"`+second+`"},
			{"target":"wine","scenario":"fixture/b","report":"`+first+`"}
		]
	}`)

	forward := runMatrixJSON(t, "-manifest", forwardManifest)
	reverse := runMatrixJSON(t, "-manifest", reverseManifest)
	if forward != reverse {
		t.Fatalf("JSON depends on manifest order:\nforward:\n%s\nreverse:\n%s", forward, reverse)
	}
}

func runMatrix(t *testing.T, args ...string) compat.Matrix {
	t.Helper()
	output := runMatrixJSON(t, args...)
	var matrix compat.Matrix
	if err := json.Unmarshal([]byte(output), &matrix); err != nil {
		t.Fatalf("decode matrix: %v\noutput:\n%s", err, output)
	}
	return matrix
}

func runMatrixJSON(t *testing.T, args ...string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatalf("run(%q): %v\nstderr:\n%s", args, err, stderr.String())
	}
	return stdout.String()
}

func assertRowState(t *testing.T, matrix compat.Matrix, want compat.MatrixState) {
	t.Helper()
	if len(matrix.Rows) != 1 {
		t.Fatalf("rows = %d, want 1: %+v", len(matrix.Rows), matrix.Rows)
	}
	if got := matrix.Rows[0].State; got != want {
		t.Fatalf("state = %q, want %q: %+v", got, want, matrix.Rows[0])
	}
}

func writeReport(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	writeFile(t, path, content)
	return path
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.TrimSpace(content)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}
