package compat

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestBuildMatrixAggregatesAndSorts(t *testing.T) {
	exitZero := int64(0)
	first := MatrixInput{
		Target:   "wine",
		Scenario: "npp/open",
		Report: reportWithLog(LogSummary{
			Imports:             ImportSummary{Resolved: 5},
			Calls:               []CallSummary{{Kind: "auto_stub", Count: 2}},
			ExitProcessCode:     &exitZero,
			AutomationCompleted: true,
		}),
	}
	second := MatrixInput{
		Target:   "raven",
		Scenario: "npp/open",
		Report: reportWithLog(LogSummary{
			Imports:             ImportSummary{Resolved: 5},
			ExitProcessCode:     &exitZero,
			AutomationCompleted: true,
		}),
	}
	third := MatrixInput{
		Target:   "raven",
		Scenario: "npp/open",
		Report: reportWithLog(LogSummary{
			Imports:             ImportSummary{Resolved: 5},
			ExitProcessCode:     &exitZero,
			AutomationCompleted: true,
		}),
	}

	matrix, err := BuildMatrix([]MatrixInput{first, second, third})
	if err != nil {
		t.Fatal(err)
	}
	if len(matrix.Rows) != 2 {
		t.Fatalf("Rows = %+v", matrix.Rows)
	}
	raven := matrix.Rows[0]
	if raven.Target != "raven" || raven.Scenario != "npp/open" {
		t.Fatalf("First row = %+v", raven)
	}
	if raven.State != StateMismatch || raven.Runs != 2 || raven.Logs != 2 {
		t.Fatalf("Raven state/runs = %+v", raven)
	}
	if raven.Imports != (MatrixImportSummary{Resolved: 10}) {
		t.Fatalf("Raven imports = %+v", raven.Imports)
	}
	if !raven.AutomationCompleted || raven.AutomationCompletedLogs != 2 {
		t.Fatalf("Raven automation = %+v", raven)
	}
	if !reflect.DeepEqual(raven.ExitProcessCodes, []int64{0, 0}) {
		t.Fatalf("Raven exit codes = %v", raven.ExitProcessCodes)
	}
	wine := matrix.Rows[1]
	if wine.State != StateMismatch || wine.InvokedStubCount != 2 {
		t.Fatalf("Wine row = %+v", wine)
	}
}

func TestBuildMatrixStates(t *testing.T) {
	exitZero := int64(0)
	tests := []struct {
		name  string
		input MatrixInput
		want  MatrixState
	}{
		{
			name: "pass",
			input: MatrixInput{
				Report: reportWithLog(LogSummary{ExitProcessCode: &exitZero, AutomationCompleted: true}),
			},
			want: StatePass,
		},
		{
			name: "mismatch",
			input: MatrixInput{
				Report: reportWithLog(LogSummary{Calls: []CallSummary{{Kind: "unimplemented", Count: 1}}}),
			},
			want: StateMismatch,
		},
		{
			name:  "truncated log",
			input: MatrixInput{Report: reportWithLog(LogSummary{})},
			want:  StateMismatch,
		},
		{
			name: "crash",
			input: MatrixInput{
				Report: reportWithLog(LogSummary{RuntimeErrors: IssueSummary{Count: 1}}),
			},
			want: StateCrash,
		},
		{
			name:  "hang",
			input: MatrixInput{TimedOut: true},
			want:  StateHang,
		},
		{
			name: "unresolved",
			input: MatrixInput{
				Report: reportWithLog(LogSummary{Imports: ImportSummary{Unresolved: 1}}),
			},
			want: StateUnresolved,
		},
		{
			name:  "skipped",
			input: MatrixInput{Skipped: true},
			want:  StateSkipped,
		},
		{
			name:  "empty report",
			input: MatrixInput{},
			want:  StateSkipped,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.input.Target = "raven"
			test.input.Scenario = test.name
			matrix, err := BuildMatrix([]MatrixInput{test.input})
			if err != nil {
				t.Fatal(err)
			}
			if got := matrix.Rows[0].State; got != test.want {
				t.Fatalf("State = %q, want %q", got, test.want)
			}
		})
	}
}

func TestBuildMatrixAutomationRequirement(t *testing.T) {
	exitZero := int64(0)
	matrix, err := BuildMatrix([]MatrixInput{
		{
			Target:            "raven",
			Scenario:          "no-exit",
			Report:            reportWithLog(LogSummary{}),
			RequireAutomation: true,
		},
		{
			Target:            "raven",
			Scenario:          "exited",
			Report:            reportWithLog(LogSummary{ExitProcessCode: &exitZero}),
			RequireAutomation: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if matrix.Rows[0].Scenario != "exited" || matrix.Rows[0].State != StateMismatch {
		t.Fatalf("Exited row = %+v", matrix.Rows[0])
	}
	if matrix.Rows[1].Scenario != "no-exit" || matrix.Rows[1].State != StateHang {
		t.Fatalf("No-exit row = %+v", matrix.Rows[1])
	}
}

func TestBuildMatrixIgnoresSkippedReportsWhenComparingTargets(t *testing.T) {
	matrix, err := BuildMatrix([]MatrixInput{
		{Target: "raven", Scenario: "npp/open"},
		{Target: "wine", Scenario: "npp/open", Report: reportWithLog(LogSummary{AutomationCompleted: true})},
	})
	if err != nil {
		t.Fatal(err)
	}
	if matrix.Rows[0].State != StateSkipped {
		t.Fatalf("Raven state = %q", matrix.Rows[0].State)
	}
	if matrix.Rows[1].State != StatePass {
		t.Fatalf("Wine state = %q", matrix.Rows[1].State)
	}
}

func TestBuildMatrixDoesNotAggregateSkippedReportData(t *testing.T) {
	exitZero := int64(0)
	exitSeven := int64(7)
	matrix, err := BuildMatrix([]MatrixInput{
		{
			Target:   "raven",
			Scenario: "open",
			Report:   reportWithLog(LogSummary{ExitProcessCode: &exitZero, AutomationCompleted: true}),
		},
		{
			Target:   "raven",
			Scenario: "open",
			Skipped:  true,
			Report: reportWithLog(LogSummary{
				Imports:         ImportSummary{Unresolved: 3},
				RuntimeErrors:   IssueSummary{Count: 2},
				ExitProcessCode: &exitSeven,
			}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	row := matrix.Rows[0]
	if row.State != StatePass || row.Runs != 2 || row.Logs != 1 {
		t.Fatalf("Row = %+v", row)
	}
	if !reflect.DeepEqual(row.ExitProcessCodes, []int64{0}) {
		t.Fatalf("Exit codes = %v", row.ExitProcessCodes)
	}
	if row.Imports.Unresolved != 0 || row.RuntimeErrorCount != 0 {
		t.Fatalf("Skipped data was aggregated: %+v", row)
	}
}

func TestBuildMatrixRequiresExpectedExitInEveryLog(t *testing.T) {
	exitZero := int64(0)
	matrix, err := BuildMatrix([]MatrixInput{{
		Target:           "raven",
		Scenario:         "fixture",
		ExpectedExitCode: &exitZero,
		Report: Report{Logs: []LogSummary{
			{ExitProcessCode: &exitZero},
			{},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if matrix.Rows[0].State != StateMismatch {
		t.Fatalf("State = %q, want %q", matrix.Rows[0].State, StateMismatch)
	}
}

func TestBuildMatrixCrossTargetComparisonIgnoresResolvedImportAndLogCounts(t *testing.T) {
	exitZero := int64(0)
	matrix, err := BuildMatrix([]MatrixInput{
		{
			Target:   "raven",
			Scenario: "open",
			Report: Report{Logs: []LogSummary{
				{Imports: ImportSummary{Resolved: 50}, ExitProcessCode: &exitZero, AutomationCompleted: true},
				{Imports: ImportSummary{Resolved: 50}, ExitProcessCode: &exitZero, AutomationCompleted: true},
			}},
		},
		{
			Target:   "wine",
			Scenario: "open",
			Report: reportWithLog(LogSummary{
				Imports:             ImportSummary{Resolved: 1},
				ExitProcessCode:     &exitZero,
				AutomationCompleted: true,
			}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range matrix.Rows {
		if row.State != StatePass {
			t.Fatalf("%s state = %q, want %q", row.Target, row.State, StatePass)
		}
	}
}

func TestBuildMatrixIsDeterministic(t *testing.T) {
	inputs := []MatrixInput{
		{Target: "wine", Scenario: "b", Report: reportWithLog(LogSummary{})},
		{Target: "raven", Scenario: "a", Report: reportWithLog(LogSummary{})},
	}
	forward, err := BuildMatrix(inputs)
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := BuildMatrix([]MatrixInput{inputs[1], inputs[0]})
	if err != nil {
		t.Fatal(err)
	}
	forwardJSON, err := json.Marshal(forward)
	if err != nil {
		t.Fatal(err)
	}
	reverseJSON, err := json.Marshal(reverse)
	if err != nil {
		t.Fatal(err)
	}
	if string(forwardJSON) != string(reverseJSON) {
		t.Fatalf("Forward = %s\nReverse = %s", forwardJSON, reverseJSON)
	}
}

func TestBuildMatrixValidatesMetadata(t *testing.T) {
	if _, err := BuildMatrix(nil); err == nil {
		t.Fatal("empty input accepted")
	}
	if _, err := BuildMatrix([]MatrixInput{{Scenario: "npp/open"}}); err == nil {
		t.Fatal("empty target accepted")
	}
	if _, err := BuildMatrix([]MatrixInput{{Target: "raven"}}); err == nil {
		t.Fatal("empty scenario accepted")
	}
}

func reportWithLog(log LogSummary) Report {
	return Report{Logs: []LogSummary{log}}
}
