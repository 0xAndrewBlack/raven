package compat

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type MatrixState string

const (
	StatePass       MatrixState = "pass"
	StateMismatch   MatrixState = "mismatch"
	StateCrash      MatrixState = "crash"
	StateHang       MatrixState = "hang"
	StateUnresolved MatrixState = "unresolved"
	StateSkipped    MatrixState = "skipped"
)

type MatrixInput struct {
	Target            string
	Scenario          string
	Report            Report
	TimedOut          bool
	Skipped           bool
	RequireAutomation bool
	ExpectedExitCode  *int64
}

type Matrix struct {
	Rows []MatrixRow `json:"rows"`
}

type MatrixRow struct {
	Target                  string              `json:"target"`
	Scenario                string              `json:"scenario"`
	State                   MatrixState         `json:"state"`
	Runs                    int                 `json:"runs"`
	Logs                    int                 `json:"logs"`
	Imports                 MatrixImportSummary `json:"imports"`
	InvokedStubCount        int                 `json:"invoked_stub_count"`
	CPUFaultCount           int                 `json:"cpu_fault_count"`
	RuntimeErrorCount       int                 `json:"runtime_error_count"`
	ExitProcessCodes        []int64             `json:"exit_process_codes"`
	AutomationCompleted     bool                `json:"automation_completed"`
	AutomationCompletedLogs int                 `json:"automation_completed_logs"`
}

type MatrixImportSummary struct {
	Resolved   int `json:"resolved"`
	Unresolved int `json:"unresolved"`
}

type matrixObservation struct {
	logs                int
	imports             MatrixImportSummary
	invokedStubs        int
	cpuFaults           int
	runtimeErrors       int
	exitCodes           []int64
	automationCompleted int
	successfulLogs      int
}

type matrixGroup struct {
	row        MatrixRow
	state      MatrixState
	signatures map[string]struct{}
}

type matrixKey struct {
	target   string
	scenario string
}

func BuildMatrix(inputs []MatrixInput) (Matrix, error) {
	if len(inputs) == 0 {
		return Matrix{}, fmt.Errorf("matrix has no inputs")
	}
	groups := make(map[matrixKey]*matrixGroup)
	scenarios := make(map[string][]*matrixGroup)

	for _, input := range inputs {
		if input.Target == "" {
			return Matrix{}, fmt.Errorf("matrix target is empty")
		}
		if input.Scenario == "" {
			return Matrix{}, fmt.Errorf("matrix scenario is empty")
		}

		key := matrixKey{target: input.Target, scenario: input.Scenario}
		group := groups[key]
		if group == nil {
			group = &matrixGroup{
				row: MatrixRow{
					Target:           input.Target,
					Scenario:         input.Scenario,
					ExitProcessCodes: []int64{},
				},
				state:      StateSkipped,
				signatures: make(map[string]struct{}),
			}
			groups[key] = group
			scenarios[input.Scenario] = append(scenarios[input.Scenario], group)
		}

		observation := observeReport(input.Report)
		state := classifyObservation(input, observation)
		group.state = mergeMatrixState(group.state, state)
		group.row.Runs++
		if state == StateSkipped {
			continue
		}
		group.row.Logs += observation.logs
		group.row.Imports.Resolved += observation.imports.Resolved
		group.row.Imports.Unresolved += observation.imports.Unresolved
		group.row.InvokedStubCount += observation.invokedStubs
		group.row.CPUFaultCount += observation.cpuFaults
		group.row.RuntimeErrorCount += observation.runtimeErrors
		group.row.ExitProcessCodes = append(group.row.ExitProcessCodes, observation.exitCodes...)
		group.row.AutomationCompletedLogs += observation.automationCompleted
		group.signatures[observation.signature()] = struct{}{}
	}

	for _, scenarioGroups := range scenarios {
		compareScenarioGroups(scenarioGroups)
	}

	matrix := Matrix{Rows: make([]MatrixRow, 0, len(groups))}
	for _, group := range groups {
		sort.Slice(group.row.ExitProcessCodes, func(i, j int) bool {
			return group.row.ExitProcessCodes[i] < group.row.ExitProcessCodes[j]
		})
		group.row.AutomationCompleted = group.row.Logs > 0 &&
			group.row.AutomationCompletedLogs == group.row.Logs
		group.row.State = group.state
		matrix.Rows = append(matrix.Rows, group.row)
	}
	sort.Slice(matrix.Rows, func(i, j int) bool {
		if matrix.Rows[i].Target != matrix.Rows[j].Target {
			return matrix.Rows[i].Target < matrix.Rows[j].Target
		}
		return matrix.Rows[i].Scenario < matrix.Rows[j].Scenario
	})
	return matrix, nil
}

func observeReport(report Report) matrixObservation {
	observation := matrixObservation{exitCodes: []int64{}}
	for _, log := range report.Logs {
		observation.logs++
		observation.imports.Resolved += log.Imports.Resolved
		observation.imports.Unresolved += log.Imports.Unresolved
		for _, call := range log.Calls {
			if call.Kind == "auto_stub" || call.Kind == "unimplemented" {
				observation.invokedStubs += call.Count
			}
		}
		observation.cpuFaults += log.CPUFaults.Count
		observation.runtimeErrors += log.RuntimeErrors.Count
		if log.ExitProcessCode != nil {
			observation.exitCodes = append(observation.exitCodes, *log.ExitProcessCode)
		}
		if log.AutomationCompleted {
			observation.automationCompleted++
		}
		if log.ExitProcessCode != nil || log.AutomationCompleted {
			observation.successfulLogs++
		}
	}
	sort.Slice(observation.exitCodes, func(i, j int) bool {
		return observation.exitCodes[i] < observation.exitCodes[j]
	})
	return observation
}

func classifyObservation(input MatrixInput, observation matrixObservation) MatrixState {
	if input.Skipped {
		return StateSkipped
	}
	if observation.cpuFaults > 0 || observation.runtimeErrors > 0 {
		return StateCrash
	}
	if input.TimedOut {
		return StateHang
	}
	if observation.logs == 0 {
		return StateSkipped
	}
	if observation.imports.Unresolved > 0 {
		return StateUnresolved
	}
	if observation.invokedStubs > 0 {
		return StateMismatch
	}

	if input.ExpectedExitCode != nil {
		if len(observation.exitCodes) != observation.logs {
			return StateMismatch
		}
		for _, code := range observation.exitCodes {
			if code != *input.ExpectedExitCode {
				return StateMismatch
			}
		}
	}
	if input.RequireAutomation && observation.automationCompleted < observation.logs {
		if len(observation.exitCodes) == 0 {
			return StateHang
		}
		return StateMismatch
	}
	if observation.successfulLogs < observation.logs {
		return StateMismatch
	}
	return StatePass
}

func mergeMatrixState(current, next MatrixState) MatrixState {
	if matrixStatePriority(next) > matrixStatePriority(current) {
		return next
	}
	return current
}

func matrixStatePriority(state MatrixState) int {
	switch state {
	case StateCrash:
		return 5
	case StateHang:
		return 4
	case StateUnresolved:
		return 3
	case StateMismatch:
		return 2
	case StatePass:
		return 1
	default:
		return 0
	}
}

func compareScenarioGroups(groups []*matrixGroup) {
	var reference string
	hasReference := false
	mismatch := false

	for _, group := range groups {
		if len(group.signatures) != 1 {
			if len(group.signatures) > 1 {
				mismatch = true
			}
			continue
		}
		for signature := range group.signatures {
			if !hasReference {
				reference = signature
				hasReference = true
			} else if signature != reference {
				mismatch = true
			}
		}
	}
	if !mismatch {
		return
	}
	for _, group := range groups {
		if group.state == StatePass {
			group.state = StateMismatch
		}
	}
}

func (observation matrixObservation) signature() string {
	codes := make([]string, 0, len(observation.exitCodes))
	for i, code := range observation.exitCodes {
		if i != 0 && code == observation.exitCodes[i-1] {
			continue
		}
		codes = append(codes, strconv.FormatInt(code, 10))
	}
	return fmt.Sprintf(
		"%d/%d/%d/%d/%s/%t",
		observation.imports.Unresolved,
		observation.invokedStubs,
		observation.cpuFaults,
		observation.runtimeErrors,
		strings.Join(codes, ","),
		observation.logs > 0 && observation.automationCompleted == observation.logs,
	)
}
