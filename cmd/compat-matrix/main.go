package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/mirkobrombin/Raven/internal/compat"
)

type manifest struct {
	Runs []manifestRun `json:"runs"`
}

type manifestRun struct {
	Target            string `json:"target"`
	Scenario          string `json:"scenario"`
	Report            string `json:"report"`
	TimedOut          bool   `json:"timed_out,omitempty"`
	Skipped           bool   `json:"skipped,omitempty"`
	RequireAutomation bool   `json:"require_automation,omitempty"`
	ExpectedExitCode  *int64 `json:"expected_exit_code,omitempty"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "compat-matrix: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("compat-matrix", flag.ContinueOnError)
	flags.SetOutput(stderr)
	target := flags.String("target", "", "target name for positional reports")
	scenario := flags.String("scenario", "", "scenario name for positional reports")
	manifestPath := flags.String("manifest", "", "JSON manifest containing report metadata")
	timedOut := flags.Bool("timed-out", false, "mark positional reports as timed out")
	skipped := flags.Bool("skipped", false, "mark positional reports as skipped")
	requireAutomation := flags.Bool("require-automation", false, "require automation completion")
	expectedExit := flags.Int64("expected-exit", 0, "expected ExitProcess code")
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "Usage:")
		fmt.Fprintln(flags.Output(), "  compat-matrix -target TARGET -scenario SCENARIO [flags] report.json...")
		fmt.Fprintln(flags.Output(), "  compat-matrix -manifest manifest.json")
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *timedOut && *skipped {
		return errors.New("-timed-out and -skipped cannot be combined")
	}
	var expectedExitCode *int64
	flags.Visit(func(value *flag.Flag) {
		if value.Name == "expected-exit" {
			code := *expectedExit
			expectedExitCode = &code
		}
	})

	var inputs []compat.MatrixInput
	var err error
	if *manifestPath != "" {
		if flags.NArg() != 0 {
			return errors.New("manifest mode does not accept positional reports")
		}
		inputs, err = loadManifest(*manifestPath)
	} else {
		if flags.NArg() == 0 {
			flags.Usage()
			return errors.New("no OBS reports supplied")
		}
		if *target == "" || *scenario == "" {
			return errors.New("-target and -scenario are required")
		}
		inputs, err = loadReports(flags.Args(), func(report compat.Report) compat.MatrixInput {
			return compat.MatrixInput{
				Target:            *target,
				Scenario:          *scenario,
				Report:            report,
				TimedOut:          *timedOut,
				Skipped:           *skipped,
				RequireAutomation: *requireAutomation,
				ExpectedExitCode:  expectedExitCode,
			}
		})
	}
	if err != nil {
		return err
	}

	matrix, err := compat.BuildMatrix(inputs)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(matrix)
}

func loadManifest(path string) ([]compat.MatrixInput, error) {
	var value manifest
	if err := decodeJSONFile(path, &value); err != nil {
		return nil, err
	}
	base := filepath.Dir(path)
	inputs := make([]compat.MatrixInput, 0, len(value.Runs))
	for i, run := range value.Runs {
		if run.TimedOut && run.Skipped {
			return nil, fmt.Errorf("%s: run %d is both timed out and skipped", path, i)
		}
		if run.Report == "" {
			if !run.Skipped && !run.TimedOut {
				return nil, fmt.Errorf("%s: run %d has no report", path, i)
			}
			inputs = append(inputs, compat.MatrixInput{
				Target:            run.Target,
				Scenario:          run.Scenario,
				Skipped:           run.Skipped,
				TimedOut:          run.TimedOut,
				RequireAutomation: run.RequireAutomation,
				ExpectedExitCode:  run.ExpectedExitCode,
			})
			continue
		}
		reportPath := run.Report
		if !filepath.IsAbs(reportPath) {
			reportPath = filepath.Join(base, reportPath)
		}
		var report compat.Report
		if err := decodeJSONFile(reportPath, &report); err != nil {
			return nil, err
		}
		inputs = append(inputs, compat.MatrixInput{
			Target:            run.Target,
			Scenario:          run.Scenario,
			Report:            report,
			TimedOut:          run.TimedOut,
			Skipped:           run.Skipped,
			RequireAutomation: run.RequireAutomation,
			ExpectedExitCode:  run.ExpectedExitCode,
		})
	}
	return inputs, nil
}

func loadReports(paths []string, input func(compat.Report) compat.MatrixInput) ([]compat.MatrixInput, error) {
	inputs := make([]compat.MatrixInput, 0, len(paths))
	for _, path := range paths {
		var report compat.Report
		if err := decodeJSONFile(path, &report); err != nil {
			return nil, err
		}
		inputs = append(inputs, input(report))
	}
	return inputs, nil
}

func decodeJSONFile(path string, value any) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		if err == nil {
			return fmt.Errorf("%s: multiple JSON values", path)
		}
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
