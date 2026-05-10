package compat

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	resolvePattern       = regexp.MustCompile(`^\[resolve\] (.+?): ([0-9]+) (delay-)?imports, ([0-9]+) resolved, ([0-9]+) unresolved(?:, exports=[0-9]+)?$`)
	unresolvedPattern    = regexp.MustCompile(`^\[resolve\] UNRESOLVED: ([^ ]+)`)
	missingDLLPattern    = regexp.MustCompile(`^\[resolve\] DLL NOT FOUND: ([^ ]+)`)
	autoStubPattern      = regexp.MustCompile(`^\[MISSING\] auto-synth!(.+?)(?: \(id=0x[0-9A-Fa-f]+\))?$`)
	unimplementedPattern = regexp.MustCompile(`UNIMPLEMENTED: (.+?)(?: \(id=0x[0-9A-Fa-f]+\))?$`)
	exitProcessPattern   = regexp.MustCompile(`\[win32\] ExitProcess\((-?[0-9]+)\)`)
)

type Report struct {
	Logs []LogSummary `json:"logs"`
}

type LogSummary struct {
	SourceLog           string        `json:"source_log"`
	Imports             ImportSummary `json:"imports"`
	Calls               []CallSummary `json:"calls"`
	CPUFaults           IssueSummary  `json:"cpu_faults"`
	RuntimeErrors       IssueSummary  `json:"runtime_errors"`
	ExitProcessCode     *int64        `json:"exit_process_code"`
	AutomationCompleted bool          `json:"automation_completed"`
}

type ImportSummary struct {
	Resolved     int                 `json:"resolved"`
	Unresolved   int                 `json:"unresolved"`
	Observations []ImportObservation `json:"observations"`
	Details      []string            `json:"details"`
}

type ImportObservation struct {
	Module      string `json:"module"`
	Kind        string `json:"kind"`
	Total       int    `json:"total"`
	Resolved    int    `json:"resolved"`
	Unresolved  int    `json:"unresolved"`
	Occurrences int    `json:"occurrences"`
}

type CallSummary struct {
	Kind  string `json:"kind"`
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type IssueSummary struct {
	Count    int      `json:"count"`
	Messages []string `json:"messages"`
}

func ParseFiles(paths []string) (Report, error) {
	cleaned := make([]string, len(paths))
	for i, path := range paths {
		cleaned[i] = filepath.Clean(path)
	}
	sort.Strings(cleaned)

	report := Report{Logs: make([]LogSummary, 0, len(cleaned))}
	for _, path := range cleaned {
		file, err := os.Open(path)
		if err != nil {
			return Report{}, fmt.Errorf("%s: %w", path, err)
		}
		summary, parseErr := ParseLog(path, file)
		closeErr := file.Close()
		if parseErr != nil {
			return Report{}, fmt.Errorf("%s: %w", path, parseErr)
		}
		if closeErr != nil {
			return Report{}, fmt.Errorf("%s: %w", path, closeErr)
		}
		report.Logs = append(report.Logs, summary)
	}
	return report, nil
}

func ParseLog(source string, reader io.Reader) (LogSummary, error) {
	summary := LogSummary{
		SourceLog: source,
		Imports: ImportSummary{
			Observations: []ImportObservation{},
			Details:      []string{},
		},
		Calls:         []CallSummary{},
		CPUFaults:     IssueSummary{Messages: []string{}},
		RuntimeErrors: IssueSummary{Messages: []string{}},
	}
	observations := make(map[string]*ImportObservation)
	calls := make(map[string]*CallSummary)
	importDetails := make(map[string]struct{})
	cpuMessages := make(map[string]struct{})
	runtimeMessages := make(map[string]struct{})

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if match := resolvePattern.FindStringSubmatch(line); match != nil {
			kind := "regular"
			if match[3] != "" {
				kind = "delay"
			}
			total, _ := strconv.Atoi(match[2])
			resolved, _ := strconv.Atoi(match[4])
			unresolved, _ := strconv.Atoi(match[5])
			key := match[1] + "\x00" + kind + "\x00" + match[2] + "\x00" + match[4] + "\x00" + match[5]
			if observation := observations[key]; observation != nil {
				observation.Occurrences++
			} else {
				observations[key] = &ImportObservation{
					Module: match[1], Kind: kind, Total: total,
					Resolved: resolved, Unresolved: unresolved, Occurrences: 1,
				}
			}
			summary.Imports.Resolved += resolved
			summary.Imports.Unresolved += unresolved
		}
		if match := unresolvedPattern.FindStringSubmatch(line); match != nil {
			importDetails[match[1]] = struct{}{}
		}
		if match := missingDLLPattern.FindStringSubmatch(line); match != nil {
			importDetails[match[1]] = struct{}{}
		}
		if match := autoStubPattern.FindStringSubmatch(line); match != nil {
			addCall(calls, "auto_stub", match[1])
		}
		if match := unimplementedPattern.FindStringSubmatch(line); match != nil {
			addCall(calls, "unimplemented", match[1])
		}
		if strings.Contains(line, "[cpu-fault]") ||
			strings.Contains(line, "[cpu-recover]") ||
			(strings.Contains(line, "[govm] thread ") && strings.Contains(line, " crashed:")) {
			summary.CPUFaults.Count++
			cpuMessages[line] = struct{}{}
		}
		if strings.Contains(line, "runtime error:") ||
			strings.HasPrefix(line, "panic:") ||
			strings.HasPrefix(line, "fatal error:") {
			summary.RuntimeErrors.Count++
			runtimeMessages[line] = struct{}{}
		}
		if match := exitProcessPattern.FindStringSubmatch(line); match != nil {
			code, err := strconv.ParseInt(match[1], 10, 64)
			if err == nil {
				summary.ExitProcessCode = &code
			}
		}
		if strings.Contains(line, "[auto] script complete") {
			summary.AutomationCompleted = true
		}
	}
	if err := scanner.Err(); err != nil {
		return LogSummary{}, err
	}

	for _, observation := range observations {
		summary.Imports.Observations = append(summary.Imports.Observations, *observation)
	}
	sort.Slice(summary.Imports.Observations, func(i, j int) bool {
		left, right := summary.Imports.Observations[i], summary.Imports.Observations[j]
		if left.Module != right.Module {
			return left.Module < right.Module
		}
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		if left.Total != right.Total {
			return left.Total < right.Total
		}
		if left.Resolved != right.Resolved {
			return left.Resolved < right.Resolved
		}
		return left.Unresolved < right.Unresolved
	})
	summary.Imports.Details = sortedKeys(importDetails)
	for _, call := range calls {
		summary.Calls = append(summary.Calls, *call)
	}
	sort.Slice(summary.Calls, func(i, j int) bool {
		if summary.Calls[i].Kind != summary.Calls[j].Kind {
			return summary.Calls[i].Kind < summary.Calls[j].Kind
		}
		return summary.Calls[i].Name < summary.Calls[j].Name
	})
	summary.CPUFaults.Messages = sortedKeys(cpuMessages)
	summary.RuntimeErrors.Messages = sortedKeys(runtimeMessages)
	return summary, nil
}

func addCall(calls map[string]*CallSummary, kind, name string) {
	key := kind + "\x00" + name
	if call := calls[key]; call != nil {
		call.Count++
		return
	}
	calls[key] = &CallSummary{Kind: kind, Name: name, Count: 1}
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
