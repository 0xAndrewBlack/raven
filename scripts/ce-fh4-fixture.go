//go:build ignore

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	compilerID      = "vcpp_v19_51_VS18_6_x64"
	maxPESize       = 64 << 20
	maxResponseSize = 2 << 20
)

type outputLine struct {
	Text string `json:"text"`
}

type compileResponse struct {
	Code        int          `json:"code"`
	Stdout      []outputLine `json:"stdout"`
	Stderr      []outputLine `json:"stderr"`
	DidExecute  bool         `json:"didExecute"`
	TimedOut    bool         `json:"timedOut"`
	Truncated   bool         `json:"truncated"`
	BuildResult *struct {
		Code     int          `json:"code"`
		Stdout   []outputLine `json:"stdout"`
		Stderr   []outputLine `json:"stderr"`
		TimedOut bool         `json:"timedOut"`
	} `json:"buildResult"`
}

func lineText(lines []outputLine) string {
	var result strings.Builder
	for _, line := range lines {
		result.WriteString(line.Text)
	}
	return result.String()
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: ce-fh4-fixture SOURCE EXE RESPONSE")
		os.Exit(2)
	}
	source, err := os.ReadFile(os.Args[1])
	if err != nil {
		fail(err)
	}
	baseURL := os.Getenv("CE_API_URL")
	if baseURL == "" {
		baseURL = "https://godbolt.org"
	}
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		fail(err)
	}
	if parsedURL.Scheme != "https" &&
		!(parsedURL.Scheme == "http" &&
			(parsedURL.Hostname() == "localhost" || parsedURL.Hostname() == "127.0.0.1")) {
		fail(fmt.Errorf("CE_API_URL must use HTTPS or loopback HTTP: %s", baseURL))
	}

	const (
		chunkSize       = 12 * 1024
		fingerprintSize = 512
	)
	var executable []byte
	var fingerprint []byte
	for offset := 0; ; offset += chunkSize {
		argument := "--dump-self"
		if offset != 0 {
			argument = fmt.Sprintf("--dump-self=%d", offset)
		}
		result, responseBody, err := compileAndExecute(
			baseURL,
			string(source),
			argument,
			fmt.Sprintf("%s.%08x.json", os.Args[3], offset),
		)
		if err != nil {
			fail(err)
		}
		encoded := lineText(result.Stdout)
		if len(encoded)%2 != 0 {
			fail(fmt.Errorf(
				"Compiler Explorer execution returned odd-length hexadecimal output at offset %d: %s",
				offset, responseBody))
		}
		part, err := hex.DecodeString(encoded)
		if err != nil {
			fail(fmt.Errorf(
				"decode executable hex at offset %d: %w; response=%s",
				offset, err, responseBody))
		}
		if len(part) < fingerprintSize {
			fail(fmt.Errorf(
				"Compiler Explorer execution returned only %d identity bytes at offset %d: %s",
				len(part), offset, responseBody))
		}
		if fingerprint == nil {
			fingerprint = append([]byte(nil), part[:fingerprintSize]...)
		} else if !bytes.Equal(fingerprint, part[:fingerprintSize]) {
			fail(fmt.Errorf(
				"Compiler Explorer rebuilt a different PE while fetching offset %d",
				offset))
		}
		payload := part[fingerprintSize:]
		executable = append(executable, payload...)
		if len(executable) > maxPESize {
			fail(fmt.Errorf("Compiler Explorer PE exceeds %d bytes", maxPESize))
		}
		if len(payload) < chunkSize {
			break
		}
	}
	if len(executable) < 2 || executable[0] != 'M' || executable[1] != 'Z' {
		fail(errors.New("Compiler Explorer output is not a PE executable"))
	}
	if err := os.WriteFile(os.Args[2], executable, 0o755); err != nil {
		fail(err)
	}
}

func compileAndExecute(
	baseURL string,
	source string,
	argument string,
	responsePath string,
) (compileResponse, []byte, error) {
	payload := map[string]any{
		"source": source,
		"options": map[string]any{
			"userArguments": "/EHsc /O2 /GR- /GS- /MT /Brepro /link /entry:raven_entry /subsystem:console /OPT:REF /OPT:ICF /INCREMENTAL:NO kernel32.lib vcruntime.lib libvcruntime.lib libcmt.lib libucrt.lib",
			"compilerOptions": map[string]any{
				"executorRequest": true,
			},
			"filters": map[string]any{
				"execute": true,
			},
			"executeParameters": map[string]any{
				"args":  []string{argument},
				"stdin": "",
			},
			"tools":     []any{},
			"libraries": []any{},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return compileResponse{}, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		strings.TrimRight(baseURL, "/")+"/api/compiler/"+compilerID+"/compile",
		bytes.NewReader(body),
	)
	if err != nil {
		return compileResponse{}, nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "Raven-FH4-regression")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return compileResponse{}, nil, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxResponseSize+1))
	if err != nil {
		return compileResponse{}, nil, err
	}
	if len(responseBody) > maxResponseSize {
		return compileResponse{}, responseBody, fmt.Errorf(
			"Compiler Explorer response exceeds %d bytes", maxResponseSize)
	}
	if err := os.WriteFile(responsePath, responseBody, 0o600); err != nil {
		return compileResponse{}, responseBody, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return compileResponse{}, responseBody, fmt.Errorf(
			"Compiler Explorer HTTP %s: %s", response.Status, responseBody)
	}
	var result compileResponse
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return result, responseBody, fmt.Errorf(
			"decode Compiler Explorer response: %w", err)
	}
	buildCode := -1
	buildTimedOut := false
	var buildErrors string
	if result.BuildResult != nil {
		buildCode = result.BuildResult.Code
		buildTimedOut = result.BuildResult.TimedOut
		buildErrors = lineText(result.BuildResult.Stderr)
	}
	if result.BuildResult == nil || buildCode != 0 || buildTimedOut ||
		result.Code != 0 || !result.DidExecute || result.TimedOut ||
		result.Truncated {
		return result, responseBody, fmt.Errorf(
			"Compiler Explorer build=%d execute=%d didExecute=%t timedOut=%t truncated=%t stderr=%q response=%s",
			buildCode,
			result.Code,
			result.DidExecute,
			result.TimedOut || buildTimedOut,
			result.Truncated,
			buildErrors+lineText(result.Stderr),
			responseBody,
		)
	}
	return result, responseBody, nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
