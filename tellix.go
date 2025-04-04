package main

// XXX -- httpx library bugs
// 1. stdin/stdout leakage
// 2. no asn lookup even when we ask for it

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	asnmap "github.com/projectdiscovery/asnmap/libs"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/httpx/runner"
)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	log.SetOutput(io.Discard)

	s := server.NewMCPServer("tellix", "1.0.2", server.WithToolCapabilities(true))
	s.AddTool(liteTool(), liteHandler)
	s.AddTool(fullTool(), fullHandler)
	s.AddTool(asnTool(), asnHandler)

	if err := server.ServeStdio(s); err != nil {
		if strings.Contains(err.Error(), "file already closed") || errors.Is(err, io.EOF) {
			return
		}
		fmt.Fprintf(os.Stderr, "Server failed: %v\n", err)
		os.Exit(1)
	}
}

func liteTool() mcp.Tool {
	return mcp.NewTool(
		"http_lite_recon",
		mcp.WithDescription("Fast, lightweight HTTP reconnaissance"),
		mcp.WithString("targets", mcp.Required(), mcp.Description("Newline-separated list of URLs or hosts")),
	)
}

func fullTool() mcp.Tool {
	return mcp.NewTool(
		"http_full_recon",
		mcp.WithDescription("Comprehensive full HTTP scan with metadata and body preview"),
		mcp.WithString("targets", mcp.Required(), mcp.Description("Newline-separated list of URLs or hosts")),
		mcp.WithBoolean("confirm", mcp.Required(), mcp.Description("Explicit confirmation to run full mode")),
	)
}

func asnTool() mcp.Tool {
	return mcp.NewTool(
		"asn_lookup",
		mcp.WithDescription("Query ASN info for IP, ASN number, org name, or domain"),
		mcp.WithString("input", mcp.Required(), mcp.Description("IP address, ASN, domain, or organization")),
	)
}

func liteHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	raw, ok := req.Params.Arguments["targets"].(string)
	if !ok {
		return nil, errors.New("invalid or missing 'targets'")
	}
	return runHttpx(parseTargets(raw), "lite")
}

func fullHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	raw, ok := req.Params.Arguments["targets"].(string)
	if !ok {
		return nil, errors.New("invalid or missing 'targets'")
	}
	confirm, ok := req.Params.Arguments["confirm"].(bool)
	if !ok || !confirm {
		return mcp.NewToolResultText(`{"error": "Full scan requires confirm=true"}`), nil
	}
	return runHttpx(parseTargets(raw), "full")
}

func asnHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input, ok := req.Params.Arguments["input"].(string)
	if !ok || strings.TrimSpace(input) == "" {
		return nil, errors.New("missing or invalid 'input'")
	}

	client, err := asnmap.NewClient()
	if err != nil {
		return nil, fmt.Errorf("asnmap init failed: %v", err)
	}

	// domain -> IP resolution if needed
	if net.ParseIP(input) == nil {
		if resolved, err := asnmap.ResolveDomain(input); err == nil && len(resolved) > 0 {
			input = resolved[0]
		}
	}

	resp, err := client.GetData(input)
	if err != nil {
		return nil, err
	}

	mapped, err := asnmap.MapToResults(resp)
	if err != nil {
		return nil, err
	}

	out, _ := json.MarshalIndent(mapped, "", "  ")
	return mcp.NewToolResultText(string(out)), nil
}

func parseTargets(input string) goflags.StringSlice {
	var targets goflags.StringSlice
	for _, t := range strings.Split(input, "\n") {
		if trimmed := strings.TrimSpace(t); trimmed != "" {
			targets = append(targets, trimmed)
		}
	}
	return targets
}

func runHttpx(targets goflags.StringSlice, mode string) (*mcp.CallToolResult, error) {
	opts := runner.Options{
		Methods:          "GET",
		InputTargetHost:  targets,
		Silent:           true,
		Threads:          10,
		Retries:          3,
		JSONOutput:       true,
		ResponseInStdout: false,
		NoColor:          true,
	}

	switch mode {
	case "lite":
		// minimal options
	case "full":
		opts.Asn = true
		opts.Probe = true
		opts.Favicon = true
		opts.Jarm = true
		opts.TLSGrab = true
		opts.TechDetect = true
		opts.CSPProbe = true
		opts.HTTP2Probe = true
		opts.FollowRedirects = true
	default:
		return nil, errors.New("invalid mode")
	}

	var results []map[string]interface{}

	opts.OnResult = func(r runner.Result) {
		if r.Err != nil {
			return
		}

		data, _ := json.Marshal(r)
		var parsed map[string]interface{}
		_ = json.Unmarshal(data, &parsed)

		// ASN fallback if httpx didn't include it
		if r.ASN == nil && len(r.A) > 0 {
			if client, err := asnmap.NewClient(); err == nil {
				if ip := net.ParseIP(r.A[0]); ip != nil {
					if resp, err := client.GetData(ip.String()); err == nil {
						if mapped, err := asnmap.MapToResults(resp); err == nil && len(mapped) > 0 {
							parsed["asn"] = mapped[0]
						}
					}
				}
			}
		}

		if mode == "full" {
			// Headers
			if r.Response != nil && r.Response.Headers != nil {
				headers := make(map[string]string)
				for k, v := range r.Response.Headers {
					headers[k] = strings.Join(v, ", ")
				}
				parsed["headers"] = headers
			}

			// Body preview
			if r.Raw != "" {
				split := strings.SplitN(r.Raw, "\r\n\r\n", 2)
				if len(split) == 2 {
					body := split[1]
					if len(body) > 160 {
						body = body[:160]
					}
					parsed["body_preview"] = body
				}
			}
		}

		results = append(results, parsed)
	}

	if err := opts.ValidateOptions(); err != nil {
		return nil, err
	}

	r, err := runner.New(&opts)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	// Silence stdout/stdin
	devNullOut, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	origOut := os.Stdout
	os.Stdout = devNullOut
	defer func() { os.Stdout = origOut }()

	devNullIn, _ := os.OpenFile(os.DevNull, os.O_RDONLY, 0)
	origIn := os.Stdin
	os.Stdin = devNullIn
	defer func() { os.Stdin = origIn }()

	r.RunEnumeration()

	out, _ := json.MarshalIndent(map[string]interface{}{
		"mode":    mode,
		"results": results,
	}, "", "  ")

	return mcp.NewToolResultText(string(out)), nil
}
