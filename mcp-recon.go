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

	// Add prompts
	s.AddPrompt(httpLitePrompt(), httpLitePromptHandler)
	s.AddPrompt(katanaCommandPrompt(), katanaCommandPromptHandler)

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

// Prompt definitions
func httpLitePrompt() mcp.Prompt {
	return mcp.NewPrompt(
		"http_lite_scan",
		mcp.WithPromptDescription("Quick HTTP scan for basic information about websites"),
		mcp.WithArgument("targets",
			mcp.ArgumentDescription("Website URLs or hostnames to scan, one per line"),
			mcp.RequiredArgument(),
		),
	)
}

func katanaCommandPrompt() mcp.Prompt {
	return mcp.NewPrompt(
		"katana_command_generator",
		mcp.WithPromptDescription("Generate optimized Katana crawl commands based on httpx reconnaissance"),
		mcp.WithArgument("target",
			mcp.ArgumentDescription("Target URL to crawl"),
			mcp.RequiredArgument(),
		),
		mcp.WithArgument("goal",
			mcp.ArgumentDescription("Primary reconnaissance goal (e.g., 'api_discovery', 'hidden_functionality', 'comprehensive')"),
		),
		mcp.WithArgument("thoroughness",
			mcp.ArgumentDescription("Balance between speed and thoroughness (1-3, where 3 is most thorough)"),
		),
	)
}

// Prompt handlers
func httpLitePromptHandler(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	targets := request.Params.Arguments["targets"]
	if targets == "" {
		return nil, fmt.Errorf("targets are required")
	}

	return mcp.NewGetPromptResult(
		"HTTP Reconnaissance",
		[]mcp.PromptMessage{
			mcp.NewPromptMessage(
				mcp.RoleUser,
				mcp.NewTextContent(fmt.Sprintf("Run a quick HTTP scan on these targets: %s", targets))),
		},
	), nil
}

func katanaCommandPromptHandler(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	target := request.Params.Arguments["target"]
	if target == "" {
		return nil, fmt.Errorf("target is required")
	}

	goal, ok := request.Params.Arguments["goal"]
	if !ok || goal == "" {
		goal = "comprehensive" // Default value
	}

	thoroughness, ok := request.Params.Arguments["thoroughness"]
	if !ok || thoroughness == "" {
		thoroughness = "2" // Default value
	}

	katanaHelp := getKatanaHelpText()

	promptText := fmt.Sprintf(`
		You are an expert in web reconnaissance and security testing. Follow these steps to generate an optimized Katana command:

		1. First, use the http_full_recon tool to perform initial reconnaissance on "%s"
		2. Carefully analyze the HTTP response data, particularly:
		- Server technologies and frameworks detected
		- CDN, ASNs and WAFs
		- HTTP response headers and status codes
		- Directory structure patterns
		- Naming conventions

		3. Based on this analysis, generate a tailored Katana crawl command optimized for %s reconnaissance with thoroughness level %s/3

		4. Your command should:
		- Set appropriate depth based on thoroughness (%s/3)
		- Include necessary JavaScript crawling options for SPAs
		- Configure headless browsing if needed (for example to evade WAFs like Akamai)
		- Set timeout and thread values appropriate for the target
		- Include specific exclusion patterns (using -fr) based on observed URL patterns
		- Filter unnecessary file extensions (using -ef)
		- Include other parameters as appropriate

		5. Format your response as:
		a) The complete Katana command as a single line
		b) Brief explanation of key parameter choices (1 sentences each)
		c) Expected outcomes from this optimized crawl

		KATANA COMMAND REFERENCE:
		%s

		Remember to tailor your command to what you discover in the http_full_recon results. Different application types (traditional, SPA, API-driven) require different Katana configurations.`, target, goal, thoroughness, thoroughness, katanaHelp)

	// Just provide a single clear instruction for the LLM
	return mcp.NewGetPromptResult(
		"Katana Command Generator",
		[]mcp.PromptMessage{
			mcp.NewPromptMessage(
				mcp.RoleUser,
				mcp.NewTextContent(promptText),
			),
		},
	), nil
}

// Tool Handlers

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

func getKatanaHelpText() string {
	return `
Katana is a fast crawler focused on execution in automation
pipelines offering both headless and non-headless crawling.

Usage:
  katana [flags]

Flags:
INPUT:
   -u, -list string[]     target url / list to crawl
   -resume string         resume scan using resume.cfg
   -e, -exclude string[]  exclude host matching specified filter ('cdn', 'private-ips', cidr, ip, regex)

CONFIGURATION:
   -r, -resolvers string[]       list of custom resolver (file or comma separated)
   -d, -depth int                maximum depth to crawl (default 3)
   -jc, -js-crawl                enable endpoint parsing / crawling in javascript file
   -jsl, -jsluice                enable jsluice parsing in javascript file (memory intensive)
   -ct, -crawl-duration value    maximum duration to crawl the target for (s, m, h, d) (default s)
   -kf, -known-files string      enable crawling of known files (all,robotstxt,sitemapxml), a minimum depth of 3 is required to ensure all known files are properly crawled.
   -mrs, -max-response-size int  maximum response size to read (default 4194304)
   -timeout int                  time to wait for request in seconds (default 10)
   -aff, -automatic-form-fill    enable automatic form filling (experimental)
   -fx, -form-extraction         extract form, input, textarea & select elements in jsonl output
   -retry int                    number of times to retry the request (default 1)
   -proxy string                 http/socks5 proxy to use
   -td, -tech-detect             enable technology detection
   -H, -headers string[]         custom header/cookie to include in all http request in header:value format (file)
   -config string                path to the katana configuration file
   -fc, -form-config string      path to custom form configuration file
   -flc, -field-config string    path to custom field configuration file
   -s, -strategy string          Visit strategy (depth-first, breadth-first) (default "depth-first")
   -iqp, -ignore-query-params    Ignore crawling same path with different query-param values
   -tlsi, -tls-impersonate       enable experimental client hello (ja3) tls randomization
   -dr, -disable-redirects       disable following redirects (default false)

DEBUG:
   -health-check, -hc        run diagnostic check up
   -elog, -error-log string  file to write sent requests error log
   -pprof-server             enable pprof server

HEADLESS:
   -hl, -headless                    enable headless hybrid crawling (experimental)
   -sc, -system-chrome               use local installed chrome browser instead of katana installed
   -sb, -show-browser                show the browser on the screen with headless mode
   -ho, -headless-options string[]   start headless chrome with additional options
   -nos, -no-sandbox                 start headless chrome in --no-sandbox mode
   -cdd, -chrome-data-dir string     path to store chrome browser data
   -scp, -system-chrome-path string  use specified chrome browser for headless crawling
   -noi, -no-incognito               start headless chrome without incognito mode
   -cwu, -chrome-ws-url string       use chrome browser instance launched elsewhere with the debugger listening at this URL
   -xhr, -xhr-extraction             extract xhr request url,method in jsonl output

SCOPE:
   -cs, -crawl-scope string[]       in scope url regex to be followed by crawler
   -cos, -crawl-out-scope string[]  out of scope url regex to be excluded by crawler
   -fs, -field-scope string         pre-defined scope field (dn,rdn,fqdn) or custom regex (e.g., '(company-staging.io|company.com)') (default "rdn")
   -ns, -no-scope                   disables host based default scope
   -do, -display-out-scope          display external endpoint from scoped crawling

FILTER:
   -mr, -match-regex string[]       regex or list of regex to match on output url (cli, file)
   -fr, -filter-regex string[]      regex or list of regex to filter on output url (cli, file)
   -f, -field string                field to display in output (url,path,fqdn,rdn,rurl,qurl,qpath,file,ufile,key,value,kv,dir,udir)
   -sf, -store-field string         field to store in per-host output (url,path,fqdn,rdn,rurl,qurl,qpath,file,ufile,key,value,kv,dir,udir)
   -em, -extension-match string[]   match output for given extension (eg, -em php,html,js)
   -ef, -extension-filter string[]  filter output for given extension (eg, -ef png,css)
   -mdc, -match-condition string    match response with dsl based condition
   -fdc, -filter-condition string   filter response with dsl based condition

RATE-LIMIT:
   -c, -concurrency int          number of concurrent fetchers to use (default 10)
   -p, -parallelism int          number of concurrent inputs to process (default 10)
   -rd, -delay int               request delay between each request in seconds
   -rl, -rate-limit int          maximum requests to send per second (default 150)
   -rlm, -rate-limit-minute int  maximum number of requests to send per minute

UPDATE:
   -up, -update                 update katana to latest version
   -duc, -disable-update-check  disable automatic katana update check

OUTPUT:
   -o, -output string                file to write output to
   -sr, -store-response              store http requests/responses
   -srd, -store-response-dir string  store http requests/responses to custom directory
   -ncb, -no-clobber                 do not overwrite output file
   -sfd, -store-field-dir string     store per-host field to custom directory
   -or, -omit-raw                    omit raw requests/responses from jsonl output
   -ob, -omit-body                   omit response body from jsonl output
   -j, -jsonl                        write output in jsonl format
   -nc, -no-color                    disable output content coloring (ANSI escape codes)
   -silent                           display output only
   -v, -verbose                      display verbose output
   -debug                            display debug output
   -version                          display project version
`
}
