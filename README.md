# mcp-recon

> mcp-recon (formerly Tellix) is a conversational recon interface and MCP server powered by httpx and LLMs. Just ask.

## Overview

mcp-recon bridges the gap between natural language and HTTP infrastructure analysis. It exposes recon tools through the Model Context Protocol (MCP), allowing you to run reconnaissance on web domains via any compatible AI interface, like Claude Desktop.

## Features

- **Conversational Commands**: Run reconnaissance through simple text prompts
- **MCP Server**: Use with Claude Desktop, local LLM wrappers, or other MCP-compatible tools
- **Multiple Analysis Modes**: Choose from quick, complete, and full reconnaissance levels
- **Standalone ASN Lookup**: Query IPs, ASNs, or organizations directly
- **Built-in TLS, CDN, and header analysis**
- **Docker Ready**: Run in an isolated container for security and portability
- **Powered by httpx**: Built on ProjectDiscovery's battle-tested reconnaissance tools
- **Bug Workarounds**: Automatically handles `httpx`'s stdin/stdout leakage issue

## Quick Start Guide

mcp-recon provides three main reconnaissance tools:

### 1. Quick/Lightweight Reconnaissance (`http_lite_recon` / `http_quick_recon`)

Fast, lightweight HTTP fingerprinting that provides essential information with minimal overhead.

Example user query and expected response:

```
User: "Using quick http recon, what's the status code for example.com?"

AI: "I checked example.com and it's currently returning a 200 OK status code, indicating the site is up and functioning normally. It's being served from an Nginx web server on IP 93.184.216.34."
```

### 2. Full Reconnaissance (`http_full_recon`)

Comprehensive metadata collection including page previews, headers, certificates, and technology detection.

Example user query and expected response:

```
User: "Using full http recon, what certificates is www.google.com using?"

AI: "Based on my analysis, www.google.com is using a TLS 1.3 certificate issued by Google Trust Services. The certificate was issued on March 20, 2025, and is valid until June 12, 2025. It was specifically issued for 'www.google.com' and uses the TLS_AES_128_GCM_SHA256 cipher suite."
```

### 4. ASN Lookup (`asn_lookup`)

Standalone lookup of IPs, ASNs, or org names using ProjectDiscovery's `asnmap` library.

Example user query and expected response:

```
User: "Who owns ASN 14421?"

AI: "ASN 14421 is operated by 'PPLINKNET' in the US."
```

## Example Queries

### Certificate Analysis

```
User: "Use complete http recon on www.google.com to check what certificates they're using"

AI: "www.google.com is using a TLS 1.3 certificate issued by Google Trust Services (issuer: WE2). The certificate was issued on March 20, 2025, and expires on June 12, 2025. It uses the TLS_AES_128_GCM_SHA256 cipher suite."
```

### Security Header Inspection

```
User: "Use complete http recon on example.com to analyze security headers"

AI: "My analysis of example.com shows it's missing several key security headers: Content-Security-Policy, X-Frame-Options, and HTTP Strict Transport Security (HSTS). This could expose the site to XSS, clickjacking, and man-in-the-middle attacks."
```

### Technology Detection

```
User: "Use quick http recon on cloudflare.com to see what technologies they use"

AI: "cloudflare.com is running on Cloudflare's own infrastructure with HTTP/2 support. The site implements HSTS for secure connections and is served from Cloudflare's CDN with a 200 status code."
```

### Multi-Domain Comparison

```
User: "Use complete http recon on microsoft.com, apple.com, and amazon.com to compare their TLS setups"

AI: "My analysis shows:
- microsoft.com: TLS 1.3 with certificate from Microsoft RSA TLS CA
- apple.com: TLS 1.3 with certificate from DigiCert
- amazon.com: TLS 1.2 with certificate from DigiCert

Microsoft and Apple are using the newer TLS 1.3 protocol while Amazon uses TLS 1.2."
```

### Lookup by IP

```
User: "Tell me who owns 8.8.8.8 using ASN lookup"

AI: "8.8.8.8 belongs to Google LLC (AS15169) in the United States."
```

## Installation

```bash
# Clone the repository
git clone https://github.com/nickpending/mcp-recon.git
cd mcp-recon

# Build the Docker image
docker build -t mcp-recon .

# Run the container
docker run -it --rm mcp-recon
```

mcp-recon is designed to run as a Docker container to be used with Claude Desktop via the MCP protocol.

## MCP Configuration

mcp-recon runs as a standalone MCP server. Add it to your MCP configuration like so:

```json
"mcp-recon": {
  "command": "docker",
  "args": [
    "run",
    "--rm",
    "-i",
    "mcp-recon"
  ]
}
```

Or using an `.env` file:

```json
"mcp-recon": {
  "command": "docker",
  "args": [
    "run",
    "--rm",
    "-i",
    "--env-file", "/Users/yourname/.config/mcp-recon.env",
    "mcp/osint"
  ]
}
```

Your `.env` should contain:

```env
PDCP_API_KEY=your_projectdiscovery_api_key
```

## Troubleshooting

**No Results Returned**: Check that:

- Domain is publicly accessible
- You've specified the correct tool (http_quick_recon, http_full_recon, asn)
- Target domain isn't blocking scans

**Performance Issues**:

- Start with http_quick_recon for faster results
- Scan fewer domains at once for better performance

## Known Issues

- **httpx Stdin Leak**: The `httpx` library attempts to read stdin even when used as a library. mcp-recon shields `os.Stdin` to prevent interference with MCP.
- **ASN Silent Failures**: Even when `Asn = true`, `httpx` may fail to enrich IPs. mcp-recon includes a fallback using the official `asnmap` Go library.

## Security Considerations

- Only scan domains you own or have permission to test
- The full_recon mode retrieves complete page content - use judiciously
- Consider rate limiting to avoid impacting target systems

## Screenshot

mcp-recon in action via Claude Desktop, using the `http_quick_recon` and `http_complete_recon` tools:

![mcp-recon Screenshot - Quick Recon](docs/tellix-screenshot-01.png)

> This example shows a quick recon request on `www.google.com`, returning status code, title, server details, and IP address — all from a natural language query.

![mcp-recon Screenshot - Complete Recon](docs/tellix-screenshot-02.png)

> This example demonstrates a complete recon on `www.microsoft.com`, including TLS config, headers, CDN, and security observations.

## Name Change Notice

This project was formerly known as **Tellix**. It has been renamed to **mcp-recon** to better align with the Model Context Protocol (MCP) naming convention used in security tools. All links to the previous repository name will be redirected to the new name, but you should update your references when possible.

## License

This project is licensed under the MIT License.

## Related Work

[This section intentionally left as a placeholder for similar projects to be added when discovered]

## Acknowledgments

- Built with [Model Context Protocol SDK](https://modelcontextprotocol.io/introduction)
- Powered by [mcp-go](https://github.com/mark3labs/mcp-go) Go SDK for MCP
- Powered by [httpx](https://github.com/projectdiscovery/httpx) from ProjectDiscovery
- ASN lookups via [asnmap](https://github.com/projectdiscovery/asnmap) library
- Testing and development with [Claude Desktop](https://www.anthropic.com)