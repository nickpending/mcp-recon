# Tellix

> Tellix is a conversational recon interface and MCP server powered by httpx and LLMs. Just ask.

&#x20;&#x20;

## Overview

Tellix bridges the gap between natural language and HTTP infrastructure analysis. It exposes recon tools through the Model Context Protocol (MCP), allowing you to run reconnaissance on web domains via any compatible AI interface.

## Features

- **Conversational Commands**: Run reconnaissance through simple text prompts
- **MCP Server**: Use with Claude Desktop, local LLM wrappers, or other MCP-compatible tools
- **Three Analysis Modes**: Choose from quick, complete, or full reconnaissance levels
- **Docker Ready**: Run in an isolated container for security and portability
- **Powered by httpx**: Built on ProjectDiscovery's battle-tested reconnaissance tool

## Quick Start Guide

Tellix provides three levels of reconnaissance through dedicated tools:

### 1. Quick Reconnaissance (`http_quick_recon`)

Fast, lightweight HTTP fingerprinting that provides essential information with minimal overhead.

Example user query and expected response:

```
User: "Using quick http recon, what's the status code for example.com?"

AI: "I checked example.com and it's currently returning a 200 OK status code, indicating the site is up and functioning normally. It's being served from an Nginx web server on IP 93.184.216.34."
```

### 2. Complete Reconnaissance (`http_complete_recon`)

Comprehensive metadata collection including headers, certificates, and technology detection.

Example user query and expected response:

```
User: "Using complete http recon, what certificates is www.google.com using?"

AI: "Based on my analysis, www.google.com is using a TLS 1.3 certificate issued by Google Trust Services. The certificate was issued on March 20, 2025, and is valid until June 12, 2025. It was specifically issued for 'www.google.com' and uses the TLS_AES_128_GCM_SHA256 cipher suite."
```

### 3. Full Content Reconnaissance (`http_full_recon`)

In-depth analysis including full page content, requiring explicit confirmation.

Example user query and expected response:

```
User: "Using full http recon, what text appears on the homepage of example.com?"

AI: "The homepage of example.com displays a simple page with the heading 'Example Domain' followed by text explaining that this domain is established to be used for illustrative examples in documents. It also includes a link to more information at the IANA website."
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

## Installation

### Docker (Recommended)

```bash
# Build the image
docker build -t tellix .

# Run the container
docker run -it --rm tellix
```

### Manual Setup

Requirements:

- Node.js 18+
- Go (for httpx)
- httpx (`go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest`)

```bash
# Install dependencies
npm install

# Run the server
npm start
```

## MCP Configuration

Tellix runs as a standalone MCP server. Add it to your MCP configuration like so:

```json
"tellix": {
  "command": "docker",
  "args": [
    "run",
    "--rm",
    "-i",
    "tellix"
  ]
}
```

## Troubleshooting

**No Results Returned**: Check that:

- Domain is publicly accessible
- You've specified the correct tool (http\_quick\_recon, http\_complete\_recon, or http\_full\_recon)
- Target domain isn't blocking scans

**Performance Issues**:

- Start with http\_quick\_recon for faster results
- Scan fewer domains at once for better performance

## Security Considerations

- Only scan domains you own or have permission to test
- The full\_recon mode retrieves complete page content - use judiciously
- Consider rate limiting to avoid impacting target systems

## Screenshot

Tellix in action via Claude Desktop, using the `http_quick_recon` tool:



> This example shows a quick recon request on `www.google.com`, returning status code, title, server details, and IP address — all from a natural language query.

## License

This project is licensed under the MIT License.

## Acknowledgments

- Built with [Model Context Protocol SDK](https://modelcontextprotocol.io/introduction)
- Powered by [httpx](https://github.com/projectdiscovery/httpx) from ProjectDiscovery


