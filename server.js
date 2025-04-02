// Import required libraries
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { execSync } from "child_process";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { z } from "zod";

// Configure temporary directory
const tmpDir = '/tmp/osint-mcp';
fs.mkdirSync(tmpDir, { recursive: true });

// Set up logging
const logToStderr = (message) => {
  console.error(`[Tellix] ${message}`);
};

logToStderr('Starting Tellix HTTP Reconnaissance Server...');

// Helper function for executing httpx commands
const executeHttpx = (targets, options, outputType = "json") => {
  const inputId = crypto.randomBytes(8).toString('hex');
  const inputFile = path.join(tmpDir, `${inputId}.txt`);
  const outputFile = path.join(tmpDir, `${inputId}.json`);
  
  try {
    fs.writeFileSync(inputFile, targets);
    
    // Use -o flag to output directly to a file
    const cmd = `cat ${inputFile} | httpx ${options} -json -o ${outputFile}`;
    
    logToStderr(`Executing: ${cmd}`);
    
    // Execute command
    execSync(cmd, { shell: '/bin/bash' });
    
    // Read the JSON output file
    let results = [];
    if (fs.existsSync(outputFile)) {
      const content = fs.readFileSync(outputFile, 'utf8');
      if (content && content.trim()) {
        results = content.trim().split('\n')
          .filter(line => line.trim() !== '')
          .map(line => JSON.parse(line));
      }
    }
    
    return {
      command: `httpx ${options}`,
      level: outputType,
      results: results
    };
  } catch (error) {
    logToStderr(`Error in executeHttpx: ${error.message}`);
    return {
      command: `httpx ${options}`,
      level: outputType,
      error: error.message,
      results: []
    };
  } finally {
    // Clean up temp files
    try {
      if (fs.existsSync(inputFile)) fs.unlinkSync(inputFile);
      if (fs.existsSync(outputFile)) fs.unlinkSync(outputFile);
    } catch (e) {
      logToStderr(`Failed to clean up temp files: ${e.message}`);
    }
  }
};

// Create an MCP server
const server = new McpServer({ 
  name: "tellix", 
  version: "1.0.0" 
});

// 1. HTTP Quick Reconnaissance Tool
server.tool(
  "http_quick_recon", 
  {
    targets: z.string().describe("Line-separated list of URLs or hosts to scan")
  }, 
  async ({ targets }) => {
    logToStderr(`Executing http_quick_recon on ${targets.split('\n').length} targets`);
    
    // Fixed options for quick recon
    const options = "-status-code -title -web-server -ip -asn -cdn";
    
    try {
      const results = executeHttpx(targets, options, "quick");
      
      return {
        content: [{ 
          type: "text", 
          text: JSON.stringify(results, null, 2) 
        }]
      };
    } catch (error) {
      logToStderr(`HTTP quick reconnaissance failed: ${error.message}`);
      throw new Error(`HTTP quick reconnaissance failed: ${error.message}`);
    }
  }
);

// 2. HTTP Complete Reconnaissance Tool
server.tool(
  "http_complete_recon", 
  {
    targets: z.string().describe("Line-separated list of URLs or hosts to scan")
  }, 
  async ({ targets }) => {
    logToStderr(`Executing http_complete_recon on ${targets.split('\n').length} targets`);
    
    // Fixed options for complete recon
    const options = "-status-code -title -web-server -ip -asn -cdn -probe -server -vhost -fhr -td -csp-probe -jarm -favicon -sc -irh -bp -tls-grab -http2";
    
    try {
      const results = executeHttpx(targets, options, "complete");
      
      return {
        content: [{ 
          type: "text", 
          text: JSON.stringify(results, null, 2) 
        }]
      };
    } catch (error) {
      logToStderr(`HTTP complete reconnaissance failed: ${error.message}`);
      throw new Error(`HTTP complete reconnaissance failed: ${error.message}`);
    }
  }
);

// 3. HTTP Full Content Reconnaissance Tool
server.tool(
  "http_full_recon", 
  {
    targets: z.string().describe("Line-separated list of URLs or hosts to scan"),
    confirm: z.boolean().describe("Confirmation for retrieving full content (required)")
  }, 
  async ({ targets, confirm }) => {
    const targetCount = targets.split('\n').filter(t => t.trim() !== '').length;
    
    if (!confirm) {
      return {
        content: [{ 
          type: "text", 
          text: JSON.stringify({
            error: "Full reconnaissance not confirmed",
            message: `HTTP full reconnaissance requires explicit confirmation as it will retrieve complete page content for ${targetCount} targets, which could result in large data transfers. Set 'confirm: true' to proceed.`
          }, null, 2) 
        }]
      };
    }
    
    logToStderr(`Executing http_full_recon on ${targetCount} targets`);
    
    // Fixed options for full recon
    const options = "-status-code -title -web-server -ip -asn -cdn -probe -server -vhost -fhr -td -csp-probe -jarm -favicon -sc -irh -include-response";
    
    try {
      const results = executeHttpx(targets, options, "full");
      
      return {
        content: [{ 
          type: "text", 
          text: JSON.stringify(results, null, 2) 
        }]
      };
    } catch (error) {
      logToStderr(`HTTP full reconnaissance failed: ${error.message}`);
      throw new Error(`HTTP full reconnaissance failed: ${error.message}`);
    }
  }
);

// Tool metadata 
server.tool(
  "http_probe_metadata", 
  {
    action: z.enum(["help"]).default("help")
  }, 
  async ({ action }) => {
    const metadata = {
      tools: [
        {
          name: "http_quick_recon",
          description: "Fast, lightweight HTTP reconnaissance that provides essential information with minimal overhead",
          usage: "Use for initial reconnaissance or when scanning large numbers of hosts",
          parameters: "-status-code -title -web-server -ip -asn -cdn",
          example: "http_quick_recon(targets='example.com\\ntest.com')"
        },
        {
          name: "http_complete_recon",
          description: "Comprehensive HTTP reconnaissance that collects detailed information about targets without retrieving full page content",
          usage: "Use when detailed metadata is needed for security assessment",
          parameters: "-status-code -title -web-server -ip -asn -cdn -probe -server -vhost -fhr -td -csp-probe -jarm -favicon -sc -irh -bp -tls-grab -http2",
          example: "http_complete_recon(targets='example.com\\ntest.com')"
        },
        {
          name: "http_full_recon",
          description: "Complete HTTP reconnaissance including full page body content for detailed analysis",
          usage: "ONLY use when explicitly required for content analysis. Significantly increases response size and processing time",
          parameters: "-status-code -title -web-server -ip -asn -cdn -probe -server -vhost -fhr -td -csp-probe -jarm -favicon -sc -irh -include-response",
          example: "http_full_recon(targets='example.com', confirm=true)"
        }
      ],
      selection_guidelines: "Start with http_quick_recon for initial discovery, upgrade to http_complete_recon for detailed analysis, and only use http_full_recon when content analysis is explicitly required."
    };
    
    return {
      content: [{ 
        type: "text", 
        text: JSON.stringify(metadata, null, 2) 
      }]
    };
  }
);

// Connect to the transport layer
const transport = new StdioServerTransport();

// Connect and start the server
server.connect(transport).then(() => {
  logToStderr('Tellix server initialized and ready');
}).catch((error) => {
  logToStderr(`Error initializing server: ${error.message}`);
  process.exit(1);
});

// Handle process exit
process.on('SIGINT', () => {
  logToStderr('Received SIGINT. Shutting down...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  logToStderr('Received SIGTERM. Shutting down...');
  process.exit(0);
});
