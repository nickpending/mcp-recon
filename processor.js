const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

// Configure temporary directory
const tmpDir = '/tmp/osint-mcp';
fs.mkdirSync(tmpDir, { recursive: true });

// Create readline interface
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

// Process each line from stdin
rl.on('line', (line) => {
  try {
    // Parse the JSON request
    const request = JSON.parse(line);
    
    // Process the request
    const result = processRequest(request);
    
    // Output the result as JSON
    console.log(JSON.stringify(result));
  } catch (error) {
    // Handle errors
    console.log(JSON.stringify({ 
      error: error.message || 'Unknown error',
      status: 'error'
    }));
  }
});

// Function to process requests
function processRequest(request) {
  const { action, targets, params = "" } = request;
  
  if (action === "metadata") {
    // Return tool metadata and usage guidance for the LLM
    return {
      status: 'success',
      metadata: {
        name: "http_probe",
        description: "A tool for HTTP probing and reconnaissance using httpx",
        implementation: "ProjectDiscovery's httpx",
        guidance: `This tool helps analyze HTTP endpoints at scale. Before using:
1. First request 'help' to understand available options
2. Consider target scope carefully - use specific domains rather than broad ranges
3. Select appropriate parameters based on your objective (status checks, technology detection, etc.)
4. Always review results for false positives
5. For large target lists, consider using in batches
When providing results to the user, organize them in a meaningful way that highlights the most relevant information.`,
        examples: [
          {
            description: "Basic status check of domains",
            action: "run",
            targets: "example.com\ngoogle.com",
            params: "-status-code -title -follow-redirects"
          },
          {
            description: "Technology detection scan",
            action: "run", 
            targets: "github.com",
            params: "-tech-detect -status-code -title"
          }
        ]
      }
    };
  } else if (action === "help") {
    // Return httpx help documentation
    try {
      const helpOutput = execSync(`httpx -h`, { shell: '/bin/bash' });
      return {
        status: 'success',
        help: helpOutput.toString()
      };
    } catch (err) {
      throw new Error(`Failed to retrieve help: ${err.message}`);
    }
  } else if (action === "run") {
    if (!targets) {
      throw new Error('Missing required parameter: targets');
    }
    
    // Create temp files
    const inputFile = path.join(tmpDir, `${Date.now()}.txt`);
    const outputFile = path.join(tmpDir, `${Date.now()}.json`);
    
    // Write targets to file
    fs.writeFileSync(inputFile, targets);
    
    try {
      // Build command with params (always ensure JSON output)
      const jsonParam = params.includes('-j') || params.includes('-json') ? '' : '-json';
      const cmd = `cat ${inputFile} | httpx ${params} ${jsonParam} > ${outputFile}`;
      
      execSync(cmd, { shell: '/bin/bash' });
      
      // Read the JSON output
      const output = fs.readFileSync(outputFile, 'utf8');
      
      // Parse each line as JSON
      const results = output.trim().split('\n')
        .filter(line => line.trim() !== '')
        .map(line => JSON.parse(line));
      
      return {
        status: 'success',
        results: results
      };
    } catch (err) {
      throw new Error(`Failed to execute tool: ${err.message}`);
    } finally {
      // Clean up temp files
      try {
        fs.unlinkSync(inputFile);
        if (fs.existsSync(outputFile)) {
          fs.unlinkSync(outputFile);
        }
      } catch (e) {
        console.error('Failed to clean up temp files:', e);
      }
    }
  } else {
    throw new Error(`Unknown action: ${action}. Supported actions are 'metadata', 'help', and 'run'`);
  }
}
