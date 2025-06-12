# VIPER MCP Implementation

**Model Context Protocol integration for Claude Desktop**

## Overview

VIPER's MCP server provides 12 cybersecurity tools accessible through natural language in Claude Desktop. Built with Python 3.9+ compatibility and standards-compliant JSON-RPC over stdio.

## Architecture

```
Claude Desktop ←→ MCP Client ←→ VIPER MCP Server ←→ VIPER Core Functions
```

**Transport**: JSON-RPC over stdio
**Protocol**: MCP 2024-11-05 specification
**Runtime**: Async/await with asyncio

## Available Tools

### Core CVE Analysis
- `perform_live_cve_lookup` - Complete CVE analysis from all sources
- `get_comprehensive_cve_analysis` - Full analysis pipeline with AI

### Data Sources
- `get_nvd_cve_details` - NVD vulnerability database
- `get_epss_data_for_cve` - Exploitation probability scores
- `check_cve_in_cisa_kev` - CISA Known Exploited Vulnerabilities
- `get_live_msrc_info_for_cve` - Microsoft Security Response Center

### Threat Intelligence
- `search_public_exploits_for_cve` - GitHub and Exploit-DB search
- `get_gemini_cve_analysis` - AI-powered analysis (requires API key)
- `get_gemini_cve_priority` - AI priority assessment (requires API key)

### Risk Assessment
- `get_viper_risk_score` - Multi-factor risk scoring
- `get_viper_cve_alerts` - Security alert generation

### Database
- `save_cve_data_to_viperdb` - Store analysis results

## Implementation Details

### Server Structure
```python
class ViperMCPServer:
    async def run(self):
        # JSON-RPC stdio transport

    async def handle_initialize(self):
        # MCP capability negotiation

    async def handle_tools_list(self):
        # Return available tools with schemas

    async def handle_tools_call(self, name, arguments):
        # Execute requested tool
```

### Error Handling
- Graceful degradation when APIs unavailable
- Comprehensive error responses with proper codes
- Detailed logging for debugging

### Tool Registration
```python
def _register_tools(self):
    tools = [
        {
            "name": "perform_live_cve_lookup",
            "description": "Complete CVE analysis",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string"}
                },
                "required": ["cve_id"]
            }
        },
        # ... other tools
    ]
```

## Configuration

### Required
- Python 3.9+
- VIPER dependencies (see requirements.txt)

### Optional
- `GEMINI_API_KEY` - For AI analysis features
- `GITHUB_TOKEN` - Enhanced exploit search
- `NVD_API_KEY` - Higher rate limits

### Claude Desktop Setup
```json
{
  "mcpServers": {
    "ViperMCPServer": {
      "command": "/absolute/path/to/viper/run_mcp_clean.sh"
    }
  }
}
```

## Usage Examples

### Natural Language Queries
```
"Analyze CVE-2024-3400 with full Viper analysis"
"Find exploits for CVE-2023-44487 and calculate risk score"
"Check if CVE-2024-1234 is in CISA KEV catalog"
"Get comprehensive analysis and save to database"
```

### Response Format
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Analysis results..."
      }
    ]
  }
}
```

## Key Features

### Multi-Factor Risk Scoring
Combines:
- CVSS base score
- EPSS exploitation probability
- CISA KEV status
- Microsoft severity rating
- Public exploit availability
- Gemini AI assessment

### Alert Generation
7 alert types based on:
- High EPSS scores (>0.7)
- Critical CVSS + High EPSS combinations
- CISA KEV presence
- Keyword matches in descriptions
- Microsoft critical ratings
- Public exploit availability
- AI-assigned high priority

### Comprehensive CVE Data
Fetches and combines:
- NVD official vulnerability data
- EPSS exploitation probabilities
- CISA KEV catalog status
- Microsoft security bulletins
- Public exploit repositories
- AI analysis and prioritization

## Testing

### Validation Script
```bash
python -m src.mcp_server_demo
```

### Individual Tool Testing
```python
import asyncio
from src.mcp_server import get_viper_risk_score

result = asyncio.run(get_viper_risk_score({"cve_id": "CVE-2023-12345"}))
```

## Deployment

### Production Setup
- Use absolute paths in Claude Desktop config
- Set appropriate API keys
- Ensure `run_mcp_clean.sh` is executable
- Monitor logs for errors

### Troubleshooting
- Check Claude Desktop restart after config changes
- Verify file permissions
- Test individual tools for API connectivity
- Review logs for detailed error information

## Integration Benefits

- **Natural Language Interface**: No need to remember function names
- **Real-time Analysis**: Live CVE data from multiple sources
- **AI Enhancement**: Gemini-powered prioritization and analysis
- **Persistent Storage**: Save results to local database
- **Comprehensive Coverage**: 12 specialized cybersecurity tools
- **Standards Compliant**: Full MCP protocol implementation
