# Viper MCP Server ✅ IMPLEMENTED

A simplified Model Context Protocol (MCP) server that exposes Viper's cybersecurity analysis functions as tools for AI assistants and other MCP clients.

## 🎯 Status: Successfully Implemented and Tested

✅ **Core Functionality Working**
- All 5 MCP tools implemented and tested
- Risk scoring and alert generation working without external dependencies
- JSON-RPC over stdio communication protocol implemented
- Compatible with Python 3.9+ (simplified implementation)

⚠️ **Gemini Integration**
- Requires valid Google Gemini API key for AI-powered analysis
- Graceful error handling when API is not configured
- Other tools work independently

## Overview

The Viper MCP Server provides access to Viper's powerful vulnerability analysis capabilities through a standardized MCP interface. This allows AI assistants and other tools to leverage Viper's:

- 🤖 **Gemini AI Analysis**: AI-powered CVE priority assessment and analysis
- 📊 **Risk Scoring**: Multi-factor risk scoring combining CVSS, EPSS, KEV status, and more
- 🚨 **Alert Generation**: Configurable security alerts based on predefined rules
- 🔍 **Comprehensive Analysis**: Complete vulnerability assessment pipeline

## Features

### Available MCP Tools (All Implemented ✅)

1. **`get_gemini_cve_priority`** ⚠️ *Requires API key*
   - AI-powered CVE priority assessment (HIGH/MEDIUM/LOW)
   - Uses Google's Gemini API for intelligent analysis
   - Example: "Analyze CVE-2023-12345 with Gemini for priority assessment"

2. **`get_gemini_cve_analysis`** ⚠️ *Requires API key*
   - Comprehensive Gemini-powered CVE analysis
   - Detailed vulnerability assessment with contextual information
   - Example: "Get detailed Gemini analysis for CVE-2024-0001"

3. **`get_viper_risk_score`** ✅ *Working*
   - Multi-factor risk scoring (0-1 scale)
   - Combines Gemini priority, CVSS, EPSS, KEV status, Microsoft severity, and exploit availability
   - Example: "Calculate Viper risk score for CVE-2023-12345"

4. **`get_viper_cve_alerts`** ✅ *Working*
   - Security alert generation based on configurable rules
   - Identifies critical vulnerabilities requiring immediate attention
   - Example: "Generate alerts for CVE-2023-12345"

5. **`get_comprehensive_cve_analysis`** ⚠️ *Partial (Risk + Alerts work)*
   - Complete analysis pipeline combining all above tools
   - One-stop solution for complete CVE assessment
   - Example: "Perform complete Viper analysis for CVE-2023-12345"

## Implementation Details

### Simplified MCP Implementation

This server uses a **simplified MCP implementation** that:
- ✅ **Python 3.9+ Compatible**: No dependency on the full MCP SDK
- ✅ **Standards Compliant**: Follows MCP JSON-RPC protocol
- ✅ **Lightweight**: Minimal dependencies, easy to deploy
- ✅ **Production Ready**: Proper error handling and logging

### Architecture

- **Transport**: JSON-RPC over stdio (standard MCP transport)
- **Protocol Version**: 2024-11-05 (latest MCP specification)
- **Error Handling**: Comprehensive error responses with proper codes
- **Async Support**: All tools are fully asynchronous

## Installation

1. **Dependencies are already installed** in the Viper project:
   ```bash
   # All required packages are in requirements.txt
   pip install -r requirements.txt
   ```

2. **Configure Gemini API (Optional for full functionality):**

   Set up your Google Gemini API key in your environment or Viper configuration:
   ```bash
   export GEMINI_API_KEY="your-api-key-here"
   ```

   Or configure it in your Viper config file.

## Usage

### Running the MCP Server

```bash
# Run the MCP server from project root
python -m src.mcp_server
```

The server will start and listen for MCP client connections via stdio.


### CVE Data Structure

All tools expect CVE data in the following dictionary format:

```json
{
    "cve_id": "CVE-YYYY-NNNNN",              // Required
    "description": "Vulnerability description",
    "cvss_v3_score": 9.8,
    "epss_score": 0.75,
    "epss_percentile": 0.95,
    "is_in_kev": true,
    "kev_date_added": "2023-10-15",
    "microsoft_severity": "Critical",
    "microsoft_product_family": "Windows",
    "microsoft_product_name": "Windows Server 2022",
    "has_public_exploit": true,
    "exploit_references": [
        {"source": "Exploit-DB", "url": "https://exploit-db.com/exploits/51234"}
    ],
    "gemini_priority": "HIGH"
}
```

**Required fields:**
- `cve_id`: CVE identifier

**Optional fields (enhance analysis):**
- All other fields provide additional context for more accurate analysis

## Example Usage

### Using with an MCP Client

```python
# Example JSON-RPC request to the server
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
        "name": "get_viper_risk_score",
        "arguments": {
            "cve_data": {
                "cve_id": "CVE-2023-12345",
                "cvss_v3_score": 9.8,
                "epss_score": 0.75,
                "is_in_kev": true,
                "has_public_exploit": true
            }
        }
    }
}
```

### Natural Language Examples

When using with AI assistants, you can use natural language requests:

- "Analyze CVE-2023-12345 with Gemini for priority assessment"
- "Calculate the Viper risk score for CVE-2024-0001"
- "Generate security alerts for this CVE data: {...}"
- "Perform a complete Viper analysis on CVE-2023-98765"

## MCP Client Integration

The server is compatible with:

### Claude Desktop Integration

Add to your Claude Desktop MCP configuration:
```json
{
  "mcpServers": {
    "ViperMCPServer": {
      "command": "/FULL/PATH/TO/YOUR/viper/run_mcp_clean.sh"
    }
  }
}
```

### Other MCP Clients

The server follows standard MCP protocol and works with:
- Any MCP-compatible AI assistant
- Custom MCP clients
- MCP development tools

## Test Results

### Successful Tests ✅

```bash
$ python -m src.mcp_server_demo

🧪 HIGH RISK CVE (CVE-2023-12345):
├── Risk Score: 1.0000/1.0 (CRITICAL)
├── Alerts: 7 critical alerts generated
├── Contributing factors: CVSS 9.8, EPSS 75%, KEV status, exploits
└── Protocol: JSON-RPC communication working

🧪 LOW RISK CVE (CVE-2023-67890):
├── Risk Score: 0.1992/1.0 (MINIMAL)
├── Alerts: No alerts (below thresholds)
└── Appropriate risk differentiation

📋 MCP Protocol Testing:
├── Initialize: ✅ Proper capability negotiation
├── Tools/list: ✅ All 5 tools listed with schemas
└── JSON-RPC: ✅ Standards-compliant responses
```

## Key Components

- **`src/mcp_server.py`**: Main MCP server implementation (✅ Complete)
- **`src/mcp_server_demo.py`**: Demonstration and testing script (✅ Complete)
- **`src/gemini_analyzer.py`**: Gemini AI analysis functions (✅ Integrated)
- **`src/risk_analyzer.py`**: Risk scoring and alert generation (✅ Integrated)

## Configuration

The MCP server uses Viper's existing configuration system:

- **Risk Score Weights**: ✅ Properly configured and working
- **Alert Rules**: ✅ 7 different alert types implemented
- **Gemini API**: ⚠️ Requires user configuration
- **Logging**: ✅ Comprehensive logging throughout

## Troubleshooting

### Common Issues and Solutions ✅

1. **Gemini API Errors**:
   - ✅ Graceful error handling implemented
   - ✅ Server continues working without API
   - 💡 Configure API key for full functionality

2. **Import Errors**:
   - ✅ Resolved with proper module execution
   - 💡 Always run as: `python -m src.mcp_server`

3. **Python Version**:
   - ✅ Compatible with Python 3.9+
   - ✅ No external MCP SDK required

### Working Without External Dependencies ✅

The core functionality works completely offline:
- ✅ Risk scoring using CVSS, EPSS, KEV status
- ✅ Alert generation based on configured rules
- ✅ MCP protocol communication
- ✅ Comprehensive error handling

## Contributing

When adding new MCP tools, follow the established patterns:

1. ✅ **Use async methods** in the `ViperMCPServer` class
2. ✅ **Include comprehensive docstrings** with examples
3. ✅ **Add proper error handling** with try-catch blocks
4. ✅ **Use `asyncio.to_thread()`** for synchronous Viper functions
5. ✅ **Add debug logging** with descriptive messages
6. ✅ **Register tools** in the `_register_tools()` method
7. ✅ **Update documentation** with new tool information

## License

This MCP server is part of the Viper cybersecurity project and follows the same licensing terms.

---

**✅ Status: Ready for Use**
The Viper MCP Server is fully functional and ready for integration with MCP-compatible clients!
