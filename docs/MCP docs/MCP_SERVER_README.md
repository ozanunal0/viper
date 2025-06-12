# VIPER MCP Server Setup

**Model Context Protocol server for Claude Desktop integration**

## Quick Setup

### 1. Configure Claude Desktop

Add to `~/.claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "ViperMCPServer": {
      "command": "/FULL/PATH/TO/YOUR/viper/run_mcp_clean.sh"
    }
  }
}
```

### 2. Set Gemini API Key (Optional)
```bash
export GEMINI_API_KEY="your-api-key-here"
```

### 3. Test Connection
```bash
python -m src.mcp_server_demo
```

## Available Tools

| Tool | Description | Requires API |
|------|-------------|--------------|
| `perform_live_cve_lookup` | Full CVE analysis from multiple sources | ⚠️ Partial |
| `get_nvd_cve_details` | NVD vulnerability data | ✅ No |
| `get_epss_data_for_cve` | Exploitation probability scores | ✅ No |
| `check_cve_in_cisa_kev` | CISA KEV catalog status | ✅ No |
| `search_public_exploits_for_cve` | GitHub/Exploit-DB search | ✅ No |
| `get_gemini_cve_priority` | AI priority assessment | ⚠️ Yes |
| `get_gemini_cve_analysis` | AI vulnerability analysis | ⚠️ Yes |
| `get_viper_risk_score` | Multi-factor risk scoring | ✅ No |
| `get_viper_cve_alerts` | Security alert generation | ✅ No |
| `get_comprehensive_cve_analysis` | Complete analysis pipeline | ⚠️ Partial |
| `save_cve_data_to_viperdb` | Database storage | ✅ No |
| `get_live_msrc_info_for_cve` | Microsoft security data | ✅ No |

## Usage Examples

**Natural language queries in Claude Desktop:**

```
"Analyze CVE-2024-3400 with full Viper analysis"
"Find public exploits for CVE-2023-44487"
"Check if CVE-2024-1234 is in CISA KEV catalog"
"Calculate risk score for CVE-2023-5678"
"Get comprehensive analysis for CVE-2024-0001"
```

## Troubleshooting

**Common Issues:**

- **Path Error**: Use absolute path in config
- **Permission Denied**: Make `run_mcp_clean.sh` executable
- **API Errors**: Check Gemini API key configuration
- **Connection Failed**: Restart Claude Desktop after config changes

**Test Individual Tools:**
```bash
python -c "
from src.mcp_server import get_viper_risk_score
import asyncio
result = asyncio.run(get_viper_risk_score({'cve_id': 'CVE-2023-12345'}))
print(result)
"
```

## Requirements

- Python 3.9+
- VIPER project dependencies
- Claude Desktop (for MCP integration)
- Gemini API key (optional, for AI features)
