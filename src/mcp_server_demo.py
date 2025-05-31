"""
Demo script for Viper MCP Server (Simplified Implementation)

This script demonstrates how to use the MCP server tools with example CVE data.
It directly calls the server methods for demonstration purposes.
"""

import asyncio
import json

# Example CVE data for testing
EXAMPLE_CVE_DATA = {
    "cve_id": "CVE-2023-12345",
    "description": "Remote code execution vulnerability in popular web framework allowing attackers to execute arbitrary code",
    "cvss_v3_score": 9.8,
    "epss_score": 0.75,
    "epss_percentile": 0.95,
    "is_in_kev": True,
    "kev_date_added": "2023-10-15",
    "microsoft_severity": "Critical",
    "microsoft_product_family": "Windows",
    "microsoft_product_name": "Windows Server 2022",
    "has_public_exploit": True,
    "exploit_references": [
        {"source": "Exploit-DB", "url": "https://exploit-db.com/exploits/51234"},
        {"source": "GitHub", "url": "https://github.com/evil/poc"},
    ],
    "gemini_priority": "HIGH",
}

EXAMPLE_CVE_DATA_LOW_RISK = {
    "cve_id": "CVE-2023-67890",
    "description": "Information disclosure vulnerability in legacy library with limited impact",
    "cvss_v3_score": 3.1,
    "epss_score": 0.02,
    "epss_percentile": 0.15,
    "is_in_kev": False,
    "microsoft_severity": "Low",
    "has_public_exploit": False,
    "gemini_priority": "LOW",
}


async def demo_mcp_tools():
    """
    Demonstrates the MCP server tools with example data.
    This function imports and calls the server methods directly for demonstration.
    """
    print("=" * 70)
    print("VIPER MCP SERVER DEMONSTRATION (Simplified Implementation)")
    print("=" * 70)

    # Import the server class
    try:
        from .mcp_server import ViperMCPServer
    except ImportError:
        # If relative import fails, try absolute import
        import os
        import sys

        sys.path.append(os.path.dirname(__file__))
        from mcp_server import ViperMCPServer

    # Create server instance
    server = ViperMCPServer()

    print("\n📋 Available Tools:")
    for tool_name, tool_info in server.tools.items():
        print(f"• {tool_name}")
        print(f"  Description: {tool_info['description'][:80]}...")

    print("\n🧪 Testing with HIGH RISK CVE:")
    print(f"CVE: {EXAMPLE_CVE_DATA['cve_id']}")
    print(f"CVSS: {EXAMPLE_CVE_DATA['cvss_v3_score']}")
    print(f"EPSS: {EXAMPLE_CVE_DATA['epss_score']}")
    print(f"KEV Status: {EXAMPLE_CVE_DATA['is_in_kev']}")

    try:
        # Test 1: Risk Score Calculation (works without API)
        print("\n" + "=" * 50)
        print("1. RISK SCORE CALCULATION")
        print("=" * 50)
        risk_result = await server.get_viper_risk_score(EXAMPLE_CVE_DATA)
        print(risk_result)

        # Test 2: Alert Generation (works without API)
        print("\n" + "=" * 50)
        print("2. ALERT GENERATION")
        print("=" * 50)
        alerts_result = await server.get_viper_cve_alerts(EXAMPLE_CVE_DATA)
        print(alerts_result)

        # Test 3: Gemini Priority Analysis (requires API)
        print("\n" + "=" * 50)
        print("3. GEMINI PRIORITY ANALYSIS")
        print("=" * 50)
        try:
            priority_result = await server.get_gemini_cve_priority(EXAMPLE_CVE_DATA)
            print(priority_result)
        except Exception as e:
            print(f"❌ Gemini API not configured: {str(e)}")
            print("💡 This is expected if you haven't set up the Gemini API key.")

        # Test 4: Comprehensive Analysis (partial without API)
        print("\n" + "=" * 50)
        print("4. COMPREHENSIVE ANALYSIS (Risk + Alerts)")
        print("=" * 50)
        try:
            comprehensive_result = await server.get_comprehensive_cve_analysis(EXAMPLE_CVE_DATA)
            print(comprehensive_result)
        except Exception as e:
            print(f"❌ Error in comprehensive analysis: {str(e)}")
            print("💡 Some features require Gemini API configuration.")

    except Exception as e:
        print(f"❌ Error during HIGH RISK CVE testing: {str(e)}")

    print("\n\n🧪 Testing with LOW RISK CVE:")
    print(f"CVE: {EXAMPLE_CVE_DATA_LOW_RISK['cve_id']}")
    print(f"CVSS: {EXAMPLE_CVE_DATA_LOW_RISK['cvss_v3_score']}")
    print(f"EPSS: {EXAMPLE_CVE_DATA_LOW_RISK['epss_score']}")
    print(f"KEV Status: {EXAMPLE_CVE_DATA_LOW_RISK['is_in_kev']}")

    try:
        # Test with low risk CVE
        print("\n" + "=" * 50)
        print("5. LOW RISK CVE - RISK SCORE")
        print("=" * 50)
        low_risk_result = await server.get_viper_risk_score(EXAMPLE_CVE_DATA_LOW_RISK)
        print(low_risk_result)

        print("\n" + "=" * 50)
        print("6. LOW RISK CVE - ALERTS")
        print("=" * 50)
        low_alerts_result = await server.get_viper_cve_alerts(EXAMPLE_CVE_DATA_LOW_RISK)
        print(low_alerts_result)

    except Exception as e:
        print(f"❌ Error during LOW RISK CVE testing: {str(e)}")


def test_mcp_protocol():
    """Test the MCP protocol requests and responses."""
    print("\n" + "=" * 70)
    print("MCP PROTOCOL TESTING")
    print("=" * 70)

    try:
        from .mcp_server import ViperMCPServer
    except ImportError:
        import os
        import sys

        sys.path.append(os.path.dirname(__file__))
        from mcp_server import ViperMCPServer

    server = ViperMCPServer()

    # Test initialization request
    init_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0.0"},
        },
    }

    print("\n📤 Sending initialize request:")
    print(json.dumps(init_request, indent=2))

    # Process request (this would normally be async)
    import asyncio

    response = asyncio.run(server.handle_request(init_request))

    print("\n📥 Received response:")
    print(json.dumps(response, indent=2))

    # Test tools list request
    list_request = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}

    print("\n📤 Sending tools/list request:")
    print(json.dumps(list_request, indent=2))

    response = asyncio.run(server.handle_request(list_request))

    print("\n📥 Received response:")
    print(json.dumps(response, indent=2))


def print_usage_examples():
    """Print examples of how to use the MCP tools."""
    print("\n" + "=" * 70)
    print("MCP TOOL USAGE EXAMPLES")
    print("=" * 70)

    print(
        """
🔧 TOOL: get_gemini_cve_priority
Purpose: Get AI-powered priority assessment for a CVE
Example usage: "Analyze CVE-2023-12345 with Gemini for priority assessment"
Status: ⚠️  Requires Gemini API configuration

🔧 TOOL: get_gemini_cve_analysis
Purpose: Get comprehensive Gemini analysis of a CVE
Example usage: "Get detailed Gemini analysis for CVE-2024-0001"
Status: ⚠️  Requires Gemini API configuration

🔧 TOOL: get_viper_risk_score
Purpose: Calculate combined risk score using multiple factors
Example usage: "Calculate Viper risk score for CVE-2023-12345"
Status: ✅ Works without external dependencies

🔧 TOOL: get_viper_cve_alerts
Purpose: Generate security alerts based on configurable rules
Example usage: "Generate alerts for CVE-2023-12345"
Status: ✅ Works without external dependencies

🔧 TOOL: get_comprehensive_cve_analysis
Purpose: Run complete analysis suite (Gemini + Risk + Alerts)
Example usage: "Perform complete Viper analysis for CVE-2023-12345"
Status: ⚠️  Partial functionality without Gemini API

📋 REQUIRED CVE DATA STRUCTURE:
{
    "cve_id": "CVE-YYYY-NNNNN",              # Required
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
    "exploit_references": [...],
    "gemini_priority": "HIGH"
}

🚀 TO RUN THE MCP SERVER:
python -m src.mcp_server

📝 NOTES:
• This is a simplified MCP implementation compatible with Python 3.9+
• Risk scoring and alert generation work without external APIs
• Gemini analysis requires proper API key configuration
• The server uses JSON-RPC over stdio for MCP communication

🔗 MCP CLIENT INTEGRATION:
The server follows MCP protocol standards and can be integrated with:
• Claude Desktop
• MCP-compatible AI assistants
• Custom MCP clients
"""
    )


if __name__ == "__main__":
    print("🐍 Starting Viper MCP Server Demo (Simplified Implementation)...")

    # Print usage examples
    print_usage_examples()

    # Run the demo
    asyncio.run(demo_mcp_tools())

    # Test MCP protocol
    test_mcp_protocol()

    print("\n✅ Demo completed!")
    print("\nTo run the actual MCP server, use:")
    print("python -m src.mcp_server")
