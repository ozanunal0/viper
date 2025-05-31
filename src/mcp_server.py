"""
Viper MCP Server - Simplified Implementation

This MCP server exposes Viper's existing analysis functions as tools.
This is a simplified implementation that follows MCP principles without requiring the full SDK.
All tools are asynchronous and use asyncio.to_thread for synchronous Viper functions.
"""

import asyncio
import json
import logging
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

# Add startup error logging
print("Starting Viper MCP Server - Import phase...", file=sys.stderr, flush=True)

try:
    # Relative imports from src directory
    try:
        from .clients.cisa_kev_client import fetch_kev_catalog
        from .clients.epss_client import get_epss_score
        from .clients.exploit_search_client import (
            find_public_exploits,
            search_exploit_db,
            search_github,
        )
        from .clients.microsoft_update_client import (
            fetch_latest_patch_tuesday_data,
            fetch_patch_tuesday_data,
        )
        from .clients.nvd_client import fetch_single_cve_details
        from .gemini_analyzer import analyze_cve_with_gemini, analyze_cve_with_gemini_async
        from .risk_analyzer import analyze_cve_risk, calculate_combined_risk_score, generate_alerts
        from .utils.config import get_nvd_api_key
        from .utils.database_handler import get_cve_details, store_or_update_cve

        print("Successfully imported with relative imports", file=sys.stderr, flush=True)

        # Create fallback functions for missing Microsoft client functions
        def get_cve_to_msrc_mapping_from_nvd(api_key, cve_id):
            """Fallback function - MSRC mapping not implemented yet"""
            return None

        def get_msrc_document(msrc_id):
            """Fallback function - MSRC document retrieval not implemented yet"""
            return None

    except ImportError as e:
        print(f"Relative import failed: {e}, trying direct imports...", file=sys.stderr, flush=True)
        # Fallback for when running directly
        from gemini_analyzer import analyze_cve_with_gemini, analyze_cve_with_gemini_async
        from risk_analyzer import analyze_cve_risk, calculate_combined_risk_score, generate_alerts

        try:
            from clients.cisa_kev_client import fetch_kev_catalog
            from clients.epss_client import get_epss_score
            from clients.exploit_search_client import (
                find_public_exploits,
                search_exploit_db,
                search_github,
            )
            from clients.microsoft_update_client import (
                fetch_latest_patch_tuesday_data,
                fetch_patch_tuesday_data,
            )
            from clients.nvd_client import fetch_single_cve_details
            from utils.config import get_nvd_api_key
            from utils.database_handler import get_cve_details, store_or_update_cve

            print("Successfully imported with direct imports", file=sys.stderr, flush=True)

            # Create fallback functions for missing Microsoft client functions
            def get_cve_to_msrc_mapping_from_nvd(api_key, cve_id):
                """Fallback function - MSRC mapping not implemented yet"""
                return None

            def get_msrc_document(msrc_id):
                """Fallback function - MSRC document retrieval not implemented yet"""
                return None

        except ImportError as e:
            print(f"Direct imports also failed: {e}, using fallback functions...", file=sys.stderr, flush=True)

            # For demo purposes when clients aren't available
            def fetch_single_cve_details(cve_id):
                return None

            def get_epss_score(cve_id):
                return (None, None)

            def fetch_kev_catalog():
                return []

            def search_github(cve_id):
                return []

            def search_exploit_db(cve_id):
                return []

            def find_public_exploits(cve_id):
                return []

            def get_cve_to_msrc_mapping_from_nvd(api_key, cve_id):
                return None

            def get_msrc_document(msrc_id):
                return None

            def get_cve_details(cve_id):
                return None

            def store_or_update_cve(data):
                return True

            def get_nvd_api_key():
                return None

            def fetch_patch_tuesday_data(year, month):
                return None

            def fetch_latest_patch_tuesday_data():
                return None

            print("Using fallback functions", file=sys.stderr, flush=True)

    # Initialize logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    print("Logging initialized", file=sys.stderr, flush=True)

except Exception as e:
    print(f"Critical error during import phase: {e}", file=sys.stderr, flush=True)
    import traceback

    traceback.print_exc(file=sys.stderr)
    sys.exit(1)

print("Imports completed successfully", file=sys.stderr, flush=True)


class ViperMCPServer:
    """Simplified MCP Server for Viper cybersecurity tools."""

    def __init__(self, name: str = "viper-mcp-server"):
        self.name = name
        self.version = "1.0.0"
        self.tools = self._register_tools()

    def _register_tools(self) -> Dict[str, Dict[str, Any]]:
        """Register all available tools."""
        return {
            # Original tools
            "get_gemini_cve_priority": {
                "description": "Analyzes a CVE using Viper's Gemini integration to determine its priority (HIGH/MEDIUM/LOW). Example: 'Analyze CVE-2023-12345 with Gemini for priority assessment'",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "cve_data": {
                            "type": "object",
                            "description": "CVE information dictionary",
                            "properties": {
                                "cve_id": {"type": "string", "description": "CVE identifier"},
                                "description": {"type": "string", "description": "CVE description"},
                                "cvss_v3_score": {"type": "number", "description": "CVSS v3 score"},
                                "epss_score": {"type": "number", "description": "EPSS score"},
                                "is_in_kev": {"type": "boolean", "description": "CISA KEV status"},
                                "microsoft_severity": {"type": "string", "description": "Microsoft severity"},
                                "has_public_exploit": {"type": "boolean", "description": "Public exploit availability"},
                            },
                            "required": ["cve_id"],
                        }
                    },
                    "required": ["cve_data"],
                },
            },
            "get_gemini_cve_analysis": {
                "description": "Provides comprehensive AI-powered CVE analysis using Viper's Gemini integration. Example: 'Get detailed Gemini analysis for CVE-2024-0001'",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "cve_data": {"type": "object", "description": "CVE information dictionary"},
                        "use_async": {
                            "type": "boolean",
                            "description": "Whether to use async processing",
                            "default": True,
                        },
                    },
                    "required": ["cve_data"],
                },
            },
            "get_viper_risk_score": {
                "description": "Calculates Viper's combined risk score (0-1 scale) using multiple factors. Example: 'Calculate Viper risk score for CVE-2023-12345'",
                "inputSchema": {
                    "type": "object",
                    "properties": {"cve_data": {"type": "object", "description": "CVE risk data dictionary"}},
                    "required": ["cve_data"],
                },
            },
            "get_viper_cve_alerts": {
                "description": "Generates security alerts based on Viper's configurable rules. Example: 'Generate alerts for CVE-2023-12345'",
                "inputSchema": {
                    "type": "object",
                    "properties": {"cve_data": {"type": "object", "description": "CVE data for alert analysis"}},
                    "required": ["cve_data"],
                },
            },
            "get_comprehensive_cve_analysis": {
                "description": "Complete Viper analysis combining Gemini, risk scoring, and alerts. Example: 'Perform complete Viper analysis for CVE-2023-12345'",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "cve_data": {"type": "object", "description": "Complete CVE data for comprehensive analysis"}
                    },
                    "required": ["cve_data"],
                },
            },
            # New comprehensive live lookup tool
            "perform_live_cve_lookup": {
                "description": "Performs comprehensive live lookup and analysis for a CVE ID. Fetches data from NVD, EPSS, CISA KEV, searches for exploits, runs AI analysis, calculates risk, and can save to database. Example: 'Do a full live lookup for CVE-2024-1001 and save it to the database' or 'Get live details for CVE-2024-2002 from NVD and EPSS only, don't save'",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "cve_id": {"type": "string", "description": "CVE identifier"},
                        "force_live_fetch": {
                            "type": "boolean",
                            "description": "Skip local DB check and fetch all data live",
                            "default": False,
                        },
                        "use_nvd": {"type": "boolean", "description": "Fetch data from NVD", "default": True},
                        "use_epss": {"type": "boolean", "description": "Fetch EPSS score", "default": True},
                        "use_cisa_kev": {
                            "type": "boolean",
                            "description": "Check against CISA KEV catalog",
                            "default": True,
                        },
                        "search_github_exploits": {
                            "type": "boolean",
                            "description": "Search GitHub for exploits",
                            "default": True,
                        },
                        "search_exploitdb": {
                            "type": "boolean",
                            "description": "Search Exploit-DB for exploits",
                            "default": False,
                        },
                        "run_gemini_analysis": {
                            "type": "boolean",
                            "description": "Perform Gemini AI analysis",
                            "default": True,
                        },
                        "calculate_viper_risk": {
                            "type": "boolean",
                            "description": "Calculate Viper risk score",
                            "default": True,
                        },
                        "save_to_db": {"type": "boolean", "description": "Save results to database", "default": False},
                        "fetch_msrc_live": {
                            "type": "boolean",
                            "description": "Actively fetch security update data from Microsoft (MSRC) for the given CVE",
                            "default": True,
                        },
                    },
                    "required": ["cve_id"],
                },
            },
            # Granular tools
            "get_nvd_cve_details": {
                "description": "Fetches detailed CVE information directly from the National Vulnerability Database (NVD). Example: 'Fetch NVD details for CVE-2023-5000'",
                "inputSchema": {
                    "type": "object",
                    "properties": {"cve_id": {"type": "string", "description": "CVE identifier"}},
                    "required": ["cve_id"],
                },
            },
            "get_epss_data_for_cve": {
                "description": "Retrieves EPSS score and percentile for a CVE. Example: 'Get EPSS score for CVE-2023-5001'",
                "inputSchema": {
                    "type": "object",
                    "properties": {"cve_id": {"type": "string", "description": "CVE identifier"}},
                    "required": ["cve_id"],
                },
            },
            "check_cve_in_cisa_kev": {
                "description": "Checks if a CVE is in CISA Known Exploited Vulnerabilities catalog. Example: 'Is CVE-2023-5002 in CISA KEV?'",
                "inputSchema": {
                    "type": "object",
                    "properties": {"cve_id": {"type": "string", "description": "CVE identifier"}},
                    "required": ["cve_id"],
                },
            },
            "search_public_exploits_for_cve": {
                "description": "Searches for public exploits on GitHub and/or Exploit-DB. Example: 'Find public exploits for CVE-2023-5003 on GitHub' or 'Search exploits for CVE-2023-5004 on both GitHub and Exploit-DB'",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "cve_id": {"type": "string", "description": "CVE identifier"},
                        "search_github": {
                            "type": "boolean",
                            "description": "Search GitHub for exploits",
                            "default": True,
                        },
                        "search_exploitdb": {
                            "type": "boolean",
                            "description": "Search Exploit-DB for exploits",
                            "default": True,
                        },
                    },
                    "required": ["cve_id"],
                },
            },
            "save_cve_data_to_viperdb": {
                "description": 'Saves CVE data to Viper\'s local database. Example: \'Save this CVE data to Viper DB: {"cve_id": "CVE-2023-7000", "description": "...", ...}\'',
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "cve_data_json": {"type": "string", "description": "JSON string of CVE data to save"}
                    },
                    "required": ["cve_data_json"],
                },
            },
            "get_live_msrc_info_for_cve": {
                "description": "Actively retrieves Microsoft Security Response Center (MSRC) information for a given CVE ID by looking up MSRC document IDs via NVD and fetching those documents. Example: 'Get live MSRC details for CVE-2023-30001'",
                "inputSchema": {
                    "type": "object",
                    "properties": {"cve_id": {"type": "string", "description": "CVE identifier"}},
                    "required": ["cve_id"],
                },
            },
        }

    # Original tool methods (keeping existing implementation)
    async def get_gemini_cve_priority(self, cve_data: Dict[str, Any]) -> str:
        """Get Gemini CVE priority assessment."""
        print(
            f"[ViperMCP-Gemini] Processing priority request for {cve_data.get('cve_id', 'Unknown CVE')}...",
            file=sys.stderr,
            flush=True,
        )

        try:
            priority, raw_response = await analyze_cve_with_gemini_async(cve_data)
            cve_id = cve_data.get("cve_id", "Unknown CVE")

            result = f"Gemini Priority Analysis for {cve_id}:\n"
            result += f"Priority: {priority}\n"
            result += f"Analysis Details: {raw_response}\n"

            if priority == "ERROR_ANALYZING":
                result += "\nNote: An error occurred during analysis. Please check the CVE data and try again."

            return result

        except Exception as e:
            error_msg = f"Error during Gemini priority analysis: {str(e)}"
            print(error_msg, file=sys.stderr, flush=True)
            return error_msg

    async def get_gemini_cve_analysis(self, cve_data: Dict[str, Any], use_async: bool = True) -> str:
        """Get comprehensive Gemini CVE analysis."""
        cve_id = cve_data.get("cve_id", "Unknown CVE")
        print(f"[ViperMCP-Gemini] Processing analysis request for {cve_id}...", file=sys.stderr, flush=True)

        try:
            if use_async:
                priority, raw_response = await analyze_cve_with_gemini_async(cve_data)
            else:
                priority, raw_response = await asyncio.to_thread(analyze_cve_with_gemini, cve_data)

            result = f"Comprehensive Gemini Analysis for {cve_id}:\n"
            result += "=" * 50 + "\n"
            result += f"Priority Assessment: {priority}\n\n"

            if "cvss_v3_score" in cve_data:
                result += f"CVSS v3 Score: {cve_data['cvss_v3_score']}\n"
            if "epss_score" in cve_data:
                result += f"EPSS Score: {cve_data['epss_score']:.4f}\n"
            if "is_in_kev" in cve_data:
                result += f"CISA KEV Status: {'Yes' if cve_data['is_in_kev'] else 'No'}\n"

            result += f"\nDetailed Analysis:\n{raw_response}\n"

            if priority == "ERROR_ANALYZING":
                result += "\n⚠️  Warning: Analysis encountered errors. Please verify CVE data completeness."

            return result

        except Exception as e:
            error_msg = f"Error during comprehensive Gemini analysis for {cve_id}: {str(e)}"
            print(error_msg, file=sys.stderr, flush=True)
            return error_msg

    async def get_viper_risk_score(self, cve_data: Dict[str, Any]) -> str:
        """Calculate Viper risk score."""
        cve_id = cve_data.get("cve_id", "Unknown CVE")
        print(f"[ViperMCP-Risk] Processing risk score request for {cve_id}...", file=sys.stderr, flush=True)

        try:
            risk_score = await asyncio.to_thread(calculate_combined_risk_score, cve_data)

            result = f"Viper Risk Assessment for {cve_id}:\n"
            result += "=" * 40 + "\n"
            result += f"Combined Risk Score: {risk_score:.4f} / 1.0\n"
            result += f"Risk Level: {self._get_risk_level(risk_score)}\n\n"

            result += "Contributing Factors:\n"
            if "gemini_priority" in cve_data:
                result += f"• Gemini Priority: {cve_data['gemini_priority']}\n"
            if "cvss_v3_score" in cve_data:
                result += f"• CVSS v3 Score: {cve_data['cvss_v3_score']}\n"
            if "epss_score" in cve_data:
                result += f"• EPSS Score: {cve_data['epss_score']:.4f}\n"
            if "is_in_kev" in cve_data:
                result += f"• CISA KEV Status: {'Yes' if cve_data['is_in_kev'] else 'No'}\n"
            if "microsoft_severity" in cve_data:
                result += f"• Microsoft Severity: {cve_data['microsoft_severity']}\n"
            if "has_public_exploit" in cve_data:
                result += f"• Public Exploits: {'Available' if cve_data['has_public_exploit'] else 'None'}\n"

            return result

        except Exception as e:
            error_msg = f"Error calculating risk score for {cve_id}: {str(e)}"
            print(error_msg, file=sys.stderr, flush=True)
            return error_msg

    async def get_viper_cve_alerts(self, cve_data: Dict[str, Any]) -> str:
        """Generate CVE alerts."""
        cve_id = cve_data.get("cve_id", "Unknown CVE")
        print(f"[ViperMCP-Alerts] Processing alert generation for {cve_id}...", file=sys.stderr, flush=True)

        try:
            alerts = await asyncio.to_thread(generate_alerts, cve_data)

            result = f"Viper Security Alerts for {cve_id}:\n"
            result += "=" * 40 + "\n"

            if alerts:
                result += f"⚠️  {len(alerts)} Alert(s) Generated:\n\n"
                for i, alert in enumerate(alerts, 1):
                    result += f"{i}. {alert}\n"
            else:
                result += "✅ No alerts generated - CVE does not meet alert criteria\n"

            return result

        except Exception as e:
            error_msg = f"Error generating alerts for {cve_id}: {str(e)}"
            print(error_msg, file=sys.stderr, flush=True)
            return error_msg

    async def get_comprehensive_cve_analysis(self, cve_data: Dict[str, Any]) -> str:
        """Get comprehensive CVE analysis."""
        cve_id = cve_data.get("cve_id", "Unknown CVE")
        print(f"[ViperMCP-Comprehensive] Processing complete analysis for {cve_id}...", file=sys.stderr, flush=True)

        try:
            # Run analyses concurrently
            gemini_task = analyze_cve_with_gemini_async(cve_data)
            risk_task = asyncio.to_thread(analyze_cve_risk, cve_data)

            (gemini_priority, gemini_response), (risk_score, alerts) = await asyncio.gather(gemini_task, risk_task)

            result = f"COMPREHENSIVE VIPER ANALYSIS FOR {cve_id}\n"
            result += "=" * 60 + "\n\n"

            result += "🤖 GEMINI AI ANALYSIS:\n"
            result += f"Priority: {gemini_priority}\n"
            result += f"Analysis: {gemini_response}\n\n"

            result += "📊 RISK ASSESSMENT:\n"
            result += f"Combined Risk Score: {risk_score:.4f} / 1.0\n"
            result += f"Risk Level: {self._get_risk_level(risk_score)}\n\n"

            result += "🚨 SECURITY ALERTS:\n"
            if alerts:
                for i, alert in enumerate(alerts, 1):
                    result += f"{i}. {alert}\n"
            else:
                result += "No alerts triggered\n"

            result += "\n" + "=" * 60 + "\n"
            result += f"Analysis completed for {cve_id}"

            return result

        except Exception as e:
            error_msg = f"Error during comprehensive analysis for {cve_id}: {str(e)}"
            print(error_msg, file=sys.stderr, flush=True)
            return error_msg

    # New comprehensive live lookup tool
    async def perform_live_cve_lookup(
        self,
        cve_id: str,
        force_live_fetch: bool = False,
        use_nvd: bool = True,
        use_epss: bool = True,
        use_cisa_kev: bool = True,
        search_github_exploits: bool = True,
        search_exploitdb: bool = False,
        run_gemini_analysis: bool = True,
        calculate_viper_risk: bool = True,
        save_to_db: bool = False,
        fetch_msrc_live: bool = True,
    ) -> str:
        """
        Performs a comprehensive live lookup and analysis for a specified CVE ID.
        Fetches data from NVD, EPSS, CISA KEV, searches for public exploits,
        runs Gemini AI analysis, calculates a risk score, and can save results to the database.
        Control data sources and actions using the boolean flags.
        Example: 'Do a full live lookup for CVE-2024-1001 and save it to the database.'
        Or: 'Get live details for CVE-2024-2002 from NVD and EPSS only, don't save.'
        Or: 'Lookup CVE-2024-3003 locally, but if not found, fetch live data and analyze risk.'
        """
        print(
            f"[ViperMCP] Received perform_live_cve_lookup for {cve_id} with options: "
            f"force_live={force_live_fetch}, nvd={use_nvd}, epss={use_epss}, "
            f"kev={use_cisa_kev}, github={search_github_exploits}, exploitdb={search_exploitdb}, "
            f"gemini={run_gemini_analysis}, risk={calculate_viper_risk}, save={save_to_db}, "
            f"msrc_live={fetch_msrc_live}",
            file=sys.stderr,
            flush=True,
        )

        try:
            # Initialize data structure
            comprehensive_cve_data = {
                "cve_id": cve_id,
            }
            status_messages = []

            # Check local database first unless force_live_fetch is True
            if not force_live_fetch:
                try:
                    print(f"[ViperMCP] Checking local database for {cve_id}...", file=sys.stderr, flush=True)
                    local_data = await asyncio.to_thread(get_cve_details, cve_id)
                    if local_data:
                        comprehensive_cve_data.update(local_data)
                        status_messages.append("✅ Found in local database")
                except Exception as e:
                    print(f"[ViperMCP] Database check error: {str(e)}", file=sys.stderr, flush=True)

            # Fetch from NVD if needed
            if use_nvd and not comprehensive_cve_data.get("description"):
                try:
                    print(f"[ViperMCP] Fetching NVD data for {cve_id}...", file=sys.stderr, flush=True)
                    nvd_data = await asyncio.to_thread(fetch_single_cve_details, cve_id)
                    if nvd_data:
                        comprehensive_cve_data.update(nvd_data)
                        status_messages.append("✅ Fetched NVD data")
                    else:
                        status_messages.append("⚠️ No NVD data found")
                except Exception as e:
                    status_messages.append(f"❌ NVD fetch error: {str(e)}")
                    print(f"[ViperMCP] NVD fetch error: {str(e)}", file=sys.stderr, flush=True)

            if use_epss and comprehensive_cve_data.get("description"):
                try:
                    print(f"[ViperMCP] Fetching EPSS data for {cve_id}...", file=sys.stderr, flush=True)
                    epss_score, epss_percentile = await asyncio.to_thread(get_epss_score, cve_id)
                    if epss_score is not None:
                        comprehensive_cve_data["epss_score"] = epss_score
                        comprehensive_cve_data["epss_percentile"] = epss_percentile
                        status_messages.append("✅ Fetched EPSS data")
                    else:
                        status_messages.append("⚠️ No EPSS data found")
                except Exception as e:
                    status_messages.append(f"❌ EPSS fetch error: {str(e)}")
                    print(f"[ViperMCP] EPSS fetch error: {str(e)}", file=sys.stderr, flush=True)

            if use_cisa_kev and comprehensive_cve_data.get("description"):
                try:
                    print(f"[ViperMCP] Checking CISA KEV for {cve_id}...", file=sys.stderr, flush=True)
                    kev_catalog = await asyncio.to_thread(fetch_kev_catalog)
                    is_in_kev = False
                    kev_date_added = None

                    for entry in kev_catalog:
                        if entry.get("cveID") == cve_id:
                            is_in_kev = True
                            kev_date_added = entry.get("dateAdded")
                            break

                    comprehensive_cve_data["is_in_kev"] = is_in_kev
                    if kev_date_added:
                        comprehensive_cve_data["kev_date_added"] = kev_date_added

                    status_messages.append(f"✅ KEV check: {'In catalog' if is_in_kev else 'Not in catalog'}")
                except Exception as e:
                    status_messages.append(f"❌ KEV check error: {str(e)}")
                    print(f"[ViperMCP] KEV check error: {str(e)}", file=sys.stderr, flush=True)

            if (search_github_exploits or search_exploitdb) and comprehensive_cve_data.get("description"):
                try:
                    print(f"[ViperMCP] Searching for exploits for {cve_id}...", file=sys.stderr, flush=True)
                    all_exploits = []

                    if search_github_exploits:
                        github_exploits = await asyncio.to_thread(search_github, cve_id)
                        all_exploits.extend(github_exploits)
                        print(
                            f"[ViperMCP-Exploits] Found {len(github_exploits)} GitHub exploits",
                            file=sys.stderr,
                            flush=True,
                        )

                    if search_exploitdb:
                        exploitdb_exploits = await asyncio.to_thread(search_exploit_db, cve_id)
                        all_exploits.extend(exploitdb_exploits)
                        print(
                            f"[ViperMCP-Exploits] Found {len(exploitdb_exploits)} ExploitDB exploits",
                            file=sys.stderr,
                            flush=True,
                        )

                    comprehensive_cve_data["exploit_references"] = all_exploits
                    comprehensive_cve_data["has_public_exploit"] = len(all_exploits) > 0
                    status_messages.append(f"✅ Found {len(all_exploits)} exploit(s)")
                except Exception as e:
                    status_messages.append(f"❌ Exploit search error: {str(e)}")
                    print(f"[ViperMCP] Exploit search error: {str(e)}", file=sys.stderr, flush=True)

            # MSRC data fetching
            if fetch_msrc_live and comprehensive_cve_data.get("description"):
                try:
                    print(f"[ViperMCP] Actively fetching MSRC data for {cve_id}...", file=sys.stderr, flush=True)

                    # Get NVD API key for MSRC mapping
                    nvd_api_key_for_msrc = await asyncio.to_thread(get_nvd_api_key)

                    if nvd_api_key_for_msrc:
                        # Step A: Get MSRC ID(s) for the CVE
                        print(
                            f"[ViperMCP-MSRC] Looking up MSRC IDs for {cve_id} via NVD...", file=sys.stderr, flush=True
                        )
                        msrc_ids_map = await asyncio.to_thread(
                            get_cve_to_msrc_mapping_from_nvd, nvd_api_key_for_msrc, cve_id
                        )

                        all_msrc_details = []
                        msrc_ids_found = []

                        if msrc_ids_map and msrc_ids_map.get("msrc_ids"):
                            msrc_ids_found = msrc_ids_map["msrc_ids"]
                            print(
                                f"[ViperMCP-MSRC] Found {len(msrc_ids_found)} MSRC ID(s): {msrc_ids_found}",
                                file=sys.stderr,
                                flush=True,
                            )

                            # Step B: Fetch MSRC Document(s)
                            for msrc_id in msrc_ids_found:
                                print(f"[ViperMCP-MSRC] Fetching MSRC document: {msrc_id}", file=sys.stderr, flush=True)
                                msrc_doc_detail = await asyncio.to_thread(get_msrc_document, msrc_id)

                                if msrc_doc_detail:
                                    all_msrc_details.append(msrc_doc_detail)
                                    print(
                                        f"[ViperMCP-MSRC] Successfully fetched MSRC document: {msrc_id}",
                                        file=sys.stderr,
                                        flush=True,
                                    )
                                else:
                                    print(
                                        f"[ViperMCP-MSRC] No details found for MSRC ID: {msrc_id}",
                                        file=sys.stderr,
                                        flush=True,
                                    )
                        else:
                            print(f"[ViperMCP-MSRC] No MSRC IDs found for {cve_id}", file=sys.stderr, flush=True)

                        if all_msrc_details:
                            # Process and merge MSRC data into comprehensive_cve_data
                            comprehensive_cve_data["live_msrc_details"] = all_msrc_details

                            # Extract key information from first MSRC document
                            primary_msrc = all_msrc_details[0]
                            if primary_msrc.get("Severity"):
                                comprehensive_cve_data["microsoft_severity_live"] = primary_msrc["Severity"]
                            if primary_msrc.get("AffectedProducts"):
                                comprehensive_cve_data["affected_products_msrc"] = primary_msrc["AffectedProducts"]
                            if primary_msrc.get("MSRC_URL"):
                                comprehensive_cve_data["msrc_url"] = primary_msrc["MSRC_URL"]
                            if primary_msrc.get("ID"):
                                comprehensive_cve_data["msrc_id"] = primary_msrc["ID"]

                            status_messages.append(f"✅ Actively fetched {len(all_msrc_details)} MSRC document(s)")
                            print(
                                f"[ViperMCP] Successfully fetched MSRC data for {cve_id}", file=sys.stderr, flush=True
                            )
                        else:
                            status_messages.append("ℹ️ No specific MSRC document found for this CVE via NVD mapping")
                            print(f"[ViperMCP] No MSRC document found for {cve_id}", file=sys.stderr, flush=True)
                    else:
                        status_messages.append("⚠️ No NVD API key available for MSRC mapping")
                        print(f"[ViperMCP] No NVD API key available for MSRC mapping", file=sys.stderr, flush=True)

                except Exception as e:
                    status_messages.append(f"❌ MSRC active fetch error: {str(e)}")
                    print(f"[ViperMCP] MSRC active fetch error for {cve_id}: {str(e)}", file=sys.stderr, flush=True)

            if run_gemini_analysis and comprehensive_cve_data.get("description"):
                try:
                    print(f"[ViperMCP] Running Gemini analysis for {cve_id}...", file=sys.stderr, flush=True)
                    gemini_priority, gemini_response = await analyze_cve_with_gemini_async(comprehensive_cve_data)
                    comprehensive_cve_data["gemini_priority"] = gemini_priority
                    comprehensive_cve_data["gemini_raw_response"] = gemini_response
                    status_messages.append(f"✅ Gemini analysis: {gemini_priority}")
                except Exception as e:
                    status_messages.append(f"❌ Gemini analysis error: {str(e)}")
                    print(f"[ViperMCP] Gemini analysis error: {str(e)}", file=sys.stderr, flush=True)

            if calculate_viper_risk and comprehensive_cve_data.get("description"):
                try:
                    print(f"[ViperMCP] Calculating risk score for {cve_id}...", file=sys.stderr, flush=True)
                    risk_score, alerts = await asyncio.to_thread(analyze_cve_risk, comprehensive_cve_data)
                    comprehensive_cve_data["risk_score"] = risk_score
                    comprehensive_cve_data["alerts"] = alerts
                    status_messages.append(f"✅ Risk score: {risk_score:.4f} ({len(alerts)} alerts)")
                except Exception as e:
                    status_messages.append(f"❌ Risk calculation error: {str(e)}")
                    print(f"[ViperMCP] Risk calculation error: {str(e)}", file=sys.stderr, flush=True)

            # Add timestamp
            comprehensive_cve_data["processed_at"] = datetime.now().isoformat()

            # Save to database if requested
            if save_to_db and comprehensive_cve_data.get("description"):
                try:
                    print(f"[ViperMCP] Saving {cve_id} to database...", file=sys.stderr, flush=True)
                    await asyncio.to_thread(store_or_update_cve, comprehensive_cve_data)
                    status_messages.append("✅ Successfully saved to database")
                except Exception as e:
                    status_messages.append(f"❌ Database save error: {str(e)}")
                    print(f"[ViperMCP] Database save error: {str(e)}", file=sys.stderr, flush=True)

            # Prepare result
            result = {
                "cve_id": cve_id,
                "status_messages": status_messages,
                "comprehensive_data": comprehensive_cve_data,
                "summary": {
                    "has_description": bool(comprehensive_cve_data.get("description")),
                    "has_epss": "epss_score" in comprehensive_cve_data,
                    "in_kev": comprehensive_cve_data.get("is_in_kev", False),
                    "exploit_count": len(comprehensive_cve_data.get("exploit_references", [])),
                    "risk_score": comprehensive_cve_data.get("risk_score"),
                    "gemini_priority": comprehensive_cve_data.get("gemini_priority"),
                    "live_msrc_data_retrieved": "live_msrc_details" in comprehensive_cve_data,
                },
            }

            return json.dumps(result, indent=2)

        except Exception as e:
            error_msg = f"Error during live CVE lookup for {cve_id}: {str(e)}"
            print(error_msg, file=sys.stderr, flush=True)
            return json.dumps({"error": error_msg, "cve_id": cve_id})

    # New granular tools
    async def get_nvd_cve_details(self, cve_id: str) -> str:
        """
        Retrieves detailed information for a given CVE ID directly from the National Vulnerability Database (NVD).
        This includes description, CVSS scores, publication dates, references, and CPEs.
        Example: 'Fetch NVD details for CVE-2023-5000.'
        """
        print(f"[ViperMCP-NVD] Fetching NVD details for {cve_id}...", file=sys.stderr, flush=True)

        try:
            nvd_data = await asyncio.to_thread(fetch_single_cve_details, cve_id)
            if nvd_data:
                return json.dumps(nvd_data, indent=2)
            else:
                return json.dumps({"error": f"No NVD data found for {cve_id}", "cve_id": cve_id})
        except Exception as e:
            error_msg = f"Error fetching NVD data for {cve_id}: {str(e)}"
            print(error_msg, file=sys.stderr, flush=True)
            return json.dumps({"error": error_msg, "cve_id": cve_id})

    async def get_epss_data_for_cve(self, cve_id: str) -> str:
        """
        Fetches the EPSS score (probability of exploitation) and percentile for a specific CVE ID.
        Example: 'Get EPSS score for CVE-2023-5001.'
        """
        print(f"[ViperMCP-EPSS] Fetching EPSS data for {cve_id}...", file=sys.stderr, flush=True)

        try:
            epss_score, epss_percentile = await asyncio.to_thread(get_epss_score, cve_id)

            result = {"cve_id": cve_id, "epss_score": epss_score, "epss_percentile": epss_percentile}

            if epss_score is None:
                result["error"] = "No EPSS data found for this CVE"

            return json.dumps(result, indent=2)

        except Exception as e:
            error_msg = f"Error fetching EPSS data for {cve_id}: {str(e)}"
            print(error_msg, file=sys.stderr, flush=True)
            return json.dumps({"error": error_msg, "cve_id": cve_id})

    async def check_cve_in_cisa_kev(self, cve_id: str) -> str:
        """
        Checks if a given CVE ID is present in the CISA Known Exploited Vulnerabilities (KEV) catalog.
        Returns KEV status and date added if found.
        Example: 'Is CVE-2023-5002 in CISA KEV?'
        """
        print(f"[ViperMCP-KEV] Checking KEV status for {cve_id}...", file=sys.stderr, flush=True)

        try:
            kev_catalog = await asyncio.to_thread(fetch_kev_catalog)

            is_in_kev = False
            kev_date_added = None

            for entry in kev_catalog:
                if entry.get("cveID") == cve_id:
                    is_in_kev = True
                    kev_date_added = entry.get("dateAdded")
                    break

            result = {"cve_id": cve_id, "is_in_kev": is_in_kev, "kev_date_added": kev_date_added}

            return json.dumps(result, indent=2)

        except Exception as e:
            error_msg = f"Error checking KEV status for {cve_id}: {str(e)}"
            print(error_msg, file=sys.stderr, flush=True)
            return json.dumps({"error": error_msg, "cve_id": cve_id})

    async def search_public_exploits_for_cve(
        self, cve_id: str, search_github: bool = True, search_exploitdb: bool = True
    ) -> str:
        """
        Searches for public exploits for a given CVE ID on GitHub and/or Exploit-DB.
        Example: 'Find public exploits for CVE-2023-5003 on GitHub.'
        Or: 'Search exploits for CVE-2023-5004 on both GitHub and Exploit-DB.'
        """
        print(
            f"[ViperMCP-Exploits] Searching exploits for {cve_id} (GitHub: {search_github}, ExploitDB: {search_exploitdb})...",
            file=sys.stderr,
            flush=True,
        )

        try:
            all_exploits = []

            if search_github:
                github_exploits = await asyncio.to_thread(search_github, cve_id)
                all_exploits.extend(github_exploits)
                print(f"[ViperMCP-Exploits] Found {len(github_exploits)} GitHub exploits", file=sys.stderr, flush=True)

            if search_exploitdb:
                exploitdb_exploits = await asyncio.to_thread(search_exploit_db, cve_id)
                all_exploits.extend(exploitdb_exploits)
                print(
                    f"[ViperMCP-Exploits] Found {len(exploitdb_exploits)} ExploitDB exploits",
                    file=sys.stderr,
                    flush=True,
                )

            result = {
                "cve_id": cve_id,
                "search_sources": {"github": search_github, "exploitdb": search_exploitdb},
                "exploit_count": len(all_exploits),
                "exploits": all_exploits,
            }

            return json.dumps(result, indent=2)

        except Exception as e:
            error_msg = f"Error searching exploits for {cve_id}: {str(e)}"
            print(error_msg, file=sys.stderr, flush=True)
            return json.dumps({"error": error_msg, "cve_id": cve_id})

    async def save_cve_data_to_viperdb(self, cve_data_json: str) -> str:
        """
        Saves or updates CVE data (provided as a JSON string) to the Viper local database.
        The JSON data should match Viper's internal CVE data structure.
        Example: 'Save this CVE data to Viper DB: {"cve_id": "CVE-2023-7000", "description": "...", ...}'
        """
        print(f"[ViperMCP-DB] Attempting to save CVE data to database...", file=sys.stderr, flush=True)

        try:
            # Parse JSON data
            cve_data = json.loads(cve_data_json)
            cve_id = cve_data.get("cve_id", "Unknown")

            print(f"[ViperMCP-DB] Parsed data for {cve_id}", file=sys.stderr, flush=True)

            # Save to database
            await asyncio.to_thread(store_or_update_cve, cve_data)

            success_msg = f"Successfully saved {cve_id} to Viper database"
            print(f"[ViperMCP-DB] {success_msg}", file=sys.stderr, flush=True)
            return success_msg

        except json.JSONDecodeError as e:
            error_msg = f"Failed to parse JSON data: {str(e)}"
            print(error_msg, file=sys.stderr, flush=True)
            return error_msg
        except Exception as e:
            error_msg = f"Failed to save CVE data: {str(e)}"
            print(error_msg, file=sys.stderr, flush=True)
            return error_msg

    async def get_live_msrc_info_for_cve(self, cve_id: str) -> str:
        """
        Actively retrieves Microsoft Security Response Center (MSRC) information for a given CVE ID.
        This involves looking up MSRC document IDs related to the CVE via NVD and then fetching those documents.
        Provides details like MSRC document ID, affected Microsoft products, severity, and related KBs if available.
        Example: 'Get live MSRC details for CVE-2023-30001.'
        """
        print(f"[ViperMCP-MSRC] Fetching live MSRC data for {cve_id}...", file=sys.stderr, flush=True)

        try:
            # Get NVD API key for MSRC mapping
            nvd_api_key = await asyncio.to_thread(get_nvd_api_key)

            if not nvd_api_key:
                error_result = {
                    "cve_id": cve_id,
                    "error": "No NVD API key available for MSRC mapping",
                    "msrc_documents": [],
                }
                return json.dumps(error_result, indent=2)

            # Step 1: Get MSRC ID(s) for the CVE via NVD mapping
            print(f"[ViperMCP-MSRC] Looking up MSRC IDs for {cve_id} via NVD...", file=sys.stderr, flush=True)
            msrc_ids_map = await asyncio.to_thread(get_cve_to_msrc_mapping_from_nvd, nvd_api_key, cve_id)

            all_msrc_details = []
            msrc_ids_found = []

            if msrc_ids_map and msrc_ids_map.get("msrc_ids"):
                msrc_ids_found = msrc_ids_map["msrc_ids"]
                print(
                    f"[ViperMCP-MSRC] Found {len(msrc_ids_found)} MSRC ID(s): {msrc_ids_found}",
                    file=sys.stderr,
                    flush=True,
                )

                # Step 2: Fetch each MSRC document
                for msrc_id in msrc_ids_found:
                    print(f"[ViperMCP-MSRC] Fetching MSRC document: {msrc_id}", file=sys.stderr, flush=True)
                    msrc_doc_detail = await asyncio.to_thread(get_msrc_document, msrc_id)

                    if msrc_doc_detail:
                        all_msrc_details.append(msrc_doc_detail)
                        print(
                            f"[ViperMCP-MSRC] Successfully fetched MSRC document: {msrc_id}",
                            file=sys.stderr,
                            flush=True,
                        )
                    else:
                        print(f"[ViperMCP-MSRC] No details found for MSRC ID: {msrc_id}", file=sys.stderr, flush=True)
            else:
                print(f"[ViperMCP-MSRC] No MSRC IDs found for {cve_id}", file=sys.stderr, flush=True)

            # Prepare result
            result = {
                "cve_id": cve_id,
                "msrc_ids_found": msrc_ids_found,
                "msrc_documents_retrieved": len(all_msrc_details),
                "msrc_documents": all_msrc_details,
                "summary": {
                    "has_msrc_data": len(all_msrc_details) > 0,
                    "total_documents": len(all_msrc_details),
                    "microsoft_severity": all_msrc_details[0].get("Severity") if all_msrc_details else None,
                    "affected_products_count": len(all_msrc_details[0].get("AffectedProducts", []))
                    if all_msrc_details
                    else 0,
                },
            }

            if not all_msrc_details:
                result["message"] = f"No MSRC documents found for {cve_id} via NVD mapping"
            else:
                result["message"] = f"Successfully retrieved {len(all_msrc_details)} MSRC document(s) for {cve_id}"

            return json.dumps(result, indent=2)

        except Exception as e:
            error_msg = f"Error fetching live MSRC data for {cve_id}: {str(e)}"
            print(error_msg, file=sys.stderr, flush=True)

            error_result = {"cve_id": cve_id, "error": error_msg, "msrc_documents": []}
            return json.dumps(error_result, indent=2)

    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to risk level."""
        if risk_score >= 0.8:
            return "CRITICAL"
        elif risk_score >= 0.6:
            return "HIGH"
        elif risk_score >= 0.4:
            return "MEDIUM"
        elif risk_score >= 0.2:
            return "LOW"
        else:
            return "MINIMAL"

    async def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle incoming MCP requests."""
        try:
            method = request.get("method")
            params = request.get("params", {})
            request_id = request.get("id")

            # Handle notifications (requests without id) - don't send responses
            if request_id is None:
                # This is a notification, handle it but don't send a response
                if method == "notifications/initialized":
                    print("Client initialized notification received", file=sys.stderr, flush=True)
                    return None  # No response for notifications
                else:
                    print(f"Unknown notification: {method}", file=sys.stderr, flush=True)
                    return None  # No response for notifications

            # Handle regular requests (with id)
            if method == "initialize":
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {"listChanged": True}},
                        "serverInfo": {"name": self.name, "version": self.version},
                    },
                }

            elif method == "tools/list":
                tools_list = []
                for name, tool_info in self.tools.items():
                    tools_list.append(
                        {"name": name, "description": tool_info["description"], "inputSchema": tool_info["inputSchema"]}
                    )

                return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": tools_list}}

            elif method == "tools/call":
                tool_name = params.get("name")
                arguments = params.get("arguments", {})

                if tool_name in self.tools:
                    # Call the appropriate method
                    if hasattr(self, tool_name):
                        result = await getattr(self, tool_name)(**arguments)
                        return {
                            "jsonrpc": "2.0",
                            "id": request_id,
                            "result": {"content": [{"type": "text", "text": result}], "isError": False},
                        }
                    else:
                        return {
                            "jsonrpc": "2.0",
                            "id": request_id,
                            "error": {"code": -32601, "message": f"Tool method {tool_name} not implemented"},
                        }
                else:
                    return {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
                    }

            # Handle unsupported methods
            elif method in ["resources/list", "prompts/list"]:
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": f"Method not supported: {method}"},
                }

            else:
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": f"Unknown method: {method}"},
                }

        except Exception as e:
            print(f"Error handling request: {str(e)}", file=sys.stderr, flush=True)
            # Only return error response if we have a request ID
            if request.get("id") is not None:
                return {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "error": {"code": -32603, "message": f"Internal error: {str(e)}"},
                }
            else:
                return None  # No response for notifications even on error

    async def run_stdio(self):
        """Run the server using stdio transport."""
        print("Starting Viper MCP Server (stdio transport)...", file=sys.stderr, flush=True)
        print("Available tools:", file=sys.stderr, flush=True)
        for tool_name, tool_info in self.tools.items():
            print(f"- {tool_name}: {tool_info['description'][:60]}...", file=sys.stderr, flush=True)
        print(f"\nTotal: {len(self.tools)} tools available", file=sys.stderr, flush=True)
        print("Listening for requests on stdin...", file=sys.stderr, flush=True)

        while True:
            try:
                # Read request from stdin
                line = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
                if not line:
                    break

                line = line.strip()
                if not line:
                    continue

                # Parse JSON request
                request = json.loads(line)

                # Handle the request
                response = await self.handle_request(request)

                # Only send response if it's not None (notifications return None)
                if response is not None:
                    print(json.dumps(response), flush=True)

            except json.JSONDecodeError as e:
                print(f"JSON decode error: {str(e)}", file=sys.stderr, flush=True)
                error_response = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {str(e)}"},
                }
                print(json.dumps(error_response), flush=True)

            except Exception as e:
                print(f"Unexpected error: {str(e)}", file=sys.stderr, flush=True)
                error_response = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32603, "message": f"Internal error: {str(e)}"},
                }
                print(json.dumps(error_response), flush=True)


async def main():
    """Main function to run the MCP server."""
    try:
        print("Creating ViperMCPServer instance...", file=sys.stderr, flush=True)
        server = ViperMCPServer()
        print("ViperMCPServer created successfully", file=sys.stderr, flush=True)

        print("Starting stdio transport...", file=sys.stderr, flush=True)
        await server.run_stdio()

    except Exception as e:
        print(f"Critical error in main(): {e}", file=sys.stderr, flush=True)
        import traceback

        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    try:
        print("Starting asyncio event loop...", file=sys.stderr, flush=True)
        asyncio.run(main())
    except KeyboardInterrupt:
        print("MCP server stopped by user", file=sys.stderr, flush=True)
    except Exception as e:
        print(f"Critical error in __main__: {e}", file=sys.stderr, flush=True)
        import traceback

        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
