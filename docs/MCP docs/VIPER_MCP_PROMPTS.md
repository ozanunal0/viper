# VIPER MCP Prompts

**Quick reference for Claude Desktop integration**

## Basic CVE Analysis

```
"Analyze CVE-2024-3400 with full Viper analysis"
"Get comprehensive analysis for CVE-2023-44487"
"Perform complete Viper analysis on CVE-2024-0001"
```

## Specific Data Lookups

```
"Get NVD details for CVE-2024-3400"
"Check EPSS score for CVE-2023-44487"
"Is CVE-2024-1234 in the CISA KEV catalog?"
"Find Microsoft security data for CVE-2023-5678"
```

## Exploit Research

```
"Find public exploits for CVE-2023-44487"
"Search GitHub for CVE-2024-3400 exploits"
"Look for Exploit-DB entries for CVE-2023-1234"
```

## Risk Assessment

```
"Calculate Viper risk score for CVE-2024-3400"
"Generate security alerts for CVE-2023-44487"
"What's the priority level for CVE-2024-0001?"
```

## AI Analysis

```
"Analyze CVE-2024-3400 with Gemini AI"
"Get AI priority assessment for CVE-2023-44487"
"What does Gemini think about CVE-2024-1234?"
```

## Database Operations

```
"Save CVE-2024-3400 analysis to database"
"Store this CVE data in Viper database"
"Update database with CVE-2023-44487 information"
```

## Complex Queries

```
"Analyze CVE-2024-3400 - get everything: NVD data, EPSS, KEV status, exploits, AI analysis, and risk score"

"For CVE-2023-44487: check CISA KEV, find exploits, calculate risk score, and save to database"

"Complete analysis of CVE-2024-0001: NVD lookup, EPSS score, exploit search, Gemini analysis, alerts, and database save"
```

## Batch Operations

```
"Analyze these CVEs: CVE-2024-3400, CVE-2023-44487, CVE-2024-0001"
"Get risk scores for CVE-2024-3400 and CVE-2023-44487"
"Check KEV status for multiple CVEs: CVE-2024-1, CVE-2024-2, CVE-2024-3"
```

## Quick Tips

- **Be specific**: Include CVE ID for best results
- **Use natural language**: No need for exact function names
- **Combine requests**: Ask for multiple analyses at once
- **Save results**: Request database storage when needed
- **Check status**: Ask about KEV, EPSS, or exploit availability

## Available MCP Tools

| Command | Purpose |
|---------|---------|
| `perform_live_cve_lookup` | Complete CVE analysis |
| `get_nvd_cve_details` | Official NVD data |
| `get_epss_data_for_cve` | Exploitation probability |
| `check_cve_in_cisa_kev` | CISA KEV status |
| `search_public_exploits_for_cve` | Exploit research |
| `get_gemini_cve_analysis` | AI analysis |
| `get_viper_risk_score` | Risk calculation |
| `save_cve_data_to_viperdb` | Database storage |
| And 4 more... | See MCP_SERVER_README.md |
