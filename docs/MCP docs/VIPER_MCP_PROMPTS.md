# VIPER MCP Server - Comprehensive Prompt Collection

This document contains detailed prompts for using VIPER (Vulnerability Intelligence, Prioritization, and Exploitation Reporter) through Claude Desktop's MCP integration.

## Table of Contents
1. [Basic CVE Operations](#basic-cve-operations)
2. [Comprehensive Analysis](#comprehensive-analysis)
3. [Risk Assessment & Prioritization](#risk-assessment--prioritization)
4. [Threat Intelligence Research](#threat-intelligence-research)
5. [Exploit Research](#exploit-research)
6. [Microsoft Security Updates](#microsoft-security-updates)
7. [Database Operations](#database-operations)
8. [EXA AI Semantic Search](#exa-ai-semantic-search)
9. [Workflow Combinations](#workflow-combinations)
10. [Advanced Scenarios](#advanced-scenarios)

---

## Basic CVE Operations

### 1. Simple CVE Lookup
```
Get basic NVD details for CVE-2024-6387
```

### 2. EPSS Score Check
```
What's the EPSS exploitation probability score for CVE-2023-44221?
```

### 3. CISA KEV Status Check
```
Is CVE-2024-1709 listed in the CISA Known Exploited Vulnerabilities catalog?
```

### 4. Multi-Source CVE Lookup
```
Perform a comprehensive live lookup for CVE-2024-6387 using all data sources (NVD, EPSS, CISA KEV, GitHub exploits) but don't save to database
```

### 5. Full CVE Analysis with Database Save
```
Do a complete live analysis for CVE-2024-3400 including Gemini AI analysis, risk scoring, and save everything to the Viper database
```

---

## Comprehensive Analysis

### 6. Complete CVE Intelligence Package
```
Perform live CVE lookup for CVE-2024-21412 with all options enabled: NVD data, EPSS scoring, CISA KEV check, GitHub exploit search, Microsoft MSRC data, Gemini analysis, risk calculation, and save to database
```

### 7. Priority Assessment Only
```
Get Gemini AI priority assessment for this CVE data: {"cve_id": "CVE-2024-6387", "description": "Remote code execution in OpenSSH", "cvss_v3_score": 8.1, "epss_score": 0.0012, "is_in_kev": false}
```

### 8. Detailed Gemini Analysis
```
Run comprehensive Gemini analysis on this CVE: {"cve_id": "CVE-2024-1709", "description": "ConnectWise ScreenConnect authentication bypass", "cvss_v3_score": 10.0, "epss_score": 0.97, "is_in_kev": true, "has_public_exploit": true}
```

### 9. Risk Score Calculation
```
Calculate Viper risk score for this vulnerability: {"cve_id": "CVE-2024-3400", "cvss_v3_score": 10.0, "epss_score": 0.97, "is_in_kev": true, "gemini_priority": "HIGH", "microsoft_severity": "Critical", "has_public_exploit": true}
```

### 10. Security Alert Generation
```
Generate security alerts for this critical CVE: {"cve_id": "CVE-2024-21412", "cvss_v3_score": 9.8, "epss_score": 0.85, "is_in_kev": true, "gemini_priority": "HIGH", "has_public_exploit": true}
```

---

## Risk Assessment & Prioritization

### 11. High-Risk CVE Workflow
```
For CVE-2024-6387: First get NVD details, then EPSS score, check CISA KEV status, search for GitHub exploits, run Gemini analysis, calculate risk score, and generate alerts
```

### 12. Vulnerability Triage
```
Help me triage these vulnerabilities by priority. Start with CVE-2024-1709 - get comprehensive analysis including Gemini priority, risk score, and alerts
```

### 13. Critical Infrastructure Assessment
```
Analyze CVE-2024-3400 (PAN-OS vulnerability) with focus on risk assessment - get EPSS data, KEV status, exploit availability, and calculate comprehensive risk score
```

### 14. Patch Priority Assessment
```
I need to prioritize patching for CVE-2024-21412. Get full live lookup with risk analysis and generate security alerts to help with prioritization
```

---

## Threat Intelligence Research

### 15. General Threat Landscape
```
Search for threat intelligence about "zero-day vulnerabilities in enterprise software 2024"
```

### 16. Ransomware Research
```
Find recent threat intelligence articles about "ransomware attack techniques targeting healthcare systems"
```

### 17. APT Group Analysis
```
Search threat intelligence for "APT29 techniques and tactics" with focus on recent publications
```

### 18. CVE-Specific Threat Research
```
Find threat intelligence content specifically about CVE-2024-6387 using semantic search
```

### 19. Vulnerability Class Research
```
Search for threat intelligence about "SQL injection vulnerabilities in web applications" published in the last 6 months
```

### 20. Generate Intelligence Summary
```
Generate a comprehensive threat intelligence answer for: "What are the most common attack vectors used by ransomware groups in 2024?"
```

---

## Exploit Research

### 21. GitHub Exploit Search
```
Search for public exploits on GitHub for CVE-2024-6387
```

### 22. Multi-Platform Exploit Search
```
Find public exploits for CVE-2024-1709 on both GitHub and Exploit-DB
```

### 23. Exploit Availability Assessment
```
Check exploit availability for CVE-2024-3400 across GitHub and ExploitDB platforms
```

### 24. High-Value Target Research
```
Search for exploits targeting CVE-2024-21412 on GitHub only (skip ExploitDB)
```

---

## Microsoft Security Updates

### 25. MSRC Document Lookup
```
Get live Microsoft Security Response Center information for CVE-2024-21412
```

### 26. Microsoft Severity Assessment
```
Fetch MSRC data for CVE-2024-26229 to get Microsoft's severity rating and affected products
```

### 27. Windows Vulnerability Analysis
```
Get comprehensive Microsoft security data for CVE-2024-30040 including affected products and KB numbers
```

---

## Database Operations

### 28. Save CVE Analysis
```
Save this comprehensive CVE data to Viper database: {"cve_id": "CVE-2024-6387", "description": "OpenSSH remote code execution", "cvss_v3_score": 8.1, "epss_score": 0.0012, "is_in_kev": false, "gemini_priority": "MEDIUM", "risk_score": 0.45}
```

### 29. Retrieve Stored Articles
```
Get all stored threat intelligence articles from the Viper database
```

### 30. CVE-Specific Articles
```
Retrieve stored threat intelligence articles specifically related to CVE-2024-6387
```

### 31. Analysis Queue Check
```
Show me all stored threat articles that need Gemini analysis
```

---

## EXA AI Semantic Search

### 32. Domain-Specific Search
```
Search threat intelligence about "industrial control systems vulnerabilities" including only content from ics-cert.us-cert.gov and cisa.gov
```

### 33. Exclude Common Sources
```
Find threat intelligence about "supply chain attacks" but exclude results from generic news sites like cnn.com, bbc.com, reuters.com
```

### 34. Time-Bounded Research
```
Search for threat intelligence about "AI security vulnerabilities" published between 2024-01-01 and 2024-06-30
```

### 35. Similar Article Discovery
```
Find articles similar to this threat report: https://www.crowdstrike.com/blog/analysis-of-intrusion-campaign-targeting-telecom-and-bpo-companies/
```

### 36. Validate EXA Integration
```
Check if EXA AI integration is working properly and show configuration details
```

---

## Workflow Combinations

### 37. Complete CVE Intelligence Workflow
```
Execute complete intelligence workflow for CVE-2024-6387:
1. Get NVD details
2. Fetch EPSS score
3. Check CISA KEV status
4. Search for GitHub exploits
5. Get MSRC data
6. Run Gemini analysis
7. Calculate risk score
8. Generate alerts
9. Search for related threat intelligence
10. Save everything to database
```

### 38. Threat Research Pipeline
```
Research pipeline for "Log4Shell exploitation techniques":
1. Search general threat intelligence
2. Generate comprehensive answer
3. Find similar articles
4. Store results in database
```

### 39. Vulnerability Assessment Chain
```
For CVE-2024-3400:
1. Get comprehensive live lookup with all data sources
2. Search for threat intelligence content about this CVE
3. Find public exploits
4. Calculate final risk assessment
```

### 40. Incident Response Preparation
```
Prepare incident response data for CVE-2024-1709:
1. Get complete CVE analysis with Gemini assessment
2. Search for active exploitation reports
3. Find available exploits and tools
4. Generate prioritized alerts
```

---

## Advanced Scenarios

### 41. Zero-Day Research
```
Research emerging zero-day threats: Search threat intelligence for "zero-day vulnerabilities discovered in 2024" and generate comprehensive analysis with citations
```

### 42. APT Campaign Analysis
```
Analyze recent APT activity: Search for "Advanced Persistent Threat campaigns 2024" and find similar articles to build threat landscape understanding
```

### 43. Critical Infrastructure Focus
```
Focus on critical infrastructure: Search threat intelligence for "SCADA and ICS vulnerabilities" excluding academic sources, focusing on practical exploitation information
```

### 44. Ransomware Intelligence Package
```
Build comprehensive ransomware intelligence:
1. Search for "ransomware attack techniques 2024"
2. Generate detailed answer for "How do modern ransomware groups gain initial access?"
3. Find similar articles from security vendors
4. Store complete package in database
```

### 45. Vulnerability Chaining Research
```
Research vulnerability chaining: Search for "vulnerability chaining techniques" and "privilege escalation chains" to understand complex attack scenarios
```

### 46. Threat Actor Profiling
```
Profile specific threat actor: Search for "Lazarus Group attack techniques" and generate comprehensive profile with recent TTPs and target information
```

### 47. Industry-Specific Threats
```
Healthcare cybersecurity focus: Search threat intelligence for "healthcare cybersecurity threats 2024" published from healthcare-specific sources like HHS and medical associations
```

### 48. Supply Chain Security
```
Supply chain threat analysis: Search for "software supply chain attacks" from the last 3 months and generate detailed analysis of current threat landscape
```

### 49. Emerging Technology Threats
```
AI/ML security research: Search for "artificial intelligence security vulnerabilities" and "machine learning model attacks" from academic and security research sources
```

### 50. Comprehensive Threat Landscape
```
Build complete threat landscape:
1. Search for "cybersecurity threat landscape 2024"
2. Generate answer for "What are the top 5 cybersecurity threats organizations face in 2024?"
3. Find similar reports from major security vendors
4. Validate all EXA integrations are working
5. Store comprehensive report in database
```

---

## Quick Reference Commands

### Rapid Assessment
- `Get NVD details for CVE-XXXX-XXXX`
- `Check EPSS score for CVE-XXXX-XXXX`
- `Is CVE-XXXX-XXXX in CISA KEV?`
- `Find GitHub exploits for CVE-XXXX-XXXX`

### Analysis
- `Run Gemini analysis for CVE-XXXX-XXXX`
- `Calculate risk score for CVE-XXXX-XXXX`
- `Generate alerts for CVE-XXXX-XXXX`
- `Get comprehensive analysis for CVE-XXXX-XXXX`

### Intelligence
- `Search threat intelligence for "QUERY"`
- `Generate answer for "QUESTION"`
- `Find articles similar to URL`
- `Get stored articles for CVE-XXXX-XXXX`

### Microsoft
- `Get MSRC data for CVE-XXXX-XXXX`
- `Find Microsoft severity for CVE-XXXX-XXXX`

### Database
- `Save CVE data: JSON_DATA`
- `Get all stored articles`
- `Show articles needing analysis`

---

## Usage Tips

1. **Start Simple**: Begin with basic CVE lookups before moving to comprehensive analysis
2. **Chain Operations**: Use results from one operation to inform the next
3. **Save Important Data**: Use database save options for critical vulnerabilities
4. **Leverage AI**: Use Gemini analysis for priority and risk assessment
5. **Search Semantically**: EXA AI understands natural language queries
6. **Time-bound Searches**: Use date ranges for current threat intelligence
7. **Exclude Noise**: Use domain filters to focus on authoritative sources
8. **Validate Integration**: Check EXA status if searches aren't working
9. **Review Stored Data**: Regularly check stored articles for follow-up analysis
10. **Combine Sources**: Use multiple data sources for complete picture

---

*This prompt collection covers all 18+ VIPER MCP tools and provides practical examples for cybersecurity professionals, incident responders, vulnerability researchers, and threat intelligence analysts.*
