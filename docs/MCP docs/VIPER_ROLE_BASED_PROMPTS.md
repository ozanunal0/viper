# VIPER MCP - Role-Based Prompt Collections

## 🛡️ SOC Analyst Prompts

### Daily Monitoring
```
Search threat intelligence for "latest malware campaigns targeting financial institutions"
```

### Alert Triage
```
Perform live CVE lookup for CVE-2024-XXXX with EPSS score, KEV status, and immediate risk assessment
```

### Incident Investigation
```
Find threat intelligence content about CVE-2024-XXXX and search for active exploitation reports
```

### Threat Landscape
```
Generate threat intelligence answer for: "What are the most active ransomware groups this week?"
```

### Vulnerability Assessment
```
Check if CVE-2024-XXXX is in CISA KEV and get exploitation probability score
```

---

## 🔍 Threat Intelligence Analyst Prompts

### APT Research
```
Search threat intelligence for "APT29 techniques and tactics" published in the last 3 months
```

### Campaign Analysis
```
Find articles similar to this threat report: [URL] and build comprehensive threat profile
```

### Emerging Threats
```
Search for threat intelligence about "zero-day vulnerabilities discovered in 2024" excluding news sites
```

### TTPs Analysis
```
Generate comprehensive answer for: "What are the latest techniques used by ransomware groups for initial access?"
```

### Industry Focus
```
Search threat intelligence for "healthcare cybersecurity threats" from authoritative sources like HHS and CISA
```

### Report Generation
```
Search for "cybersecurity threat landscape 2024" and generate detailed analysis with citations
```

---

## 🚨 Incident Responder Prompts

### Emergency Assessment
```
Do complete emergency analysis for CVE-2024-XXXX including all data sources, exploit availability, and immediate risk assessment
```

### Exploit Verification
```
Search for public exploits on GitHub and ExploitDB for CVE-2024-XXXX
```

### Impact Analysis
```
Get comprehensive CVE analysis with Gemini priority assessment and security alerts for CVE-2024-XXXX
```

### Attribution Research
```
Search threat intelligence for "Lazarus Group attack techniques" and recent campaign information
```

### IOC Research
```
Find threat intelligence about "current phishing campaigns" and extract indicators of compromise
```

---

## 🏗️ Vulnerability Manager Prompts

### Patch Prioritization
```
Get complete analysis for CVE-2024-XXXX including CVSS, EPSS, KEV status, exploit availability, and risk score
```

### Risk Assessment
```
Calculate Viper risk score for this vulnerability: {"cve_id": "CVE-2024-XXXX", "cvss_v3_score": 8.1, "epss_score": 0.85, "is_in_kev": true}
```

### Microsoft Updates
```
Get live MSRC information for CVE-2024-XXXX including severity and affected products
```

### Exploit Timeline
```
Search for public exploits and threat intelligence about CVE-2024-XXXX to understand exploitation timeline
```

### Business Impact
```
Generate security alerts and risk assessment for CVE-2024-XXXX to support business decisions
```

---

## 🔬 Security Researcher Prompts

### Vulnerability Research
```
Search threat intelligence for "SQL injection vulnerabilities in web applications" from academic and research sources
```

### Exploit Development
```
Find detailed technical content about CVE-2024-XXXX including proof-of-concept code and exploitation techniques
```

### Attack Chain Analysis
```
Search for "vulnerability chaining techniques" and "privilege escalation chains" research
```

### Zero-Day Research
```
Search threat intelligence for "zero-day vulnerabilities discovered in 2024" from security research organizations
```

### Tool Development
```
Search for "offensive security tools 2024" and "red team techniques" from security research sources
```

---

## 👔 CISO/Security Manager Prompts

### Executive Briefing
```
Generate comprehensive threat intelligence answer for: "What are the top 5 cybersecurity threats facing our industry in 2024?"
```

### Risk Reporting
```
Get comprehensive analysis for CVE-2024-XXXX with business risk assessment and recommended actions
```

### Threat Landscape
```
Search for "cybersecurity threat landscape 2024" from major security vendors and research organizations
```

### Compliance Check
```
Check if CVE-2024-XXXX is in CISA KEV catalog for compliance reporting requirements
```

### Budget Planning
```
Search threat intelligence for "cybersecurity investment priorities 2024" from analyst firms
```

---

## 🏭 Critical Infrastructure Analyst Prompts

### ICS/SCADA Research
```
Search threat intelligence for "industrial control systems vulnerabilities" from ICS-CERT and critical infrastructure sources
```

### OT Security
```
Find threat intelligence about "operational technology attacks" excluding general IT security sources
```

### Nation-State Threats
```
Search for "critical infrastructure attacks by nation-state actors" from government and defense sources
```

### Supply Chain
```
Search threat intelligence for "software supply chain attacks targeting critical infrastructure"
```

### Sector-Specific
```
Search for "power grid cybersecurity threats" from energy sector and government sources
```

---

## 🔐 Penetration Tester Prompts

### Exploit Research
```
Search for public exploits on GitHub for CVE-2024-XXXX and get technical exploitation details
```

### Attack Techniques
```
Search threat intelligence for "privilege escalation techniques 2024" from offensive security sources
```

### Tool Research
```
Find threat intelligence about "penetration testing tools and techniques" from security research sources
```

### Red Team TTPs
```
Search for "red team techniques and tactics" from offensive security and research organizations
```

### Vulnerability Chains
```
Search for "attack chain methodologies" and "multi-stage attack techniques" research
```

---

## 🌐 Cloud Security Analyst Prompts

### Cloud Threats
```
Search threat intelligence for "cloud security threats 2024" from cloud security vendors and research
```

### Container Security
```
Find threat intelligence about "container and Kubernetes security vulnerabilities"
```

### Cloud Misconfigurations
```
Search for "cloud misconfiguration attacks" and "cloud security best practices" from authoritative sources
```

### Serverless Security
```
Search threat intelligence for "serverless security vulnerabilities" from cloud security research
```

### Multi-Cloud Risks
```
Find threat intelligence about "multi-cloud security challenges" from enterprise security sources
```

---

## 💡 Usage Guidelines by Role

### SOC Analysts
- Focus on **current threats** and **immediate risks**
- Use **real-time data** sources (KEV, EPSS)
- Prioritize **actionable intelligence**

### Threat Intelligence Analysts
- Emphasize **comprehensive research** and **attribution**
- Use **time-bounded searches** for trending analysis
- Focus on **high-quality sources** and **citations**

### Incident Responders
- Prioritize **speed** and **completeness**
- Use **all available data sources**
- Focus on **exploit availability** and **active threats**

### Vulnerability Managers
- Emphasize **risk quantification** and **business impact**
- Use **multiple scoring systems** (CVSS, EPSS, Viper)
- Focus on **patch prioritization** data

### Security Researchers
- Focus on **technical depth** and **novel techniques**
- Use **academic and research** sources
- Emphasize **proof-of-concept** and **detailed analysis**

### Leadership/Management
- Focus on **strategic threats** and **business impact**
- Use **authoritative sources** and **trend analysis**
- Emphasize **risk communication** and **decision support**

---

*Each role has different intelligence requirements and operational contexts. These prompts are designed to maximize VIPER's value for specific professional responsibilities.*
