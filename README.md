<div align="center">

  <img  src="https://img.shields.io/github/last-commit/ozanunal0/viper?style=flat-square&logo=git&logoColor=white" alt="Last Commit">
  <img src="https://img.shields.io/github/stars/ozanunal0/viper?style=flat-square&logo=github&label=Stars" alt="GitHub Stars">
  <img src="https://img.shields.io/github/forks/ozanunal0/viper?style=flat-square&logo=github&label=Forks" alt="GitHub Forks">


[![Docker Support](https://img.shields.io/badge/Docker-Supported-blue?logo=docker)](https://www.docker.com/)
[![MCP Support](https://img.shields.io/badge/Claude_Desktop-MCP_Integration-purple?logo=anthropic)](https://modelcontextprotocol.io/)
[![Tests: Passing](https://img.shields.io/badge/Tests-Passing-brightgreen.svg)]()
![visitors](https://visitor-badge.laobi.icu/badge?page_id=ozanunal0.viper)

</div>



<p align="center">

![Google Gemini](https://img.shields.io/badge/google%20gemini-8E75B2?style=for-the-badge&logo=google%20gemini&logoColor=white)
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Claude](https://img.shields.io/badge/Claude-AI_Integration-FF6B35?style=for-the-badge&logo=anthropic&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![macOS](https://img.shields.io/badge/mac%20os-000000?style=for-the-badge&logo=macos&logoColor=F0F0F0)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/github%20actions-%232671E5.svg?style=for-the-badge&logo=githubactions&logoColor=white)
![PyCharm](https://img.shields.io/badge/pycharm-143?style=for-the-badge&logo=pycharm&logoColor=black&color=black&labelColor=green)

</p>


# 🛡️ VIPER - Vulnerability Intelligence, Prioritization, and Exploitation Reporter


**VIPER is your AI-powered co-pilot in the complex world of cyber threats, designed to provide actionable Vulnerability Intelligence, Prioritization, and Exploitation Reporting.**

In an era of ever-increasing cyber threats, VIPER cuts through the noise. It ingests data from critical sources like NVD, EPSS, and the CISA KEV catalog, then leverages Google Gemini AI for deep contextual analysis and vulnerability prioritization. All this intelligence is centralized, enriched, and presented through multiple interfaces: an interactive Streamlit dashboard, a powerful CLI, and **now integrated with Claude Desktop through MCP (Model Context Protocol)** for natural language vulnerability analysis.

## 🚀 **NEW: Claude Desktop Integration via MCP**

VIPER now includes a **Model Context Protocol (MCP) server** that integrates seamlessly with Claude Desktop, providing **12 powerful cybersecurity tools** accessible through natural language:

For a detailed list of tools and usage examples, see the [MCP_IMPLEMENTATION_SUMMARY.md](docs/MCP%20docs/MCP_IMPLEMENTATION_SUMMARY.md)

### **📺 Viper MCP Demo**

[![Watch the VIPER Demo Video](public/demo.jpg)](https://player.vimeo.com/video/1090650637?h=0dc04c492a)

### **💬 Natural Language Examples:**

For a detailed list of promt usage examples, see the [VIPER_MCP_PROMPTS.md](docs/MCP%20docs/VIPER_MCP_PROMPTS.md)


### **⚡ Quick MCP Setup:**

1. **Configure your Claude Desktop** with this MCP server configuration:
   ```json
   {
     "mcpServers": {
       "ViperMCPServer": {
         "command": "/FULL/PATH/TO/YOUR/viper/run_mcp_clean.sh"
       }
     }
   }
   ```

2. **See the [MCP_SERVER_README.md](docs/MCP%20docs/MCP_SERVER_README.md)** for complete setup instructions

## 📚 Documentation

📖 **Complete documentation is available in the [docs/](docs/) directory:**

## 📋 Table of Contents

1.  [🎯 Screenshots](#dashboard)
2.  [✨ Core Features](#-core-features)
3.  [🛠️ Technology Stack](#-tech-stack)
4.  [🚀 Installation & Setup](#-installation--setup)
5.  [⚙️ Usage](#-usage)
6.  [🗂️ Project Structure](#project-structure)
7.  [📈 Development Status & Roadmap](#project-roadmap--future-vision)

---
## Dashboard

VIPER provides a comprehensive dashboard for visualizing and analyzing vulnerability data:

### Home Screen
![Home](https://i.imgur.com/5Ri40Oc.png)

### Main Dashboard
![main dashboard.png](public/main%20dashboard.png)

### Detailed Analysis View
![details va.png](public/details%20va.png)

### Live CVE Lookup
![live cve lookup.png](public/live%20cve%20lookup.png)

### Analytics & Trends
![analytics.png](public/analytics.png)


## ✨ Core Features

* **Multi-Source Data Ingestion:**
    * ✅ NVD, EPSS, CISA KEV, Microsoft Patch Tuesday, Exploit-DB & GitHub.
* **AI-Powered Analysis & Prioritization:**
    * 🧠 Deep contextual analysis with **Google Gemini AI** and **Claude Desktop (via MCP)**.
* **Comprehensive Risk Scoring:**
    * 📈 Customizable weighted scoring (CVSS, EPSS, KEV, Microsoft Severity, Gemini AI, Exploit Availability).
* **Centralized & Enriched Data Storage:**
    * 🗄️ SQLite database for all collected and enriched vulnerability intelligence.
* **Multiple Access Interfaces:**
    * 🖥️ **Interactive Streamlit Dashboard:** User-friendly web interface for data exploration and analysis.
    * 💻 **CLI Mode:** For backend data processing, fetching, and analysis.
    * 🤖 **Claude Desktop MCP Integration:** Natural language vulnerability analysis with 12 specialized tools.
* **Advanced Features:**
    * 🔎 **Live CVE Lookup:** Real-time search and analysis of any CVE from NVD.


## 🚀 Tech Stack

* **Backend & Analysis:** Python
* **AI Models:** Google Gemini, Claude (via MCP)
* **MCP Integration:** Model Context Protocol server for Claude Desktop
* **Web Interface/Dashboard:** Streamlit
* **Database:** SQLite
* **Key Libraries:** requests, google-generativeai, tenacity, pandas, plotly

## 🛠️ Installation & Setup

### Prerequisites

- **Python 3.9+**
- **Claude Desktop** (for MCP integration)
- **Git**
- **Virtual Environment** (recommended)

### Option 1: Automated Setup (Recommended)

```bash
git clone git@github.com:ozanunal0/viper.git
cd viper
./setup.sh
```

### Option 2: Manual Setup

### 1. **Clone the Repository:**
```bash
git clone git@github.com:ozanunal0/viper.git
cd viper
```

### 2. **Create and Activate a Virtual Environment (Recommended):**
```bash
python -m venv venv
# On Linux/macOS:
source venv/bin/activate
# On Windows:
# venv\Scripts\activate
```

### 3. **Install Dependencies:**
```bash
pip install -r requirements.txt
```

### 4. **Configure Environment Variables:**

Copy the example environment file and configure your API keys:
```bash
cp env.example .env
nano .env  # Edit with your preferred editor
```

**Essential configuration:**
```dotenv
# Required for AI analysis
GEMINI_API_KEY=your_gemini_api_key_here

# Recommended for enhanced functionality
GITHUB_TOKEN=your_github_token_here
EXPLOIT_DB_API_URL=https://www.exploit-db.com/api/v1
EXPLOIT_SEARCH_MAX_RESULTS=10
PUBLIC_EXPLOIT_BOOST_FACTOR=1.5

# Optional for higher rate limits
NVD_API_KEY=your_nvd_api_key_here
```

### 5. **Configure Claude Desktop MCP Integration (Optional but Recommended):**


For detailed setup instructions, refer to the [MCP_SERVER_README.md](docs/MCP%20docs/MCP_SERVER_README.md)

## 🐳 Docker Deployment

VIPER can be deployed using Docker for easy setup and management.
For detailed Docker deployment instructions, database management, and troubleshooting, see [DOCKER.md](docs/DOCKER.md).



## ⚙️ Usage

### 1. **Claude Desktop MCP Integration** (Recommended for Interactive Analysis)

Once configured, use natural language with Claude Desktop to analyze vulnerabilities:

**Example Queries:**
```
📋 "Get comprehensive analysis for CVE-2024-3400"
🔍 "Find all public exploits for CVE-2023-44487 on GitHub"
⚠️ "Check if CVE-2024-1234 is in the CISA KEV catalog"
📊 "Calculate the Viper risk score for CVE-2023-5678"
🤖 "Analyze CVE-2024-0001 with Gemini AI and generate alerts"
💾 "Get live NVD details for CVE-2024-3400 and save to database"
```
Refer to the [MCP_IMPLEMENTATION_SUMMARY.md](docs/MCP%20docs/MCP_IMPLEMENTATION_SUMMARY.md) for available tools.

### 2. **Command Line Interface (CLI)**

Use the CLI to fetch, process, and analyze vulnerability data. The results (high/medium priority CVEs and alerts) will be printed to the console.

```bash
python main.py cli --days <NUMBER_OF_DAYS>
```
Days will affect the intensity and performance of outputs.

### 3. **Interactive Dashboard**

Launch the Streamlit dashboard:
```bash
python main.py dashboard
```
Or directly with:
```bash
./scripts/run_dashboard.sh
```

## Project Structure

```
viper/
├── main.py                  # Main entry point script
├── requirements.txt         # Project dependencies
├── README.md                # Project documentation
├── CONFIGURATION_GUIDE.md   # MCP setup and environment configuration
├── .gitignore               # Git ignore file
├── run_mcp_clean.sh         # MCP server runner script for Claude Desktop
├── test_exploit_search.py   # Tool to test GitHub exploit search
├── update_github_exploits.py # Tool to update CVEs with GitHub exploit data
├── data/                    # Data storage directory
│   └── viper.db             # SQLite database
├── logs/                    # Log files directory
│   └── viper.log            # Application logs
├── scripts/                 # Utility scripts
│   ├── run_dashboard.sh     # Script to run the dashboard
│   └── update_exploits.py   # Script to update exploit data for existing CVEs
├── src/                     # Source code
│   ├── mcp_server.py        # 🆕 MCP server with 12 cybersecurity tools
│   ├── clients/             # API clients
│   │   ├── cisa_kev_client.py        # CISA KEV API client
│   │   ├── epss_client.py            # EPSS API client
│   │   ├── exploit_search_client.py  # Public exploit search client
│   │   ├── nvd_client.py             # NVD API client
│   │   └── microsoft_update_client.py # Microsoft Patch Tuesday API client
│   ├── dashboard/           # Dashboard application
│   │   ├── app.py              # Main dashboard app
│   │   └── pages/              # Dashboard pages
│   │       ├── 01_Dashboard.py           # Main dashboard page
│   │       ├── 02_Detailed_Analysis.py   # Detailed CVE analysis page
│   │       ├── 03_Live_CVE_Lookup.py     # Live CVE lookup and analysis
│   │       └── 04_Analytics.py           # Analytics and trends page
│   ├── utils/               # Utility modules
│   │   ├── config.py            # Configuration management
│   │   └── database_handler.py  # Database operations
│   ├── gemini_analyzer.py   # Gemini AI analysis
│   ├── main_mvp.py          # CLI application logic
│   └── risk_analyzer.py     # Risk scoring and alerts
```


## Project Roadmap & Future Vision

VIPER aims to be a comprehensive, AI-driven Cyber Threat Intelligence (CTI) platform, drawing inspiration from advanced, multi-layered CTI systems. Our current version provides a strong foundation with NVD, EPSS, CISA KEV, and Microsoft MSRC data ingestion, coupled with Gemini AI for analysis, risk scoring, and an interactive Streamlit dashboard with real-time CVE lookup.

Here's where we're headed:

### Phase 1: Core Enhancements & Data Completeness (Immediate Focus)

✅ ~~Full NVD API Pagination: Ensure complete ingestion of all relevant CVEs from NVD by implementing robust pagination in nvd_client.py to handle large result sets (addressing current partial data fetching ).~~

✅ ~~Solidify Retry Mechanisms: Continuously refine and test tenacity based retry logic across all external API clients (nvd_client.py, epss_client.py, cisa_kev_client.py, microsoft_update_client.py, gemini_analyzer.py) for maximum resilience.~~

✅ Dashboard Usability & Features:

✅ ~~Refine real-time CVE lookup: Optimize display and ensure all enrichment (EPSS, KEV, MSData, Gemini re-analysis) is available for live queries.~~

✅ ~~Enhance filtering and sorting options on all data tables.~~

✅ ~~Implement detailed CVE view modals or dedicated pages for better readability of all enriched data.~~

🚧 Automated Periodic Execution: Integrate APScheduler or configure system cron jobs to run the main_mvp.py data pipeline automatically at configurable intervals.

### Phase 2: Expanding Data Ingestion & Enrichment

* **[🚧] Local LLM Support (Ollama Integration):**
    * Implement local LLM support primarily through Ollama for enhanced privacy and offline capabilities.
    * Enable AI-powered vulnerability analysis without external API dependencies.
    * Support for popular models like Llama, Code Llama, and specialized security-focused models.
    * Configurable model selection and local deployment options.

✅ ~~Other CISA Products & Feeds: Explore and integrate other relevant CISA feeds beyond the KEV catalog (e.g., CISA Alerts, Industrial Control Systems Advisories if applicable).
Explore and integrate other relevant CISA feeds beyond the KEV catalog (e.g., CISA Alerts, Industrial Control Systems Advisories if applicable).~~

✅ ~~Comprehensive Microsoft Patch Tuesday Parsing: Further refine microsoft_update_client.py to ensure accurate and detailed extraction of product families, specific product versions, and direct links to KB articles/MSRC guidance from CVRF/CSAF to ensure accurate and detailed extraction of product families, specific product versions, and direct links to KB articles/MSRC guidance from CVRF/CSAF data.~~

### Phase 3: Developing "Threat Analyst Agent" Capabilities

* **[🚧] Semantic Web Search Integration (EXA AI):**
    * For high-priority CVEs or emerging threats, automatically search the web for technical analyses, blog posts, news articles, and threat actor reports.
    * Store relevant article metadata (URL, title, snippet, source) linked to CVEs.
* **[🚧] AI-Powered Content Analysis (Gemini):**
    * **Summarization:** Use Gemini to summarize fetched articles and reports related to a CVE.
    * **Key Information Extraction:** Extract TTPs (Tactics, Techniques, and Procedures), affected software/hardware, and potential mitigations from unstructured text.
    * **Cross-Validation Support:** Assist analysts by comparing information from different sources regarding a specific threat.

### Phase 4: Building "Threat Hunting Agent" Foundations

* **[📝] Enhanced IOC Extraction:**
    * Expand IOC (IPs, domains, hashes, URLs, mutexes, registry keys) extraction from all ingested text sources (NVD descriptions, MSRC summaries, KEV details, fetched articles) using Gemini's advanced understanding or specialized libraries like `iocextract`.
    * Create a robust, searchable IOC database.
* **[📝] Natural Language to Query Translation (Advanced):**
    * Leverage Gemini to translate natural language threat hunting hypotheses (e.g., "Are there any Cobalt Strike beacons communicating with newly registered domains?") into structured query formats like OCSF, KQL (Azure Sentinel), or Splunk SPL.

### Phase 5: Broader Intelligence Gathering & Advanced Analytics

* **[📝] Social Media Monitoring & Clustering (Advanced):**
    * Ingest data from platforms like Twitter/X or specific Reddit communities (e.g., r/netsec) for early signals of new vulnerabilities or exploits.
    * Apply LLM-based semantic clustering (Gemini) to group discussions and identify emerging threat trends.
* **[📝] Threat Actor & Malware Profiling:**
    * Begin associating CVEs and IOCs with known threat actors and malware families (potentially integrating with MISP or other OSINT feeds).
    * Visualize these relationships in the dashboard.
* **[📝] Advanced Dashboard Analytics:**
    * Implement more sophisticated trend analysis, predictive insights (beyond EPSS), and customizable reporting features.

### Phase 6: Platform Maturity & Usability

* **[📝] User Accounts & Collaboration (Long-term):** Allow multiple users, role-based access, and collaborative analysis features (e.g., shared notes, investigation assignments).
* **[📝] Notification System:** Implement email or other notifications for high-priority alerts or newly discovered critical CVEs matching predefined criteria.
* **[📝] Database Optimization/Migration:** For larger deployments, consider migrating from SQLite to a more scalable database like PostgreSQL.

This roadmap is ambitious and will evolve. Community contributions and feedback are highly encouraged as we build VIPER into a powerful open-source CTI tool!
