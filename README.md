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


### **📺 Demo**

![demo.gif](public/demo.gif)

### **🔧 Available MCP Tools:**

1. **`perform_live_cve_lookup`** - Comprehensive live CVE analysis with all data sources
2. **`get_nvd_cve_details`** - Fetch detailed CVE information from NVD
3. **`get_epss_data_for_cve`** - Retrieve EPSS exploitation probability scores
4. **`check_cve_in_cisa_kev`** - Check CISA Known Exploited Vulnerabilities status
5. **`search_public_exploits_for_cve`** - Search GitHub and Exploit-DB for public exploits
6. **`get_gemini_cve_priority`** - AI-powered CVE priority assessment
7. **`get_gemini_cve_analysis`** - Comprehensive AI vulnerability analysis
8. **`get_viper_risk_score`** - Calculate multi-factor risk scores
9. **`get_viper_cve_alerts`** - Generate security alerts based on configurable rules
10. **`get_comprehensive_cve_analysis`** - Complete analysis combining all tools
11. **`save_cve_data_to_viperdb`** - Save analysis results to local database
12. **`get_live_msrc_info_for_cve`** - Fetch Microsoft Security Response Center data

### **💬 Natural Language Examples:**

- *"Get comprehensive analysis for CVE-2024-3400"*
- *"Find all public exploits for CVE-2023-44487"*
- *"Check if CVE-2024-1234 is in the CISA KEV catalog"*
- *"Calculate the Viper risk score for CVE-2023-5678 and save to database"*
- *"Analyze CVE-2024-0001 with Gemini AI and generate alerts"*
- *"Perform comprehensive analysis of CVE-2023-44487 - get NVD data, EPSS score, check CISA KEV, search for exploits, run Gemini analysis, and calculate risk score"*
- *"Analyze CVE-2024-3400 (PAN-OS vulnerability) with complete Viper analysis"*
- *"Give me everything about CVE-2024-3400 - NVD data, EPSS, KEV status, exploits, AI analysis, risk score, and alerts"*

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

2. **See the [Configuration Guide](CONFIGURATION_GUIDE.md)** for complete setup instructions

## 📚 Documentation

📖 **Complete documentation is available in the [docs/](docs/) directory:**

- **[Configuration Guide](CONFIGURATION_GUIDE.md)** - MCP server setup and environment configuration
- **[Getting Started Guide](docs/MCP_SERVER_README.md)** - MCP server setup and configuration
- **[Technical Implementation](docs/MCP_IMPLEMENTATION_SUMMARY.md)** - Comprehensive technical overview
- **[Development Guide](docs/DEVELOPMENT.md)** - Development setup and contribution guidelines
- **[Database Troubleshooting](docs/DATABASE_TROUBLESHOOTING.md)** - Database configuration and common issues
- **[Docker Deployment](docs/DOCKER.md)** - Containerization and deployment instructions

👉 **Start here:** [docs/README.md](docs/README.md) for complete navigation

## 📋 Table of Contents

1.  [🎯 Screenshots](#-dashboard)
2.  [✨ Core Features](#-core-features)
3.  [🛠️ Live CVE Lookup](#-live-cve-lookup)
4.  [🛠️ Technology Stack](#-tech-stack)
5.  [🚀 Installation & Setup](#-installation--setup)
6.  [⚙️ Usage](#-usage)
7.  [🗂️ Project Structure](#project-structure)
8.  [🔍 Public Exploit Search](#-public-exploit-search)
9.  [📈 Development Status & Roadmap](#-project-roadmap--future-vision)

---
## Dashboard

VIPER provides a comprehensive dashboard for visualizing and analyzing vulnerability data:

### Home Screen
![Home](https://i.imgur.com/5Ri40Oc.png)

### Main Dashboard
![Dashboard](https://i.imgur.com/GEHUX22.png)

### Detailed Analysis View
![Detailed Analysis](https://i.imgur.com/iGYK3Us.png)

### Live CVE Lookup
![Live CVE Lookup](https://i.imgur.com/sUouPLV.png)

### Analytics & Trends
![Analytics](https://i.imgur.com/HPlHdpR.png)


## ✨ Core Features

* **Multi-Source Data Ingestion:**
    * ✅ **NVD (National Vulnerability Database):** Up-to-the-minute CVE information.
    * ✅ **EPSS (Exploit Prediction Scoring System):** Likelihood of vulnerability exploitation.
    * ✅ **CISA KEV (Known Exploited Vulnerabilities) Catalog:** Confirmed actively exploited vulnerabilities.
    * ✅ **Microsoft Patch Tuesday Updates:** Security bulletins and patch information.
    * ✅ **Public Exploit Repositories:** Search for available exploits from Exploit-DB and GitHub.
* **AI-Powered Analysis & Prioritization:**
    * 🧠 Deep contextual analysis of CVE descriptions and related data using **Google Gemini AI**.
    * Automated priority assignment (HIGH, MEDIUM, LOW) based on AI assessment.
    * **🆕 Claude Desktop Integration:** Natural language vulnerability analysis through MCP protocol.
* **Comprehensive Risk Scoring:**
    * 📈 Customizable weighted risk scoring combining CVSS, EPSS, KEV status, Microsoft severity, and Gemini AI analysis.
    * Configurable boost factor for vulnerabilities present in the CISA KEV catalog.
* **Automated Alert Generation:**
    * 🔔 Configurable rules engine to generate alerts for critical vulnerabilities based on EPSS scores, CVSS & EPSS combinations, keyword matches, KEV status, and AI-assigned priority.
* **Centralized & Enriched Data Storage:**
    * 🗄️ SQLite database for all collected and enriched vulnerability intelligence.
    * Mechanisms to prevent duplicate data processing and storage.
* **Multiple Access Interfaces:**
    * 🖥️ **Interactive Streamlit Dashboard:** User-friendly web interface for data exploration and analysis.
    * 💻 **CLI Mode:** For backend data processing, fetching, and analysis.
    * 🤖 **Claude Desktop MCP Integration:** Natural language vulnerability analysis with 12 specialized tools.
* **Advanced Features:**
    * Advanced filtering (date range, priority, CVSS, EPSS, KEV status, keywords).
    * Key Performance Indicator (KPI) metrics and summary statistics.
    * Detailed CVE views with all enriched data points.
    * Trend analysis and visualizations powered by Plotly.
    * 🔎 **Live CVE Lookup:** Real-time search and analysis of any CVE from NVD.
* **Resilient API Clients:**
    * 💪 Automated retry mechanisms with exponential backoff for API calls (`tenacity` library).
* **Flexible Configuration:**
    * ⚙️ Easy management of all critical parameters (API keys, model names, thresholds, weights) via a `.env` file.
* **Modular and Extensible Architecture:**
    * 🏗️ Designed for straightforward integration of new data sources and analysis modules.

## 🔍 Live CVE Lookup

The Live CVE Lookup feature allows you to perform real-time analysis of any CVE:

* **Instant CVE Lookups:** Enter any CVE ID to get comprehensive details.
* **Local Database First:** Checks your local database before making external API calls.
* **Dynamic Data Enrichment:**
  * NVD data with descriptions, CVSS scores, references, and affected products
  * EPSS exploitation probability scores
  * CISA KEV status verification
  * Live Gemini AI analysis and priority assignment
  * Real-time risk scoring and alert generation
* **Save to Database:** Option to save or update the analyzed CVE in your local database for future reference.

This feature is ideal for:
* Investigating breaking vulnerabilities as they're published
* Ad-hoc analysis of CVEs mentioned in threat reports
* Quick verification of vulnerability details during incident response

## 🚀 Tech Stack

* **Backend & Analysis:** Python
* **AI Models:** Google Gemini, Claude (via MCP)
* **MCP Integration:** Model Context Protocol server for Claude Desktop
* **Web Interface/Dashboard:** Streamlit
* **Database:** SQLite
* **API Clients:** `requests`, `google-generativeai`
* **Data Manipulation:** Pandas, NumPy
* **Visualization:** Plotly
* **Error Handling & Retries:** `tenacity`
* **Configuration:** `python-dotenv`
* **Logging:** `logging`

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

The setup script will:
- ✅ Create virtual environment
- ✅ Install dependencies
- ✅ Create `.env` from template
- ✅ Set up directory structure
- ✅ Configure MCP script permissions

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

1. **Make the MCP runner executable:**
   ```bash
   chmod +x run_mcp_clean.sh
   ```

2. **Configure Claude Desktop** by adding to your MCP settings:
   ```json
   {
     "mcpServers": {
       "ViperMCPServer": {
         "command": "/FULL/PATH/TO/YOUR/viper/run_mcp_clean.sh"
       }
     }
   }
   ```
   **Note:** Replace `/FULL/PATH/TO/YOUR/viper/` with the actual path to your VIPER installation.

3. **Restart Claude Desktop** to load the MCP server

### 6. **Verify Installation:**

Test the CLI interface:
```bash
python main.py cli --days 1
```

Test the MCP server (if configured):
```bash
echo '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}' | ./run_mcp_clean.sh
```

**See the [Configuration Guide](CONFIGURATION_GUIDE.md) for detailed setup instructions and troubleshooting.**

## 🐳 Docker Deployment

VIPER can be deployed using Docker for easy setup and management.
For detailed Docker deployment instructions, database management, and troubleshooting, see [DOCKER.md](DOCKER.md).



## ⚙️ Usage

VIPER can be operated through three primary interfaces:

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

**Available Tools:**
- `perform_live_cve_lookup` - Complete real-time CVE analysis
- `get_nvd_cve_details` - NVD database lookups
- `search_public_exploits_for_cve` - GitHub/Exploit-DB searches
- `get_gemini_cve_analysis` - AI-powered vulnerability analysis
- `get_viper_risk_score` - Multi-factor risk calculation
- And 7 more specialized tools...

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

The dashboard provides:
- Interactive filtering of vulnerabilities
- Visualizations of vulnerability distributions
- Detailed analysis of individual CVEs
- Risk scoring and alert information
- CISA KEV catalog integration
- Microsoft Patch Tuesday analysis
- Live CVE lookup and real-time analysis


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

## Risk Scoring

VIPER calculates a combined risk score for each vulnerability using:
- Gemini AI priority assessment (HIGH, MEDIUM, LOW)
- CVSS v3 score (0-10 scale)
- EPSS score (probability of exploitation)
- CISA KEV status (with a customizable boost factor)
- Microsoft severity rating (Critical, Important, Moderate, Low)
- Public exploit availability (with a customizable boost factor)

The weights for each factor can be configured via environment variables:
- `RISK_WEIGHT_GEMINI` (default: 0.4)
- `RISK_WEIGHT_CVSS` (default: 0.3)
- `RISK_WEIGHT_EPSS` (default: 0.3)
- `RISK_WEIGHT_MS_SEVERITY` (default: 0.2)
- `KEV_BOOST_FACTOR` (default: 0.5)
- `PUBLIC_EXPLOIT_BOOST_FACTOR` (default: 0.15) - Boosts risk scores for CVEs with confirmed public exploits

## Alert Generation

VIPER generates alerts based on configurable rules:
1. Critical Exploitability Risk - CVEs with very high EPSS scores
2. Severe Impact & Likely Exploit - High CVSS score combined with significant EPSS score
3. High Impact Technique - CVEs matching specific keywords with substantial EPSS scores
4. AI Flagged - CVEs rated as HIGH priority by Gemini AI
5. CISA KEV Status - CVEs in the CISA Known Exploited Vulnerabilities catalog
6. Microsoft Critical - CVEs rated as Critical severity by Microsoft

Alert thresholds can be configured via environment variables (see config.py).

## PDF Export Feature

VIPER provides the ability to export detailed vulnerability analysis reports as PDF documents.

### Using the PDF Export Feature

1. Navigate to the "Detailed Vulnerability Analysis" page in the dashboard
2. Select a CVE from the dropdown menu to view its details
3. Scroll to the bottom of the vulnerability details
4. Click the "Export Analysis Report (PDF)" button
5. Save the generated PDF to your preferred location

### What's Included in the PDF Report

The PDF report includes:

- **Summary Information**: CVE ID, priority level, CISA KEV status, etc.
- **Description**: The full vulnerability description
- **Risk Metrics**: CVSS score, EPSS score, risk score, etc.
- **AI Analysis**: The AI assessment of the vulnerability
- **Alerts and Concerns**: Any specific alerts related to the vulnerability
- **Recommended Actions**: Mitigation recommendations based on priority level
- **References**: Links to relevant resources
- **Affected Products**: CPE entries for affected systems

## 🔍 Public Exploit Search

The Public Exploit Search feature allows VIPER to search for and identify publicly available exploits for vulnerabilities, adding critical context to your risk assessments:

* **Multi-Source Exploit Search:**
  * Searches Exploit-DB for known exploits related to CVEs
  * Searches GitHub repositories and code for exploit proof-of-concepts
  * Results are cached to minimize API calls

### GitHub Exploit Search

VIPER includes robust functionality to search GitHub for exploits and proof-of-concept code related to CVEs:

* **Comprehensive GitHub Search:**
  * Searches both repositories and code files for each CVE
  * Uses multiple targeted queries (`exploit`, `PoC`, `proof of concept`)
  * Filters results to find genuine exploits using content analysis
  * Includes repository metadata such as star count and descriptions

### Automatic Exploit Scanning

VIPER now automatically searches for public exploits as part of its standard workflow:

1. **Integrated in Main Workflow:**
   * HIGH priority CVEs are automatically checked for public exploits
   * Results are stored in the database and considered in risk scoring
   * Performance-optimized to only search for exploits for the most critical vulnerabilities

2. **Full Database Scanning:**
   * You can trigger a CVE scan for public exploits with:
     ```
     # Scan only HIGH priority CVEs (default, faster)
     python src/scripts/scan_exploits.py

     # Scan all CVEs regardless of priority (slower but comprehensive)
     python src/scripts/scan_exploits.py --priority=all
     ```
   * Options:
     - `--priority=high|all` - Which priority level to scan (defaults to 'high')
     - `--max-cves=100` - Limit scan to a certain number of CVEs
     - `--delay=2` - Set delay between API calls to avoid rate limiting

3. **Scheduled Scanning:**
   * For production deployments, consider scheduling regular exploit scans:
     ```
     # Example crontab entry (scan HIGH priority CVEs weekly on Sunday at 1:00 AM)
     0 1 * * 0 cd /path/to/viper && python src/scripts/scan_exploits.py >> logs/exploit_scan_cron.log 2>&1
     ```

### GitHub API Configuration

To enable GitHub exploit searching, you need to set up a GitHub Personal Access Token:

1. **Generate a GitHub Personal Access Token**:
   - Go to GitHub → Settings → Developer settings → Personal access tokens
   - Create a token with the `public_repo` scope (this is enough for searching public repositories)
   - For newer GitHub accounts, you'll need to create a "Fine-grained token" or a "Classic token"

2. **Add the token to your .env file**:
   ```
   GITHUB_TOKEN=your_github_token_here
   ```

3. **Additional exploit search configuration options**:
   ```
   # GitHub API URL (defaults to https://api.github.com)
   GITHUB_API_URL=https://api.github.com

   # Exploit-DB API URL (defaults to https://exploits.shodan.io/api)
   EXPLOIT_DB_API_URL=https://exploits.shodan.io/api

   # Maximum results per exploit source (defaults to 10)
   EXPLOIT_SEARCH_MAX_RESULTS=10

   # Risk score boost for vulnerabilities with public exploits (0.0-1.0, defaults to 0.15)
   PUBLIC_EXPLOIT_BOOST_FACTOR=0.15
   ```

If no GitHub token is provided, the system will skip GitHub searches and only use Exploit-DB as a source.

## API Integration

### NVD API
VIPER integrates with the National Vulnerability Database API to:
- Fetch recent CVEs based on specified time periods
- Look up detailed information for specific CVEs
- Extract CVSS scores, descriptions, and affected products

### EPSS API
Integration with the FIRST.org EPSS API provides:
- Probability scores for vulnerability exploitation
- Percentile ranking for exploitation likelihood
- Both batch and single-CVE lookup capabilities

### CISA KEV API
Integration with the CISA Known Exploited Vulnerabilities catalog provides:
- Status checks for whether CVEs are actively exploited
- Dates when vulnerabilities were added to the KEV catalog
- Vendor and product information when available

### Microsoft Security Update API
Integration with the Microsoft Security Response Center (MSRC) API provides:
- Patch Tuesday update information
- Security bulletin details
- Microsoft-specific vulnerability information and severity ratings

### Exploit Database & GitHub API
Integration with public exploit repositories provides:
- Identification of publicly available exploits for CVEs
- Details and links to exploit code
- Enhanced risk assessment based on exploit availability

## Dependencies

- `requests` - For making HTTP requests to the NVD, EPSS, CISA, and Microsoft APIs
- `python-dotenv` - For loading environment variables from .env file
- `google-generativeai` - For interacting with the Google Gemini API
- `tenacity` - For robust error handling and retry logic
- `streamlit` - For the interactive dashboard
- `pandas` - For data manipulation
- `plotly` - For interactive visualizations
- `numpy` - For numerical operations


## Project Roadmap & Future Vision

VIPER aims to be a comprehensive, AI-driven Cyber Threat Intelligence (CTI) platform, drawing inspiration from advanced, multi-layered CTI systems. Our current version provides a strong foundation with NVD, EPSS, CISA KEV, and Microsoft MSRC data ingestion, coupled with Gemini AI for analysis, risk scoring, and an interactive Streamlit dashboard with real-time CVE lookup.

Here's where we're headed:

### Phase 1: Core Enhancements & Data Completeness (Immediate Focus)

* **Full NVD API Pagination:** Ensure complete ingestion of all relevant CVEs from NVD by implementing robust pagination in `nvd_client.py` to handle large result sets (addressing current partial data fetching ).
* **Solidify Retry Mechanisms:** Continuously refine and test `tenacity` based retry logic across all external API clients (`nvd_client.py`, `epss_client.py`, `cisa_kev_client.py`, `microsoft_update_client.py`, `gemini_analyzer.py`) for maximum resilience.
* **Dashboard Usability & Features:**
    * Refine real-time CVE lookup: Optimize display and ensure all enrichment (EPSS, KEV, MSData, Gemini re-analysis) is available for live queries.
    * Enhance filtering and sorting options on all data tables.
    * Implement detailed CVE view modals or dedicated pages for better readability of all enriched data.
* **Automated Periodic Execution:** Integrate `APScheduler` or configure system `cron` jobs to run the `main_mvp.py` data pipeline automatically at configurable intervals.

### Phase 2: Expanding Data Ingestion & Enrichment

* **[ ] MalwareBazaar Integration:**
    * Fetch data on recent malware samples, hashes, and associated threat intelligence.
    * Store and display this information, potentially linking malware IOCs to CVEs or threat actors.
* **[ ] Other CISA Products & Feeds:**
    * Explore and integrate other relevant CISA feeds beyond the KEV catalog (e.g., CISA Alerts, Industrial Control Systems Advisories if applicable).
* **[ ] Comprehensive Microsoft Patch Tuesday Parsing:**
    * Further refine `microsoft_update_client.py` to ensure accurate and detailed extraction of product families, specific product versions, and direct links to KB articles/MSRC guidance from CVRF/CSAF data.

### Phase 3: Developing "Threat Analyst Agent" Capabilities

* **[ ] Semantic Web Search Integration (e.g., EXA AI):**
    * For high-priority CVEs or emerging threats, automatically search the web for technical analyses, blog posts, news articles, and threat actor reports.
    * Store relevant article metadata (URL, title, snippet, source) linked to CVEs.
* **[ ] AI-Powered Content Analysis (Gemini):**
    * **Summarization:** Use Gemini to summarize fetched articles and reports related to a CVE.
    * **Key Information Extraction:** Extract TTPs (Tactics, Techniques, and Procedures), affected software/hardware, and potential mitigations from unstructured text.
    * **Cross-Validation Support:** Assist analysts by comparing information from different sources regarding a specific threat.

### Phase 4: Building "Threat Hunting Agent" Foundations

* **[ ] Enhanced IOC Extraction:**
    * Expand IOC (IPs, domains, hashes, URLs, mutexes, registry keys) extraction from all ingested text sources (NVD descriptions, MSRC summaries, KEV details, fetched articles) using Gemini's advanced understanding or specialized libraries like `iocextract`.
    * Create a robust, searchable IOC database.
* **[ ] Natural Language to Query Translation (Advanced):**
    * Leverage Gemini to translate natural language threat hunting hypotheses (e.g., "Are there any Cobalt Strike beacons communicating with newly registered domains?") into structured query formats like OCSF, KQL (Azure Sentinel), or Splunk SPL.

### Phase 5: Broader Intelligence Gathering & Advanced Analytics

* **[ ] Social Media Monitoring & Clustering (Advanced):**
    * Ingest data from platforms like Twitter/X or specific Reddit communities (e.g., r/netsec) for early signals of new vulnerabilities or exploits.
    * Apply LLM-based semantic clustering (Gemini) to group discussions and identify emerging threat trends.
* **[ ] Threat Actor & Malware Profiling:**
    * Begin associating CVEs and IOCs with known threat actors and malware families (potentially integrating with MISP or other OSINT feeds).
    * Visualize these relationships in the dashboard.
* **[ ] Advanced Dashboard Analytics:**
    * Implement more sophisticated trend analysis, predictive insights (beyond EPSS), and customizable reporting features.

### Phase 6: Platform Maturity & Usability

* **[ ] User Accounts & Collaboration (Long-term):** Allow multiple users, role-based access, and collaborative analysis features (e.g., shared notes, investigation assignments).
* **[ ] Notification System:** Implement email or other notifications for high-priority alerts or newly discovered critical CVEs matching predefined criteria.
* **[ ] Database Optimization/Migration:** For larger deployments, consider migrating from SQLite to a more scalable database like PostgreSQL.

This roadmap is ambitious and will evolve. Community contributions and feedback are highly encouraged as we build VIPER into a powerful open-source CTI tool!
