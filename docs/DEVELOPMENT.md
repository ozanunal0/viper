# Development Guide

## Quick Start

### 1. Clone & Setup
```bash
git clone https://github.com/ozanunal0/viper.git
cd viper
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

### 2. Environment Config
```bash
cp env.example .env
# Edit .env with your API keys
```

### 3. Database Setup
```bash
python src/initialize_db.py
```

## Development Workflow

### Run Tests
```bash
pytest tests/
```

### Code Quality
```bash
flake8 src/
black src/
pre-commit run --all-files
```

### Local Development
```bash
# Dashboard
python main.py dashboard

# CLI
python main.py cli --days 7

# MCP Server Test
python -m src.mcp_server_demo
```

## Project Structure

```
src/
├── mcp_server.py           # MCP integration
├── main_mvp.py             # CLI application
├── clients/                # API clients
├── dashboard/              # Streamlit UI
├── utils/                  # Utilities
├── gemini_analyzer.py      # AI analysis
└── risk_analyzer.py        # Risk scoring
```

## Adding Features

### New Data Source
1. Create client in `src/clients/`
2. Add integration to `main_mvp.py`
3. Update database schema if needed

### New MCP Tool
1. Add async method to `ViperMCPServer`
2. Register in `_register_tools()`
3. Add tests and documentation

### Dashboard Page
1. Create in `src/dashboard/pages/`
2. Follow existing patterns
3. Update navigation

## Configuration

Key environment variables:
- `GEMINI_API_KEY` - Required for AI features
- `GITHUB_TOKEN` - Enhanced exploit search
- `NVD_API_KEY` - Higher rate limits

## Database

SQLite database: `data/viper.db`
- Schema: See `src/utils/database_handler.py`
- Migrations: Manual (add to `initialize_db.py`)

## Contributing

1. Fork repository
2. Create feature branch
3. Follow code quality checks
4. Add tests for new features
5. Submit pull request
