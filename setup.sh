#!/bin/bash

# VIPER Setup Script
# This script helps set up VIPER for new installations

set -e  # Exit on any error

echo "🛡️  VIPER Setup Script"
echo "====================="

# Get project directory
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "📍 Project directory: $PROJECT_DIR"

# Check Python version
echo "🐍 Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 not found. Please install Python 3.9 or higher."
    exit 1
fi

python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "✅ Found Python $python_version"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment already exists"
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "📈 Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "📚 Installing dependencies..."
pip install -r requirements.txt

# Copy environment template if .env doesn't exist
if [ ! -f ".env" ]; then
    if [ -f "env.example" ]; then
        echo "📋 Creating .env from template..."
        cp .env.example .env
        echo "✅ Created .env file from env.example"
        echo "⚠️  IMPORTANT: Please edit .env and add your API keys"
    else
        echo "⚠️  Warning: env.example not found. You'll need to create .env manually."
    fi
else
    echo "✅ .env file already exists"
fi

# Make MCP script executable
if [ -f "run_mcp_clean.sh" ]; then
    chmod +x run_mcp_clean.sh
    echo "✅ Made run_mcp_clean.sh executable"
fi

# Create data directory
mkdir -p data
echo "✅ Created data directory"

# Create logs directory
mkdir -p logs
echo "✅ Created logs directory"

echo ""
echo "🎉 Setup complete!"
echo ""
echo "📝 Next steps:"
echo "1. Edit .env file and add your API keys:"
echo "   - GEMINI_API_KEY (required)"
echo "   - GITHUB_TOKEN (recommended)"
echo "   - NVD_API_KEY (optional)"
echo ""
echo "2. Test the installation:"
echo "   python main.py cli --days 1"
echo ""
echo "3. For Claude Desktop MCP integration:"
echo "   - Add to Claude Desktop config:"
echo "   {\"mcpServers\": {\"ViperMCPServer\": {\"command\": \"$PROJECT_DIR/run_mcp_clean.sh\"}}}"
echo "   - See CONFIGURATION_GUIDE.md for details"
echo ""
echo "4. Start the dashboard:"
echo "   python main.py dashboard"
echo ""
echo "📖 For detailed configuration, see:"
echo "   - README.md"
