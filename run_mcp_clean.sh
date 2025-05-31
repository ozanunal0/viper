#!/bin/bash

# Clean MCP Server Runner for Viper
# This script runs the MCP server without debug logging to avoid protocol interference

# Get the directory where this script is located (project root)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Navigate to project directory
cd "$SCRIPT_DIR"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "ERROR: Virtual environment not found at venv/" >&2
    echo "Please run: python -m venv venv && source venv/bin/activate && pip install -r requirements.txt" >&2
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Check if activation was successful
if [ -z "$VIRTUAL_ENV" ]; then
    echo "ERROR: Failed to activate virtual environment" >&2
    exit 1
fi

# Set Python path to include project root for imports
export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"

# Run the MCP server cleanly from project root (not from src directory)
# Redirect stderr to debug log but keep critical errors visible
exec python -m src.mcp_server 2>/tmp/viper_mcp_debug.log
