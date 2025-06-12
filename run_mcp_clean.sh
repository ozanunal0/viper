#!/bin/bash

# Clean MCP Server Runner for Viper
# This script runs the MCP server with proper error handling and dependency checks

# Get the directory where this script is located (project root)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Navigate to project directory
cd "$SCRIPT_DIR"

# Function to log debug messages (only when not in Claude Desktop)
debug_log() {
    # Only log if stderr is a terminal AND not being called by Claude Desktop
    if [ -t 2 ] && [ -z "$CLAUDE_DESKTOP" ] && [ -z "$MCP_CONTEXT" ]; then
        echo "$1" >&2
    fi
}

# Load environment variables from .env file if it exists
if [ -f ".env" ]; then
    debug_log "Loading environment variables from .env file..."
    # Export variables from .env file, ignoring comments and empty lines
    set -a  # Automatically export all variables
    source .env
    set +a  # Turn off automatic export
fi

# Function to check if a Python package is installed
check_python_package() {
    python3 -c "import $1" 2>/dev/null
    return $?
}

debug_log "Starting Viper MCP Server..."
debug_log "Project directory: $SCRIPT_DIR"

# Check if virtual environment exists, if not create it
if [ ! -d "venv" ]; then
    debug_log "Virtual environment not found. Creating one..."
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to create virtual environment" >&2
        exit 1
    fi
fi

# Activate virtual environment
source venv/bin/activate

# Check if activation was successful
if [ -z "$VIRTUAL_ENV" ]; then
    echo "ERROR: Failed to activate virtual environment" >&2
    exit 1
fi

debug_log "Virtual environment activated: $VIRTUAL_ENV"

# Install dependencies if they're missing
if [ -f "requirements.txt" ]; then
    debug_log "Checking dependencies..."

    # Check for key dependencies
    if ! check_python_package "tenacity"; then
        debug_log "Installing missing dependencies..."
        pip install -r requirements.txt >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo "ERROR: Failed to install dependencies" >&2
            exit 1
        fi
        debug_log "Dependencies installed successfully"
    fi
fi

# Check for EXA API key
if [ -z "$EXA_API_KEY" ]; then
    debug_log "WARNING: EXA_API_KEY not set in environment variables"
    debug_log "EXA AI features may not work properly"
fi

# Set Python path to include project root for imports
export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"

debug_log "PYTHONPATH set to: $PYTHONPATH"
debug_log "Starting MCP server..."

# Run the MCP server cleanly - no stderr redirection for Claude Desktop compatibility
exec python3 -m src.mcp_server
