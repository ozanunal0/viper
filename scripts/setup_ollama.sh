#!/bin/bash

# 🦙 Ollama Setup Script for VIPER
# This script automates the Ollama installation and configuration process

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
        echo "windows"
    else
        echo "unknown"
    fi
}

# Function to install Ollama
install_ollama() {
    local os=$(detect_os)

    print_status "Installing Ollama for $os..."

    case $os in
        "linux"|"macos")
            if command_exists curl; then
                curl -fsSL https://ollama.com/install.sh | sh
            else
                print_error "curl is required but not installed. Please install curl first."
                exit 1
            fi
            ;;
        "windows")
            print_warning "Please download Ollama from https://ollama.com/download/windows"
            print_warning "This script cannot automatically install on Windows."
            exit 1
            ;;
        *)
            print_error "Unsupported operating system: $os"
            exit 1
            ;;
    esac
}

# Function to start Ollama service
start_ollama() {
    print_status "Starting Ollama service..."

    # Check if Ollama is already running
    if curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
        print_success "Ollama is already running"
        return 0
    fi

    # Try to start Ollama
    if command_exists systemctl; then
        # Try systemd first
        if systemctl is-active --quiet ollama 2>/dev/null; then
            print_success "Ollama service is already active"
        else
            print_status "Starting Ollama with systemd..."
            sudo systemctl start ollama 2>/dev/null || {
                print_warning "Systemd service not available, starting manually..."
                nohup ollama serve > ollama.log 2>&1 &
                sleep 3
            }
        fi
    else
        # Start manually
        print_status "Starting Ollama manually..."
        nohup ollama serve > ollama.log 2>&1 &
        sleep 3
    fi

    # Verify Ollama is running
    local retries=0
    while [ $retries -lt 10 ]; do
        if curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
            print_success "Ollama is running successfully"
            return 0
        fi
        print_status "Waiting for Ollama to start... (attempt $((retries + 1))/10)"
        sleep 2
        retries=$((retries + 1))
    done

    print_error "Failed to start Ollama after 10 attempts"
    return 1
}

# Function to install recommended model
install_model() {
    local model=${1:-"deepseek-r1:latest"}

    print_status "Installing model: $model"
    print_warning "This may take several minutes depending on your internet connection..."

    if ollama pull "$model"; then
        print_success "Model $model installed successfully"
    else
        print_error "Failed to install model $model"
        print_status "Trying alternative model: llama3.1:8b"
        if ollama pull llama3.1:8b; then
            print_success "Alternative model llama3.1:8b installed successfully"
            model="llama3.1:8b"
        else
            print_error "Failed to install any model"
            return 1
        fi
    fi

    echo "$model"
}

# Function to update VIPER configuration
update_viper_config() {
    local model="$1"
    local env_file=".env"

    print_status "Updating VIPER configuration..."

    # Create .env file if it doesn't exist
    if [ ! -f "$env_file" ]; then
        print_status "Creating new .env file..."
        cat > "$env_file" << EOF
# LLM Provider Configuration
LLM_PROVIDER=ollama

# Ollama Configuration
OLLAMA_API_BASE_URL=http://localhost:11434
LOCAL_LLM_MODEL_NAME=$model

# Required API Keys
GEMINI_API_KEY=your_gemini_api_key_here
GITHUB_TOKEN=your_github_token_here

# Database Configuration
DB_FILE_NAME=data/viper.db

# Logging Configuration
LOG_LEVEL=INFO
LOG_FILE_NAME=logs/viper.log
EOF
    else
        print_status "Updating existing .env file..."

        # Update or add LLM provider settings
        if grep -q "LLM_PROVIDER=" "$env_file"; then
            sed -i.bak 's/LLM_PROVIDER=.*/LLM_PROVIDER=ollama/' "$env_file"
        else
            echo "LLM_PROVIDER=ollama" >> "$env_file"
        fi

        if grep -q "OLLAMA_API_BASE_URL=" "$env_file"; then
            sed -i.bak 's|OLLAMA_API_BASE_URL=.*|OLLAMA_API_BASE_URL=http://localhost:11434|' "$env_file"
        else
            echo "OLLAMA_API_BASE_URL=http://localhost:11434" >> "$env_file"
        fi

        if grep -q "LOCAL_LLM_MODEL_NAME=" "$env_file"; then
            sed -i.bak "s/LOCAL_LLM_MODEL_NAME=.*/LOCAL_LLM_MODEL_NAME=$model/" "$env_file"
        else
            echo "LOCAL_LLM_MODEL_NAME=$model" >> "$env_file"
        fi

        # Remove backup file
        rm -f "$env_file.bak"
    fi

    print_success "VIPER configuration updated"
}

# Function to test integration
test_integration() {
    print_status "Testing Ollama integration with VIPER..."

    # Check if Python virtual environment exists
    if [ -d "venv" ]; then
        source venv/bin/activate
    fi

    # Test basic connectivity
    if curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
        print_success "✅ Ollama API is accessible"
    else
        print_error "❌ Cannot connect to Ollama API"
        return 1
    fi

    # Test VIPER integration if Python is available
    if command_exists python3; then
        print_status "Testing VIPER integration..."
        python3 -c "
import sys
sys.path.append('.')
try:
    from src.utils.config import get_llm_provider, get_ollama_api_base_url, get_local_llm_model_name
    provider = get_llm_provider()
    url = get_ollama_api_base_url()
    model = get_local_llm_model_name()
    print(f'✅ Provider: {provider}')
    print(f'✅ URL: {url}')
    print(f'✅ Model: {model}')
except Exception as e:
    print(f'❌ Error: {e}')
    sys.exit(1)
" 2>/dev/null && print_success "VIPER configuration is valid" || print_warning "Could not validate VIPER configuration"
    fi
}

# Function to show status
show_status() {
    print_status "Ollama Status:"
    echo "===================="

    # Check if Ollama is running
    if curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
        echo "🟢 Ollama Service: Running"

        # Show installed models
        echo "📦 Installed Models:"
        ollama list 2>/dev/null | tail -n +2 || echo "   No models found"

        # Show running models
        echo "🏃 Running Models:"
        ollama ps 2>/dev/null || echo "   No models currently loaded"

    else
        echo "🔴 Ollama Service: Not Running"
    fi

    echo "===================="
}

# Main function
main() {
    echo "🦙 VIPER Ollama Setup Script"
    echo "============================"

    # Parse command line arguments
    INSTALL_OLLAMA=false
    INSTALL_MODEL=""
    SHOW_STATUS=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --install-ollama)
                INSTALL_OLLAMA=true
                shift
                ;;
            --model)
                INSTALL_MODEL="$2"
                shift 2
                ;;
            --status)
                SHOW_STATUS=true
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --install-ollama    Install Ollama if not present"
                echo "  --model MODEL       Install specific model (default: deepseek-r1:latest)"
                echo "  --status           Show current status"
                echo "  --help, -h         Show this help message"
                echo ""
                echo "Examples:"
                echo "  $0                                    # Quick setup with defaults"
                echo "  $0 --install-ollama --model llama3.1:8b"
                echo "  $0 --status"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    # Show status if requested
    if [ "$SHOW_STATUS" = true ]; then
        show_status
        exit 0
    fi

    # Check if Ollama is installed
    if ! command_exists ollama; then
        if [ "$INSTALL_OLLAMA" = true ]; then
            install_ollama
        else
            print_error "Ollama is not installed. Use --install-ollama to install it."
            exit 1
        fi
    else
        print_success "Ollama is already installed"
    fi

    # Start Ollama service
    start_ollama || exit 1

    # Install model
    if [ -n "$INSTALL_MODEL" ] || ! ollama list >/dev/null 2>&1 || [ "$(ollama list | wc -l)" -le 1 ]; then
        model=$(install_model "${INSTALL_MODEL:-deepseek-r1:latest}")
        if [ $? -ne 0 ]; then
            print_error "Failed to install any model"
            exit 1
        fi
    else
        # Use existing model
        model=$(ollama list | tail -n +2 | head -n 1 | awk '{print $1}')
        print_success "Using existing model: $model"
    fi

    # Update VIPER configuration
    update_viper_config "$model"

    # Test integration
    test_integration

    # Show final status
    echo ""
    print_success "🎉 Ollama setup completed successfully!"
    echo ""
    show_status

    echo ""
    print_status "Next steps:"
    echo "1. Start VIPER dashboard: python main.py dashboard"
    echo "2. Go to Live CVE Lookup page"
    echo "3. Test CVE analysis with your local LLM!"
    echo ""
    print_status "For more information, see: docs/OLLAMA_SETUP.md"
}

# Run main function
main "$@"
