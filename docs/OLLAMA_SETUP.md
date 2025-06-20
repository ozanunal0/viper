# 🦙 Ollama Configuration Guide for VIPER

Quick guide to set up Ollama as a local LLM provider for VIPER.

## Quick Setup

```bash
# 1. Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# 2. Download recommended model
ollama pull deepseek-r1:latest

# 3. Configure VIPER
echo "LLM_PROVIDER=ollama" >> .env
echo "LOCAL_LLM_MODEL_NAME=deepseek-r1:latest" >> .env

# 4. Test
curl http://localhost:11434/api/tags
```

## Recommended Models

| Model | Size | RAM | Best For |
|-------|------|-----|----------|
| **deepseek-r1:latest** | 8.2B | 8GB | Vulnerability analysis |
| **llama3.1:8b** | 8B | 8GB | General purpose |
| **llama3.1:70b** | 70B | 64GB | High accuracy |

## Configuration

Add to `.env`:
```bash
LLM_PROVIDER=ollama
OLLAMA_API_BASE_URL=http://localhost:11434
LOCAL_LLM_MODEL_NAME=deepseek-r1:latest
```

## Common Issues

**Service not running:**
```bash
ollama serve
```

**Model not found:**
```bash
ollama pull deepseek-r1:latest
```

**Out of memory:**
```bash
ollama pull llama3.1:8b  # Use smaller model
```

## Docker Setup

```yaml
services:
  ollama:
    image: ollama/ollama:latest
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama
volumes:
  ollama_data:
```

That's it! VIPER will now use local AI processing for privacy and cost savings.
