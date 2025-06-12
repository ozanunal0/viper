# Docker Deployment

## Quick Start

### Build & Run
```bash
# Build image
docker build -t viper .

# Run with environment
docker run -d \
  -p 8501:8501 \
  -v $(pwd)/data:/app/data \
  -e GEMINI_API_KEY=your_key_here \
  viper
```

### Docker Compose
```bash
# Start services
docker-compose up -d

# Stop services
docker-compose down
```

## Configuration

### Environment Variables
```bash
# Required
GEMINI_API_KEY=your_gemini_api_key

# Optional
GITHUB_TOKEN=your_github_token
NVD_API_KEY=your_nvd_api_key
```

### Volume Mounts
- `./data:/app/data` - Database persistence
- `./logs:/app/logs` - Log files

## Docker Compose Configuration

```yaml
services:
  viper:
    build: .
    ports:
      - "8501:8501"
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
    environment:
      - GEMINI_API_KEY=${GEMINI_API_KEY}
      - GITHUB_TOKEN=${GITHUB_TOKEN}
```

## Troubleshooting

**Common Issues:**

- **Port conflicts**: Change `8501:8501` to `8502:8501`
- **Database errors**: Ensure `./data` directory exists
- **Permission issues**: Check volume mount permissions
- **API errors**: Verify environment variables

**Check logs:**
```bash
docker logs <container_id>
```

**Shell access:**
```bash
docker exec -it <container_id> /bin/bash
```

## Production Deployment

### Recommended Setup
```yaml
services:
  viper:
    image: viper:latest
    restart: unless-stopped
    ports:
      - "8501:8501"
    volumes:
      - viper_data:/app/data
      - viper_logs:/app/logs
    environment:
      - GEMINI_API_KEY=${GEMINI_API_KEY}

volumes:
  viper_data:
  viper_logs:
```

### Health Check
```bash
curl http://localhost:8501/healthz
```
