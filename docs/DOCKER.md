# Running VIPER in Docker

This document explains how to run the VIPER Vulnerability Intelligence Platform using Docker.

## Prerequisites

- Docker installed on your system
- Docker Compose installed on your system

## Setup

1. Copy the example environment file and set your API keys:

```bash
cp .env.example .env
```

2. Edit the `.env` file to add your API keys:
   - `GEMINI_API_KEY`: Your Google Gemini API key
   - `GITHUB_TOKEN`: Your GitHub personal access token
   - Other configuration as needed

## Running with Docker Compose

1. Build the application:

```bash
docker-compose build
```

2. Start the application:

```bash
docker-compose up -d
```

3. Access the VIPER dashboard at: http://localhost:8501

4. Stop the application:

```bash
docker-compose down
```

## Data Persistence

The Docker setup includes a volume mount for the `/app/data` directory, which stores:

- SQLite database containing vulnerability data
- Any other persisted data

The data will be stored in the `./data` directory on your host machine.

### Database Path Configuration

It's important to understand how database paths work in the Docker environment:

- Inside the container: The database is located at `/app/data/threat_intel_gemini_mvp.db`
- On your host machine: The same file is at `./data/threat_intel_gemini_mvp.db` (relative to where you run docker-compose)

This is configured in two places:

1. `docker-compose.yml`: Sets the environment variable `DB_FILE_NAME=/app/data/threat_intel_gemini_mvp.db`
2. Volume mapping: `-./data:/app/data` makes these paths point to the same files

If you need to run VIPER both inside Docker and directly on your host, be aware that your local `.env` configuration might use a different path. For local development without Docker, consider using `DB_FILE_NAME=data/threat_intel_gemini_mvp.db` (a relative path).

## Database Management

VIPER is designed to automatically handle common database issues like duplicate columns during initialization.

### Database Troubleshooting

If you encounter database issues, you have these options:

1. **Database Reset:**

   If you need to completely reset your database:

   ```bash
   docker exec -it viper python scripts/reset_database.py
   ```

2. **Remove Volume and Restart:**

   As a last resort, you can remove the data volume and restart:

   ```bash
   docker-compose down -v
   docker-compose up -d
   ```

### Common Database Errors

**Error: "duplicate column name: risk_score"**

This error occurs when the application tries to add columns that already exist. Recent updates have improved handling of this issue by automatically detecting and skipping duplicate columns. The application will continue normally even if this warning appears during initialization.

## Environment Variables

You can customize the application by setting environment variables in the `.env` file or directly in the `docker-compose.yml` file.

Key variables:

| Variable | Description |
|----------|-------------|
| `GEMINI_API_KEY` | Google Gemini API key for AI analysis |
| `GITHUB_TOKEN` | GitHub token for searching exploit repositories |
| `DB_FILE_NAME` | Path to the SQLite database file |
| `LOG_LEVEL` | Logging level (INFO, DEBUG, etc.) |

## Building the Image Manually

If you need to build the Docker image manually:

```bash
docker build -t viper-app .
```

Then run it:

```bash
docker run -p 8501:8501 -v ./data:/app/data viper-app
```

## Troubleshooting

1. If you can't access the app, check if it's running:

```bash
docker ps
```

2. Check application logs:

```bash
docker-compose logs viper-app
```

3. If you're having database issues, check the volume permissions:

```bash
ls -la ./data
```
