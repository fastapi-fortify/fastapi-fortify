# Installation Guide

This guide covers the installation and initial setup of FastAPI Guard.

## Requirements

- **Python**: 3.8 or higher
- **FastAPI**: 0.68 or higher
- **Operating System**: Linux, macOS, or Windows

## Installation Methods

### PyPI Installation (Recommended)

```bash
pip install fastapi-guard
```

### Development Installation

For development or to get the latest features:

```bash
git clone https://github.com/your-username/fastapi-guard.git
cd fastapi-guard
pip install -e ".[dev]"
```

### Docker Installation

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install fastapi-guard

COPY . .
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

## Verification

Verify your installation:

```python
import fastapi_fortify
print(f"FastAPI Guard version: {fastapi_fortify.__version__}")
```

## Optional Dependencies

### Redis (Recommended for Production)

For distributed rate limiting and better performance:

```bash
pip install redis
```

### Additional Security Features

For enhanced threat intelligence:

```bash
pip install fastapi-guard[security]
```

### Development Tools

For testing and development:

```bash
pip install fastapi-guard[dev]
```

## Quick Setup

### 1. Basic Integration

```python
from fastapi import FastAPI
from fastapi_fortify import SecurityMiddleware

app = FastAPI()
app.add_middleware(SecurityMiddleware)

@app.get("/")
async def root():
    return {"message": "Hello, secure world!"}
```

### 2. With Configuration

```python
from fastapi import FastAPI
from fastapi_fortify import SecurityMiddleware, SecurityConfig

app = FastAPI()

config = SecurityConfig(
    waf_enabled=True,
    bot_detection_enabled=True,
    rate_limiting_enabled=True,
    ip_blocklist_enabled=True
)

app.add_middleware(SecurityMiddleware, config=config)
```

### 3. Production Setup

```python
from fastapi import FastAPI
from fastapi_fortify import SecurityMiddleware
from fastapi_fortify.config.presets import ProductionConfig

app = FastAPI()

# Use production-optimized configuration
config = ProductionConfig()
app.add_middleware(SecurityMiddleware, config=config)
```

## Environment Configuration

Set up environment variables for production:

```bash
# Security settings
export SECURITY_MODE=production
export SECURITY_API_KEY=your-secret-api-key

# Redis settings (optional)
export REDIS_URL=redis://localhost:6379/0

# Logging
export LOG_LEVEL=INFO
export LOG_FORMAT=json
```

## Health Check

Test your installation:

```bash
curl http://localhost:8000/security/health
```

Expected response:
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "uptime_seconds": 42.5,
  "components": {
    "middleware": "healthy",
    "waf": "healthy",
    "bot_detection": "healthy",
    "ip_blocklist": "healthy",
    "rate_limiter": "healthy"
  }
}
```

## Troubleshooting

### Common Issues

**Import Error:**
```bash
pip install --upgrade fastapi-guard
```

**Redis Connection Error:**
```python
# Use memory backend instead
config = SecurityConfig(
    rate_limiter_backend="memory"
)
```

**Performance Issues:**
```python
# Disable resource-intensive features for development
config = SecurityConfig(
    bot_detection_enabled=False,  # Disable for dev
    threat_intelligence_enabled=False
)
```

### Getting Help

- Check the [troubleshooting guide](troubleshooting.md)
- Review [configuration options](configuration.md)
- Open an issue on GitHub

## Next Steps

- Read the [Configuration Guide](configuration.md)
- Explore [Security Best Practices](security-guide.md)
- Check out [Performance Tuning](performance.md)