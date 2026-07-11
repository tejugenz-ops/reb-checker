FROM python:3.12-slim

# Runtime libs needed by curl_cffi (TLS fingerprinting) and HTTPS.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libcurl4 \
        libssl3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Application code.
COPY bot.py .

# bot.py writes proxy_pool.txt to PROXY_POOL_DIR at runtime.
# If you mount a Railway Volume at /app/data, proxy_pool.txt lives there
# and survives restarts. This ENV is already set to enable that.
ENV PROXY_POOL_DIR=/app/data

# IMPORTANT: keep this on plain HTTP (http://...). HTTPS validation reloads
# the libcurl TLS path that tripped Railway's abuse detector.
ENV PROXY_VALIDATE_URL=http://httpbin.org/ip

# Unbuffered stdout so logs appear in Railway's console in real time.
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

CMD ["python", "bot.py"]
