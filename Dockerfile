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

# bot.py writes hits_*.txt and proxy_pool.txt to /app at runtime.
# To persist the proxy pool across Railway redeployments, mount a Railway
# Volume at /app/data and set PROXY_POOL_DIR (see bot.py) -- uncomment the
# ENV line below if you do that.
# ENV PROXY_POOL_DIR=/app/data

# Unbuffered stdout so logs appear in Railway's console in real time.
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

CMD ["python", "bot.py"]