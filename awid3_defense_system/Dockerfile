FROM python:3.10-slim

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    wireless-tools \
    iw \
    network-manager \
    iputils-ping \
    net-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Create necessary directories
RUN mkdir -p logs data/raw data/cleaned data/scalers models

ENV HEADLESS=true
ENV PYTHONUNBUFFERED=1

CMD ["python", "run.py"]
