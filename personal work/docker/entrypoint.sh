#!/usr/bin/env bash
set -e

echo "=== Installing tshark ==="
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y tshark
rm -rf /var/lib/apt/lists/*

echo "=== Installing n8n ==="
npm install -g n8n

echo "=== Starting n8n ==="
exec n8n start

