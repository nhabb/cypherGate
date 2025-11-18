#!/usr/bin/env bash
set -e

echo "=== Removing old Docker / containerd packages if they exist ==="
sudo apt-get remove -y docker.io docker-doc docker-compose podman-docker containerd containerd.io runc || true

echo "=== Updating package list ==="
sudo apt-get update -y

echo "=== Installing prerequisites (ca-certificates, curl, gnupg, lsb-release) ==="
sudo apt-get install -y ca-certificates curl gnupg lsb-release

echo "=== Setting up Docker's official APT repository (if not already) ==="
sudo mkdir -p /etc/apt/keyrings

if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
fi

# This will overwrite the file if it exists, which is fine
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release; echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

echo "=== Updating package list (Docker repo included) ==="
sudo apt-get update -y

echo "=== Installing Docker Engine from Docker repo ==="
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

echo "=== Enabling and starting Docker service ==="
sudo systemctl enable docker
sudo systemctl start docker

echo "=== Adding current user to 'docker' group ==="
sudo usermod -aG docker "$USER" || true

echo
echo "=========================================="
echo " Docker installation finished (docker-ce)."
echo " You may need to LOG OUT and LOG IN again"
echo " so you can run 'docker' without sudo."
echo
echo " Test it with:"
echo "   docker run hello-world"
echo "=========================================="

