FROM node:20-bullseye

ENV DEBIAN_FRONTEND=noninteractive

# Install tshark at build time
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y tshark \
 && rm -rf /var/lib/apt/lists/*

# Install n8n at build time
RUN npm install -g n8n

WORKDIR /data

EXPOSE 5678

# This process keeps the container running
CMD ["n8n", "start"]
