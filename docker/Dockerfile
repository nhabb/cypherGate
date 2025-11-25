FROM node:20-bullseye

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /data

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 5678

ENTRYPOINT ["/entrypoint.sh"]

