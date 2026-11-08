#!/bin/sh
# Prepares a fresh Ubuntu server for AgentTrap. Run once as root.
# docker-buildx makes `docker build` use BuildKit; without it Docker falls
# back to the deprecated legacy builder, whose cache cannot be pruned.
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq docker.io docker-compose-v2 docker-buildx openssl unattended-upgrades
systemctl enable --now docker
# Swap helps the Go and web builds on small droplets.
if [ ! -f /swapfile ]; then
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap -q /swapfile && swapon /swapfile
  echo "/swapfile none swap sw 0 0" >> /etc/fstab
fi
# Container logs go to journald; keep the journal across reboots, size-capped.
"$(dirname "$0")/persistent-logs.sh"
docker buildx version
docker compose version
