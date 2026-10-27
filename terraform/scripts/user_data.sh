#!/bin/bash
set -euo pipefail

# Non-interactive apt installation
export DEBIAN_FRONTEND=noninteractive

# Update package lists and install prerequisite tools
apt-get update -y
apt-get install -y nginx curl git

# Install Node.js 20 LTS
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs

# Install PM2 process manager globally
npm install -g pm2

# Setup application directory owned by unprivileged 'ubuntu' user
APP_DIR="/home/ubuntu/nodeapp"
mkdir -p "$APP_DIR"

# Clone application repository
git clone https://github.com/mmdcloud/aws-client-vpn-endpoint /tmp/repo
cp -r /tmp/repo/src/. "$APP_DIR/"
rm -rf /tmp/repo

# Set proper non-root ownership
chown -R ubuntu:ubuntu "$APP_DIR"

# Configure Nginx reverse proxy
cp "$APP_DIR/scripts/default" /etc/nginx/sites-available/default
nginx -t
systemctl restart nginx
systemctl enable nginx

# Install Node.js dependencies as 'ubuntu' user
cd "$APP_DIR"
sudo -u ubuntu npm ci --only=production || sudo -u ubuntu npm install

# Start application using PM2 as 'ubuntu' user with auto-restart on reboot
sudo -u ubuntu pm2 start server.mjs --name "nodeapp"
env PATH=$PATH:/usr/bin /usr/lib/node_modules/pm2/bin/pm2 startup systemd -u ubuntu --hp /home/ubuntu
sudo -u ubuntu pm2 save

echo "Application bootstrap completed successfully."
