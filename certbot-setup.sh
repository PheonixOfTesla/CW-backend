#!/bin/bash

# Install Certbot
sudo apt-get update
sudo apt-get install -y certbot python3-certbot-nginx

# Get certificates
sudo certbot --nginx -d api.clockwork.platform -d www.api.clockwork.platform \
  --non-interactive \
  --agree-tos \
  --email admin@clockwork.platform \
  --redirect

# Set up auto-renewal
echo "0 0,12 * * * root certbot renew --quiet --post-hook 'systemctl reload nginx'" | sudo tee -a /etc/crontab > /dev/null

echo "SSL certificates installed and auto-renewal configured!"