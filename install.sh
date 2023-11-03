#!/bin/bash

# Set the installation directory
INSTALL_DIR="/opt/security"

sudo apt install git python3 python3-pip -y

# Clone the GitHub repository
git clone https://github.com/botsarefuture/security.git "$INSTALL_DIR"

# Change to the installation directory
cd "$INSTALL_DIR"

# Install dependencies
sudo pip install -r requirements.txt

sudo cp systemd_file.service /etc/systemd/system/security.service

sudo systemctl daemon-reload

