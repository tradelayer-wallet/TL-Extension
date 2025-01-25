#!/bin/bash

echo "==========================================="
echo " TradeLayer Wallet Extension Setup"
echo "==========================================="

# Check if npm is installed
if ! command -v npm &> /dev/null
then
    echo "npm is not installed. Installing Node.js and npm..."
    
    # Automatically install Node.js and npm for Debian/Ubuntu-based systems
    if [ -f /etc/debian_version ]; then
        echo "Updating package list..."
        sudo apt update
        echo "Installing Node.js and npm..."
        sudo apt install -y nodejs npm
    elif [ -f /etc/redhat-release ]; then
        # For RedHat/CentOS
        echo "Installing Node.js and npm on RedHat-based systems..."
        curl -fsSL https://rpm.nodesource.com/setup_16.x | sudo bash -
        sudo yum install -y nodejs
    else
        echo "Please manually install Node.js and npm from https://nodejs.org/"
        exit 1
    fi
fi

# Ensure npm is now available
if ! command -v npm &> /dev/null
then
    echo "npm installation failed. Please install Node.js and npm manually."
    exit 1
fi

# Install npm dependencies
echo "Installing dependencies..."
npm install

# Check if npm install was successful
if [ $? -ne 0 ]; then
    echo "An error occurred during npm install. Please check the logs above for details."
    exit 1
fi

echo "Dependencies installed successfully!"

# Provide instructions for loading the extension in Chrome
echo "==========================================="
echo " Next Steps:"
echo " 1. Open Chrome and navigate to chrome://extensions/"
echo " 2. Enable Developer Mode (toggle in the top-right corner)."
echo " 3. Click Load Unpacked and select this folder."
echo "==========================================="

exit 0
