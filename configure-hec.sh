#!/bin/bash

# Define paths
LOCAL_CERTS_DIR="/opt/splunk/etc/auth/mycerts"
INPUTS_CONF="/opt/splunk/etc/apps/splunk_httpinput/local/inputs.conf"

# Ensure local directories exist
mkdir -p $(dirname "$INPUTS_CONF")

# 1. Configure inputs.conf for HEC SSL
cat << EOF > "$INPUTS_CONF"
[http]
disabled = 0
enableSSL = 1
port = 8088
serverCert = $LOCAL_CERTS_DIR/splunk.pem
EOF
