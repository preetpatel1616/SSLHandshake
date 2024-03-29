#!/bin/sh

# Test script for SSL with DHE key exchange

# Variables for executables
CLIENT="client1"
SERVER="server"

# Paths to executables
CLIENT_PATH="./tst/bin/$CLIENT"
SERVER_PATH="./tst/bin/$SERVER"

# Navigate to the root directory for relative paths to work consistently
cd "$(dirname "$0")/../"

# Clean up any old logs in tst and root directory
rm -f tst/*.log
rm -f ./*.log

# Enable strict error checking
set -e
set -v

# Clean and build all components using the root Makefile
make clean all

# Start the server in the background
$SERVER_PATH &

# Give the server time to initialize
sleep 2

# Run the first client in the background
$CLIENT_PATH 1 &

# Small delay to let the first client establish a connection
sleep 1

# # Run the second client in the foreground
# $CLIENT_PATH 2

# # Allow some time for messages to be exchanged
# sleep 8

# # Kill the server and client processes if any are left
# pkill -f $SERVER_PATH || true
# pkill -f $CLIENT_PATH || true
