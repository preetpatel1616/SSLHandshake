#!/bin/sh

# Test script for SSL with DHE key exchange

# Variables for executables
CLIENT="client2"
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
SERVER_PID=$!

# Insert check here to ensure server is ready. For now, using sleep.
sleep 2

# Run the first client in the background
$CLIENT_PATH 1 &
CLIENT1_PID=$!

# Small delay to let the first client establish a connection
sleep 1

# Run the second client in the background
$CLIENT_PATH 2 &
CLIENT2_PID=$!

# Allow some time for messages to be exchanged
sleep 8

# Kill the server and client processes if any are left
kill $SERVER_PID
kill $CLIENT1_PID || true
kill $CLIENT2_PID || true

echo "Test script completed."
