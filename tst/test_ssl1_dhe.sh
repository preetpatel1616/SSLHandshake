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
SERVER_PID=$!

# Insert check here to ensure server is ready. For now, using sleep.
sleep 2

# Optionally, implement a more robust mechanism to check server readiness here
# e.g., by checking for a server-created 'ready' file or specific log message

# Run the first client in the background
$CLIENT_PATH 1 &
CLIENT1_PID=$!

# Small delay to let the first client establish a connection
# Adjust as necessary based on observed timings and network conditions
sleep 1

# Insert logic here if you need to check client1's actions or status before continuing

# # Run the second client in the foreground
# $CLIENT_PATH 2

# Allow some time for messages to be exchanged
# Adjust this sleep as necessary to accommodate for expected message exchange times
sleep 8

# Kill the server and client processes if any are left
kill $SERVER_PID
kill $CLIENT1_PID || true
# pkill -f $CLIENT_PATH 2 || true # Uncomment if using a second client

# Note: Using 'kill' with stored PIDs for a cleaner script exit
# 'pkill' or 'kill' could be used based on preference and requirements

echo "Test script completed."
