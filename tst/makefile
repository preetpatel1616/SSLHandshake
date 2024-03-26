# Compiler and flags configuration
CXX = g++
CXXFLAGS = -std=c++11 -Wall -I../src/ssl -I../src/common -I../src/tcp -pthread

# OpenSSL library flags
OPENSSL_LIBS = -lssl -lcrypto

# Paths to the static libraries
LIB_COMMON = ../src/common/bin/libcommon.a
LIB_TCP = ../src/tcp/bin/libtcp.a
LIB_SSL = ../src/ssl/bin/libssl.a

# Source directory
SRC_DIR = .

# Object files directory
OBJ_DIR = obj

# Binaries directory
BIN_DIR = bin

# Executables
SERVER_EXEC = $(BIN_DIR)/server
CLIENT1_EXEC = $(BIN_DIR)/client1
CLIENT2_EXEC = $(BIN_DIR)/client2

# Source files
SERVER_SRC = $(SRC_DIR)/mainServer.cc
CLIENT1_SRC = $(SRC_DIR)/mainClient1.cc
CLIENT2_SRC = $(SRC_DIR)/mainClient2.cc

# Object files
SERVER_OBJ = $(OBJ_DIR)/mainServer.o
CLIENT1_OBJ = $(OBJ_DIR)/mainClient1.o
CLIENT2_OBJ = $(OBJ_DIR)/mainClient2.o

# Phony targets for clean and all
.PHONY: all clean

# Default target
all: $(SERVER_EXEC) $(CLIENT1_EXEC) $(CLIENT2_EXEC)

# Server executable
$(SERVER_EXEC): $(SERVER_OBJ) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIB_SSL) $(LIB_TCP) $(LIB_COMMON) $(OPENSSL_LIBS)

# Client 1 executable
$(CLIENT1_EXEC): $(CLIENT1_OBJ) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIB_SSL) $(LIB_TCP) $(LIB_COMMON) $(OPENSSL_LIBS)
# Client 2 executable
$(CLIENT2_EXEC): $(CLIENT2_OBJ) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIB_SSL) $(LIB_TCP) $(LIB_COMMON) $(OPENSSL_LIBS)

# Rule to create object files from source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cc | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Include headers and source files dependencies
$(SERVER_OBJ): $(SERVER_SRC) ../src/ssl/SslServer.h ../src/ssl/SslClient.h
$(CLIENT1_OBJ): $(CLIENT1_SRC) ../src/ssl/SslClient.h
$(CLIENT2_OBJ): $(CLIENT2_SRC) ../src/ssl/SslClient.h

# Create binaries directory
$(BIN_DIR):
	mkdir -p $@

# Create object files directory
$(OBJ_DIR):
	mkdir -p $@

# Clean the build
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
