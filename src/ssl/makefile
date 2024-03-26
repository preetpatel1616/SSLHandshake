# Compiler settings - Can be customized.
CXX = g++
CXXFLAGS = -std=c++11 -Wall -I../common -I../tcp -I.

# OpenSSL settings
OPENSSL_LIB = -lssl -lcrypto
OPENSSL_INCLUDE = /usr/include/openssl

# Directory structure
SRC_DIR = .
OBJ_DIR = obj
BIN_DIR = bin
COMMON_DIR = ../common
TCP_DIR = ../tcp

# All source files
SRCS = $(SRC_DIR)/Ssl.cc $(SRC_DIR)/SslClient.cc $(SRC_DIR)/SslServer.cc $(SRC_DIR)/crypto_adaptor.cc
OBJS = $(SRCS:$(SRC_DIR)/%.cc=$(OBJ_DIR)/%.o)

# Common and TCP dependencies
COMMON_DEPS = $(COMMON_DIR)/Logger/Logger.h $(COMMON_DIR)/Utils/Utils.h $(COMMON_DIR)/StatusCodes.h
TCP_DEPS = $(TCP_DIR)/TCP.h $(TCP_DIR)/TcpClient.h $(TCP_DIR)/TcpServer.h

# Define the target
TARGET = $(BIN_DIR)/libssl.a

# Phony targets for clean and all
.PHONY: all clean

# Default target
all: $(TARGET)

# Create the library from object files
$(TARGET): $(OBJS)
	@mkdir -p $(@D)
	ar rcs $@ $^

# Rule to create object files from source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cc $(COMMON_DEPS) $(TCP_DEPS)
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -I$(OPENSSL_INCLUDE) -c $< -o $@ $(OPENSSL_LIB)

# Clean the build
clean:
	$(RM) -r $(OBJ_DIR) $(BIN_DIR)

