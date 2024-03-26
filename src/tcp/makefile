# Compiler settings - Can be customized.
CXX = g++
CXXFLAGS = -std=c++11 -Wall -I../common -I.

# Directory structure
SRC_DIR = .
OBJ_DIR = obj
BIN_DIR = bin
COMMON_DIR = ../common

# All source files
SRCS = $(SRC_DIR)/TCP.cc $(SRC_DIR)/TcpClient.cc $(SRC_DIR)/TcpServer.cc
OBJS = $(SRCS:$(SRC_DIR)/%.cc=$(OBJ_DIR)/%.o)

# Common dependencies
COMMON_DEPS = $(COMMON_DIR)/Logger/Logger.h $(COMMON_DIR)/Utils/Utils.h $(COMMON_DIR)/StatusCodes.h

# Define the target
TARGET = $(BIN_DIR)/libtcp.a

# Phony targets for clean and all
.PHONY: all clean

# Default target
all: $(TARGET)

# Create the library from object files
$(TARGET): $(OBJS)
	@mkdir -p $(@D)
	ar rcs $@ $^

# Rule to create object files from source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cc $(COMMON_DEPS)
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean the build
clean:
	$(RM) -r $(OBJ_DIR) $(BIN_DIR)

