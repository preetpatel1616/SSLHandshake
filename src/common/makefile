# Compiler settings - Can be customized.
CXX = g++
CXXFLAGS = -std=c++11 -Wall -I.

# Directory structure
SRC_DIR = .
OBJ_DIR = obj
BIN_DIR = bin

# All source files
SRCS = $(SRC_DIR)/Logger/Logger.cc $(SRC_DIR)/Utils/Utils.cc
OBJS = $(SRCS:$(SRC_DIR)/%.cc=$(OBJ_DIR)/%.o)

# Define the target
TARGET = $(BIN_DIR)/libcommon.a

# Phony targets for clean and all
.PHONY: all clean

# Default target
all: $(TARGET)

# Create the library from object files
$(TARGET): $(OBJS)
	@mkdir -p $(@D)
	ar rcs $@ $^

# Rule to create object files from source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cc
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean the build
clean:
	$(RM) -r $(OBJ_DIR) $(BIN_DIR)

