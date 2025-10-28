# KernelPWNED - Kernel Exploit Suggester Makefile
# Author: c0d3Ninja
# Version: 1.0

# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -g
LDFLAGS = 

# Directories
SRCDIR = .
MODULEDIR = modules
OBJDIR = obj
BINDIR = bin

# Source files
MAIN_SOURCES = main.cpp
MODULE_SOURCES = $(wildcard $(MODULEDIR)/*.cpp)

# Object files
MAIN_OBJECTS = $(MAIN_SOURCES:%.cpp=$(OBJDIR)/%.o)
MODULE_OBJECTS = $(MODULE_SOURCES:$(MODULEDIR)/%.cpp=$(OBJDIR)/$(MODULEDIR)/%.o)
OBJECTS = $(MAIN_OBJECTS) $(MODULE_OBJECTS)

# Target executable
TARGET = $(BINDIR)/kernelpwned

# Default target
all: directories $(TARGET)

# Create all necessary directories
directories:
	@mkdir -p $(OBJDIR) $(OBJDIR)/$(MODULEDIR) $(BINDIR)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/$(MODULEDIR):
	mkdir -p $(OBJDIR)/$(MODULEDIR)

$(BINDIR):
	mkdir -p $(BINDIR)

# Compile main directory source files
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Compile module directory source files
$(OBJDIR)/$(MODULEDIR)/%.o: $(MODULEDIR)/%.cpp | $(OBJDIR) $(OBJDIR)/$(MODULEDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Link object files to create executable
$(TARGET): $(OBJECTS) | $(BINDIR)
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS)

# Clean build artifacts
clean:
	rm -rf $(OBJDIR) $(BINDIR)

# Install the tool (requires sudo)
install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/
	sudo chmod +x /usr/local/bin/kernelpwned
	@echo "KernelPWNED installed to /usr/local/bin/"

# Uninstall the tool
uninstall:
	sudo rm -f /usr/local/bin/kernelpwned
	@echo "KernelPWNED uninstalled"

# Run the tool
run: $(TARGET)
	./$(TARGET)

# Debug build
debug: CXXFLAGS += -DDEBUG -g3
debug: clean $(TARGET)

# Release build
release: CXXFLAGS += -DNDEBUG -O3
release: clean $(TARGET)

# Static analysis
analyze:
	cppcheck --enable=all --std=c++17 $(SRCDIR)/*.cpp $(MODULEDIR)/*.cpp

# Format code
format:
	clang-format -i $(SRCDIR)/*.cpp $(MODULEDIR)/*.cpp $(MODULEDIR)/*.h

# Show help
help:
	@echo "KernelPWNED - Kernel Exploit Suggester"
	@echo "Available targets:"
	@echo "  all       - Build the kernel exploit suggester (default)"
	@echo "  clean     - Remove build artifacts"
	@echo "  install   - Install tool to /usr/local/bin/ (requires sudo)"
	@echo "  uninstall - Remove tool from /usr/local/bin/"
	@echo "  run       - Build and run the tool"
	@echo "  debug     - Build with debug symbols"
	@echo "  release   - Build optimized release version"
	@echo "  analyze   - Run static analysis with cppcheck"
	@echo "  format    - Format source code with clang-format"
	@echo "  help      - Show this help message"

# Phony targets
.PHONY: all directories clean install uninstall run debug release analyze format help

# Dependencies
$(OBJDIR)/main.o: main.cpp $(MODULEDIR)/kernelpwn.h
$(OBJDIR)/$(MODULEDIR)/kernelpwn.o: $(MODULEDIR)/kernelpwn.cpp $(MODULEDIR)/kernelpwn.h $(MODULEDIR)/executils.h
$(OBJDIR)/$(MODULEDIR)/executils.o: $(MODULEDIR)/executils.cpp $(MODULEDIR)/executils.h

