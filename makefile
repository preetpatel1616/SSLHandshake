# Phony targets for specifying default actions
.PHONY: all common tcp ssl tst clean

# Default target to build everything
all: common tcp ssl tst

# Build the common library
common:
	$(MAKE) -C src/common

# Build the TCP library
tcp: common
	$(MAKE) -C src/tcp

# Build the SSL library
ssl: tcp common
	$(MAKE) -C src/ssl

# Build the tst binaries
tst: ssl tcp common
	$(MAKE) -C tst

# Clean target to clean up build artifacts
clean:
	$(MAKE) -C src/common clean
	$(MAKE) -C src/tcp clean
	$(MAKE) -C src/ssl clean
	$(MAKE) -C tst clean
