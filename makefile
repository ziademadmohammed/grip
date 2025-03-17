# Define variables
BINARY_NAME=netmonitor
GO=go
BUILD_DIR=build
RSRC=rsrc
MANIFEST=app.manifest

# Default target (runs when you just type 'make')
all: build

check-build-dir:
	@echo "Checking if build directory exists..."
	@mkdir -p $(BUILD_DIR)

# Embed the manifest into the build
embed-manifest: install-rsrc check-build-dir
	@echo "Embedding manifest into build..."
	$(RSRC) -manifest $(CURDIR)/$(MANIFEST) -o cmd/netmonitor/rsrc.syso

# Install rsrc tool for manifest embedding if not already installed
install-rsrc:
	@echo "Installing rsrc tool for manifest embedding..."
	$(GO) install github.com/akavel/rsrc@latest

# Build the Go application with the embedded manifest
build: embed-manifest check-build-dir
	@echo "Building the application..."
	CGO_ENABLED=1 $(GO) build -v -ldflags="-r $(BUILD_DIR)" -o $(BUILD_DIR)/$(BINARY_NAME).exe cmd/netmonitor/main.go
	@echo "Build complete! Binary is in the $(BUILD_DIR) directory."

# Run the application
run: check-build-dir
	@echo "Running the application..."
	CGO_ENABLED=1 $(GO) run -ldflags="-r $(BUILD_DIR)" cmd/netmonitor/main.go cmd/netmonitor/svc.go cmd/netmonitor/logging.go cmd/netmonitor/stats.go debug

# Clean the build directory
clean:
	@echo "Cleaning up..."
	rm -rf $(BUILD_DIR)
	@echo "Cleanup complete!"

# Test the application
test:
	@echo "Running tests..."
	$(GO) test ./...

# Install dependencies
deps:
	@echo "Installing dependencies..."
	$(GO) mod download

# Format the code
fmt:
	@echo "Formatting code..."
	$(GO) fmt ./...

# Lint the code
lint:
	@echo "Linting code..."
	golint ./...

# Build and run the application
start: build
	@echo "Running the built application..."
	$(BUILD_DIR)/$(BINARY_NAME).exe debug

# Run the built executable in debug mode
run-debug: build
	@echo "Running the built application in debug mode..."
	$(BUILD_DIR)/$(BINARY_NAME).exe debug

# Install the Windows service
install-service: build
	@echo "Installing Windows service..."
	$(BUILD_DIR)/$(BINARY_NAME).exe install
	@echo "Service installed. Use 'make start-service' to start it."

# Start the Windows service
start-service:
	@echo "Starting Windows service..."
	net start NetMonitor

# Stop the Windows service
stop-service:
	@echo "Stopping Windows service..."
	net stop NetMonitor

# Remove the Windows service
remove-service:
	@echo "Removing Windows service..."
	$(BUILD_DIR)/$(BINARY_NAME).exe remove

# Help command (lists available targets)
help:
	@echo "Available targets:"
	@echo "  build            - Build the application with embedded manifest"
	@echo "  install-rsrc     - Install the rsrc tool for manifest embedding"
	@echo "  embed-manifest   - Embed the manifest into the build"
	@echo "  run              - Run the application from source"
	@echo "  run-debug        - Build and run the executable in debug mode"
	@echo "  clean            - Clean the build directory"
	@echo "  test             - Run tests"
	@echo "  deps             - Install dependencies"
	@echo "  fmt              - Format the code"
	@echo "  lint             - Lint the code"
	@echo "  start            - Build and run the application"
	@echo "  install-service  - Install Windows service"
	@echo "  start-service    - Start Windows service"
	@echo "  stop-service     - Stop Windows service"
	@echo "  remove-service   - Remove Windows service"
	@echo "  help             - Show this help message"