.PHONY: all dev build cross release install clean download check-go

BINARY_NAME=cross-ssh
WIZARD_NAME=Cross-Suite_Wizard
DIST_DIR=dist

LDFLAGS=-s -w
CGO=CGO_ENABLED=0

all: build

check-go:
	@which go >/dev/null 2>&1 || (echo "==>> [!] Go compiler not found in PATH" && exit 1)

download: check-go
	@echo "==>> Downloading and verifying Go module dependencies..."
	@go mod download
	@go mod tidy
	@echo "==>> Dependencies verified."

dev: download
	@echo "==>> Compiling fast native host binary..."
	@rm -f $(WIZARD_NAME) $(BINARY_NAME) $(WIZARD_NAME).exe $(BINARY_NAME).exe
	@$(CGO) go build -ldflags="$(LDFLAGS)" -o $(WIZARD_NAME) main.go
	@ln -sf $(WIZARD_NAME) $(BINARY_NAME) 2>/dev/null || cp $(WIZARD_NAME) $(BINARY_NAME) 2>/dev/null || true
	@chmod +x $(WIZARD_NAME) $(BINARY_NAME) 2>/dev/null || true
	@echo "==>> Local binary ready: ./$(WIZARD_NAME)"

build: dev

cross: download
	@echo "==>> Purging old distribution artifacts..."
	@rm -rf $(DIST_DIR)
	@mkdir -p $(DIST_DIR)
	@echo "==>> Compiling standalone universal binaries (CGO_ENABLED=0)..."
	
	# 1. Linux Standard (RHEL, CentOS, Debian, Ubuntu, Fedora, Arch, Alpine)
	@echo "==>> Building Linux [x86_64 (amd64)]..."
	@$(CGO) GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(WIZARD_NAME)-linux-amd64 main.go
	
	# 2. Linux ARM64 (AWS Graviton, Raspberry Pi 4/5, Oracle ARM)
	@echo "==>> Building Linux [aarch64 (arm64)]..."
	@$(CGO) GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(WIZARD_NAME)-linux-arm64 main.go
	
	# 3. macOS Intel (x86_64)
	@echo "==>> Building macOS [Intel (amd64)]..."
	@$(CGO) GOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(WIZARD_NAME)-darwin-amd64 main.go
	
	# 4. macOS Apple Silicon (M1/M2/M3/M4 arm64)
	@echo "==>> Building macOS [Apple Silicon (arm64)]..."
	@$(CGO) GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(WIZARD_NAME)-darwin-arm64 main.go
	
	# 5. Windows 64-bit (Embed UAC manifest if present)
	@echo "==>> Building Windows [x86_64 (.exe)]..."
	@if [ -f cross-ssh.exe.manifest ]; then \
		command -v rsrc >/dev/null 2>&1 || go install github.com/akavel/rsrc@latest; \
		rsrc -manifest cross-ssh.exe.manifest -o cross-ssh.syso 2>/dev/null || true; \
	fi
	@$(CGO) GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(WIZARD_NAME)-windows-amd64.exe main.go
	@$(CGO) GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(WIZARD_NAME).exe main.go
	@rm -f cross-ssh.syso
	
	@chmod +x $(DIST_DIR)/* $(WIZARD_NAME) 2>/dev/null || true
	@echo "==>> Universal cross-compilation complete! Binaries located in ./$(DIST_DIR)/"

release: cross
	@echo "==>> Packaging distribution archives..."
	@cd $(DIST_DIR) && for bin in *; do \
		if [ -f "$$bin" ]; then \
			case "$$bin" in \
				*.exe) zip -q "$${bin%.exe}.zip" "$$bin" ;; \
				*)     tar -czf "$${bin}.tar.gz" "$$bin" ;; \
			esac; \
		fi \
	done
	@echo "==>> Release packages ready in ./$(DIST_DIR)/"

install: dev
	@echo "==>> Installing system-wide binary to /usr/local/bin..."
	@sudo cp $(WIZARD_NAME) /usr/local/bin/$(BINARY_NAME)
	@sudo cp $(WIZARD_NAME) /usr/local/bin/$(WIZARD_NAME)
	@sudo chmod +x /usr/local/bin/$(BINARY_NAME) /usr/local/bin/$(WIZARD_NAME)
	@echo "==>> Installation successful! Execute 'cross-ssh' or 'Cross-Suite_Wizard' from any directory."

clean:
	@echo "==>> Cleaning build cache and compiled binaries..."
	@rm -rf $(DIST_DIR) $(BINARY_NAME) $(BINARY_NAME).exe $(WIZARD_NAME) $(WIZARD_NAME).exe *.syso
	@go clean -cache 2>/dev/null || true
	@echo "==>> Workspace clean."