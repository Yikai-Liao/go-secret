# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Repository**: `github.com/Yikai-Liao/sectore`  
**Module**: `github.com/Yikai-Liao/sectore`

`sectore` is a powerful CLI tool for securely managing encrypted key-value pairs. It provides enterprise-grade AES-256-GCM encryption with PBKDF2 key derivation and integrity verification through SHA-256 hashing.

### Architecture

- **cmd/sectore/main.go**: CLI interface using Cobra framework with commands: `set`, `unset`, `export`, `init`, `import`, `edit`
- **pkg/crypto/**: AES-256-GCM encryption/decryption with secure password handling
- **pkg/file/**: Secret file I/O with hash verification and JSON marshaling

### Key Components

- **SecretFile**: JSON structure with encrypted secrets and integrity hash (`__hash__` field)
- **Hash Verification**: SHA-256 hash of decrypted key-value pairs ensures data integrity
- **Password Security**: Zero-out sensitive data after use, PBKDF2 key derivation (100k iterations)

## Development Commands

### Building and Testing
```bash
# Build executable
go build -o bin/sectore cmd/sectore/main.go

# Run all tests (includes unit and integration tests)
go test ./...

# Run specific package tests
go test -v ./pkg/crypto
go test -v ./pkg/file  
go test -v ./test

# Run tests with coverage
go test -cover ./...
go test -coverprofile=coverage.out ./...

# Build for different platforms
GOOS=linux GOARCH=amd64 go build -o bin/sectore-linux-amd64 cmd/sectore/main.go
GOOS=windows GOARCH=amd64 go build -o bin/sectore-windows-amd64.exe cmd/sectore/main.go
GOOS=darwin GOARCH=amd64 go build -o bin/sectore-darwin-amd64 cmd/sectore/main.go
```

### Code Quality
```bash
# Run linter
golangci-lint run

# Run security scanner
gosec ./...

# Format code
go fmt ./...
```

### Running
```bash
./bin/sectore --help                        # Show help
./bin/sectore init                          # Initialize with random password
./bin/sectore set sectore.json -p password  # Set environment variables
./bin/sectore export secrets.json -p password -o config.env  # Export to .env
```

### Installation Methods
```bash
# Install from source
go install github.com/Yikai-Liao/sectore/cmd/sectore@latest

# Clone and build
git clone https://github.com/Yikai-Liao/sectore.git
cd sectore
go build -o bin/sectore cmd/sectore/main.go
```

## File Format

Secret files are JSON with encrypted values and integrity hash:
```json
{
  "key1": "encrypted_value_base64",
  "key2": "encrypted_value_base64", 
  "__hash__": "sha256_hash_of_decrypted_pairs"
}
```

## Project Structure

```
sectore/
├── .github/workflows/           # GitHub Actions CI/CD
│   ├── ci.yml                  # Main CI pipeline (test, lint, security)
│   ├── release.yml             # Release automation
│   └── dependency-update.yml   # Weekly dependency updates
├── cmd/sectore/                # CLI application entry point
│   └── main.go                 # Main CLI application
├── pkg/                        # Reusable packages
│   ├── crypto/                 # Encryption/decryption functionality
│   │   ├── crypto.go
│   │   └── crypto_test.go
│   └── file/                   # File I/O and secret management
│       ├── file.go
│       └── file_test.go
├── test/                       # Integration tests
│   └── main_test.go
├── bin/                        # Built executables (gitignored)
├── go.mod                      # Go module definition
├── go.sum                      # Dependency checksums
├── .golangci.yml              # Linting configuration
├── .gitignore                 # Git ignore patterns
├── README.md                  # Project documentation
└── CLAUDE.md                  # This file
```

## CI/CD Pipeline

The project uses GitHub Actions for automated testing and deployment:

### Workflows
- **CI Pipeline**: Runs on every push/PR
  - Multi-platform testing (Linux, macOS, Windows)
  - Multiple Go versions (1.21, 1.22, 1.23)
  - Code linting with golangci-lint
  - Security scanning with Gosec
  - Code coverage reporting
  - Cross-compilation builds

- **Release Pipeline**: Triggered on new tags
  - Builds binaries for all supported platforms
  - Creates GitHub releases with assets
  - Generates checksums for verification

- **Dependency Updates**: Weekly automation
  - Updates Go modules to latest versions
  - Creates PRs for review

### Local Testing
```bash
# Test workflows locally with act
./act push -j test --dryrun     # Dry run tests
./act push -j lint              # Run linting
./act pull_request              # Test PR workflow
```

## Import Paths

When working with this codebase, use these import paths:

```go
import (
    "github.com/Yikai-Liao/sectore/pkg/crypto"
    "github.com/Yikai-Liao/sectore/pkg/file"
)
```

## Security Notes

- All encryption uses AES-256-GCM with random salt and nonce
- Passwords are derived using PBKDF2 (100k iterations)
- Hash verification prevents tampering detection
- Sensitive data is zeroed from memory after use
- Regular security scanning in CI pipeline
- No secrets or sensitive data in repository

## Development Best Practices

### Code Standards
- Follow standard Go conventions and style guidelines
- Use `go fmt` for consistent formatting
- Run `golangci-lint run` before committing
- Ensure all tests pass with `go test ./...`
- Maintain test coverage above 85%

### Testing Guidelines
- Write unit tests for all new functionality
- Include integration tests for CLI commands
- Test error conditions and edge cases
- Use table-driven tests where appropriate
- Mock external dependencies properly

### Security Considerations
- Never log or print sensitive data (passwords, secrets)
- Always zero out sensitive data from memory after use
- Validate all user inputs thoroughly
- Use secure random number generation
- Follow cryptographic best practices

### Git Workflow
- Create feature branches from `main`
- Write descriptive commit messages
- Ensure CI passes before merging
- Use conventional commit format when possible
- Keep commits focused and atomic

### Release Process
- Tag releases with semantic versioning (v1.0.0)
- Update CHANGELOG.md for each release
- Test release binaries on all supported platforms
- Verify checksums match expected values