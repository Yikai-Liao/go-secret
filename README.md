# Sectore

A powerful CLI tool for securely managing encrypted key-value pairs with enterprise-grade AES-256-GCM encryption and integrity verification.

[![CI](https://github.com/Yikai-Liao/sectore/workflows/CI/badge.svg)](https://github.com/Yikai-Liao/sectore/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/Yikai-Liao/sectore)](https://goreportcard.com/report/github.com/Yikai-Liao/sectore)
[![codecov](https://codecov.io/gh/Yikai-Liao/sectore/branch/main/graph/badge.svg)](https://codecov.io/gh/Yikai-Liao/sectore)

## Features

- **Enterprise Security**: AES-256-GCM encryption with PBKDF2 key derivation (100k iterations)
- **Data Integrity**: SHA-256 hash verification prevents tampering detection
- **Flexible Operations**: Set, unset, export, import, and interactively edit secrets
- **Multiple Formats**: Support for JSON and .env file exports
- **Memory Safety**: Zero-out sensitive data after use
- **Cross-Platform**: Works on Linux, macOS, and Windows

## Installation

### Build from Source

```bash
# Clone the repository
git clone https://github.com/Yikai-Liao/sectore.git
cd sectore

# Build the binary
go build -o bin/sectore cmd/sectore/main.go

# Or install globally
go install ./cmd/sectore
```

### Install from Source (without cloning)

```bash
# Install directly from source
go install github.com/Yikai-Liao/sectore/cmd/sectore@latest

# Or install specific version
go install github.com/Yikai-Liao/sectore/cmd/sectore@v1.0.0
```

### Download Pre-built Binaries

Pre-built binaries are available for Linux, macOS, and Windows on the [Releases](https://github.com/Yikai-Liao/sectore/releases) page.

## Usage

### Initialize Secret Storage

```bash
# Create new secret file with random password
sectore init

# Create custom secret file with specific password
sectore init my-secrets.json -p mypassword
```

### Manage Secrets

```bash
# Set environment variables from encrypted file
sectore set secrets.json -p password

# Generate unset commands
sectore unset secrets.json -p password

# Interactive editing
sectore edit secrets.json -p password
```

### Import/Export

```bash
# Import from plain JSON
sectore import plain.json -p password -o encrypted.json

# Export to JSON (without hash)
sectore export encrypted.json -p password -o decrypted.json

# Export to .env format
sectore export encrypted.json -p password -o config.env
```

## Project Structure

```
sectore/
├── .github/workflows/    # GitHub Actions CI/CD
├── cmd/sectore/          # CLI application entry point
├── pkg/
│   ├── crypto/          # Encryption/decryption functionality
│   └── file/            # File I/O and secret management
├── test/                # Integration tests
├── bin/                 # Built executables
├── go.mod               # Go module definition
├── .golangci.yml        # Linting configuration
└── README.md            # This file
```

## File Format

Secret files are JSON with encrypted values and integrity hash:

```json
{
  "API_KEY": "encrypted_base64_value",
  "DATABASE_URL": "encrypted_base64_value",
  "__hash__": "sha256_hash_of_decrypted_pairs"
}
```

## Development

### Building

```bash
# Build for current platform
go build -o bin/sectore cmd/sectore/main.go

# Build for specific platform
GOOS=linux GOARCH=amd64 go build -o bin/sectore-linux-amd64 cmd/sectore/main.go
```

### Testing

```bash
# Run all tests
go test ./...

# Run specific package tests
go test ./pkg/crypto
go test ./pkg/file

# Run with coverage
go test -cover ./...

# Run integration tests
go test -v ./test/...
```

### Code Quality

```bash
# Run linter
golangci-lint run

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

### Local CI Testing

This project uses [act](https://github.com/nektos/act) for local GitHub Actions testing:

```bash
# Install act (example for Linux ARM64)
wget https://github.com/nektos/act/releases/download/v0.2.77/act_Linux_arm64.tar.gz
tar -xzf act_Linux_arm64.tar.gz
chmod +x act

# Test workflows locally
./act push -j test --dryrun    # Dry run tests
./act push -j lint             # Run linting
./act pull_request             # Test PR workflow
```

## CI/CD Pipeline

This project uses GitHub Actions for continuous integration and deployment:

### Workflows

- **CI (`ci.yml`)**: Runs on every push and PR
  - Multi-platform testing (Linux, macOS, Windows)
  - Multiple Go versions (1.21, 1.22, 1.23)
  - Code linting with golangci-lint
  - Security scanning with Gosec
  - Code coverage reporting to Codecov
  - Cross-compilation for multiple architectures

- **Release (`release.yml`)**: Runs on new releases
  - Builds binaries for all supported platforms
  - Creates release archives with checksums
  - Automatically uploads assets to GitHub Releases

- **Dependency Update (`dependency-update.yml`)**: Weekly automated dependency updates
  - Updates Go modules to latest versions
  - Creates PRs for dependency updates
  - Runs tests to ensure compatibility

### Status Checks

All PRs must pass:
- ✅ Tests on all platforms and Go versions
- ✅ Linting and code quality checks
- ✅ Security scanning
- ✅ Code coverage requirements

## Security Notes

- All encryption uses AES-256-GCM with random salt and nonce
- Passwords are derived using PBKDF2 with 100,000 iterations
- Hash verification prevents tampering detection
- Sensitive data is zeroed from memory after use
- Never commit secret files to version control
- Regular security scanning in CI pipeline

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and linting (`go test ./...` and `golangci-lint run`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes and version history.