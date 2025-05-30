# Sectore

A powerful CLI tool for securely managing encrypted key-value pairs with enterprise-grade AES-256-GCM encryption and integrity verification.

## Features

- **Enterprise Security**: AES-256-GCM encryption with PBKDF2 key derivation (100k iterations)
- **Data Integrity**: SHA-256 hash verification prevents tampering detection
- **Flexible Operations**: Set, unset, export, import, and interactively edit secrets
- **Multiple Formats**: Support for JSON and .env file exports
- **Memory Safety**: Zero-out sensitive data after use

## Installation

### Build from Source

```bash
# Clone the repository
git clone <repository-url>
cd go-secret

# Build the binary
go build -o bin/sectore cmd/sectore/main.go

# Or install globally
go install ./cmd/sectore
```

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
go-secret/
├── cmd/sectore/          # CLI application entry point
├── pkg/
│   ├── crypto/          # Encryption/decryption functionality
│   └── file/            # File I/O and secret management
├── test/                # Integration tests
├── bin/                 # Built executables
├── go.mod               # Go module definition
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
```

### Code Coverage

```bash
# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

## Security Notes

- All encryption uses AES-256-GCM with random salt and nonce
- Passwords are derived using PBKDF2 with 100,000 iterations
- Hash verification prevents tampering detection
- Sensitive data is zeroed from memory after use
- Never commit secret files to version control

## License

[Add your license here]

## Contributing

[Add contribution guidelines here]