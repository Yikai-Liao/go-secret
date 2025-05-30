# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`go-secret` is a CLI tool for securely managing encrypted key-value pairs. It provides AES-256-GCM encryption with PBKDF2 key derivation and integrity verification through SHA-256 hashing.

### Architecture

- **main.go**: CLI interface using Cobra framework with commands: `set`, `unset`, `export`, `init`, `import`, `edit`
- **internal/crypto/**: AES-256-GCM encryption/decryption with secure password handling
- **internal/file/**: Secret file I/O with hash verification and JSON marshaling

### Key Components

- **SecretFile**: JSON structure with encrypted secrets and integrity hash (`__hash__` field)
- **Hash Verification**: SHA-256 hash of decrypted key-value pairs ensures data integrity
- **Password Security**: Zero-out sensitive data after use, PBKDF2 key derivation (100k iterations)

## Development Commands

### Building and Testing
```bash
go build -o go-secret main.go     # Build executable
go test ./...                     # Run all tests
go test -v ./internal/crypto      # Test crypto module
go test -v ./internal/file        # Test file module
```

### Running
```bash
./go-secret --help                # Show help
./go-secret init                  # Initialize with random password
./go-secret set secrets.json -p password  # Set environment variables
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

## Security Notes

- All encryption uses AES-256-GCM with random salt and nonce
- Passwords are derived using PBKDF2 (100k iterations)
- Hash verification prevents tampering detection
- Sensitive data is zeroed from memory after use