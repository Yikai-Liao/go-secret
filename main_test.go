package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go-secret/internal/crypto" // Import for Encrypt function
	"go-secret/internal/file"   // Import internal/file package to access SecretFile struct and constants
)

// runCLI helper function to compile and execute go-secret CLI commands
// Returns stdout, stderr and error
func runCLI(t *testing.T, args []string, stdinInput string, tempDir string) (string, string, error) {
	// Ensure command execution in temp directory
	originalCwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Failed to switch to temp directory: %v", err)
	}
	defer os.Chdir(originalCwd) // Ensure switching back to original directory after test

	// Compile go-secret
	cmd := exec.Command("go", "build", "-o", "go-secret", originalCwd)
	cmd.Dir = originalCwd // Compile command executes in project root directory
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to compile go-secret: %v\n%s", err, output)
	}

	// Build CLI command
	cliCmd := exec.Command(filepath.Join(originalCwd, "go-secret"), args...)

	// Simulate standard input
	if stdinInput != "" {
		cliCmd.Stdin = strings.NewReader(stdinInput)
	}

	var stdout, stderr bytes.Buffer
	cliCmd.Stdout = &stdout
	cliCmd.Stderr = &stderr

	err = cliCmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// If it's ExitError, means program exited with non-zero status code
			return stdout.String(), stderr.String(), exitErr
		}
		// Other types of errors
		return stdout.String(), stderr.String(), err
	}

	return stdout.String(), stderr.String(), nil
}

// TestInitCommand tests the init command
func TestInitCommand(t *testing.T) {
	// Create temp directory
	tempDir, err := ioutil.TempDir("", "go-secret-test-init-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir) // Ensure temp directory cleanup after test

	defaultFilePath := filepath.Join(tempDir, "go-secret.json")
	customFilePath := filepath.Join(tempDir, "my-secrets.json")
	testPassword := "testpassword"

	// 1. Test normal initialization (no file argument, generate random password)
	t.Run("InitDefaultFileWithRandomPassword", func(t *testing.T) {
		stdout, stderr, err := runCLI(t, []string{"init"}, "", tempDir)
		if err != nil {
			t.Fatalf("init command failed: %v\nStderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, "Random password generated. Please keep this password safe:") ||
			!strings.Contains(stdout, "Password: ") ||
			!strings.Contains(stdout, fmt.Sprintf("Secret file '%s' successfully initialized.", filepath.Base(defaultFilePath))) {
			t.Errorf("init command output incorrect.\nStdout: %s\nStderr: %s", stdout, stderr)
		}
		if _, err := os.Stat(defaultFilePath); os.IsNotExist(err) {
			t.Errorf("Default secret file not created: %s", defaultFilePath)
		}
		sf, err := file.ReadSecretFile(defaultFilePath)
		if err != nil {
			t.Errorf("Failed to read initialized file: %v", err)
		}
		if sf.Hash == "" {
			t.Errorf("Hash field in initialized file is empty.")
		}
		os.Remove(defaultFilePath)
	})

	// 2. Test normal initialization (with file argument and password)
	t.Run("InitCustomFileWithPassword", func(t *testing.T) {
		stdout, stderr, err := runCLI(t, []string{"init", customFilePath, "-p", testPassword}, "", tempDir)
		if err != nil {
			t.Fatalf("init command failed: %v\nStderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, fmt.Sprintf("Secret file '%s' successfully initialized.", customFilePath)) {
			t.Errorf("init command output incorrect.\nStdout: %s\nStderr: %s", stdout, stderr)
		}
		if _, err := os.Stat(customFilePath); os.IsNotExist(err) {
			t.Errorf("Custom secret file not created: %s", customFilePath)
		}
		os.Remove(customFilePath)
	})

	// 3. Test file exists, no force overwrite, user chooses not to overwrite
	t.Run("InitFileExistsNoForceNoOverwrite", func(t *testing.T) {
		originalContent := `{"old":"value"}`
		ioutil.WriteFile(defaultFilePath, []byte(originalContent), 0644)

		stdout, stderr, err := runCLI(t, []string{"init"}, "n\n", tempDir)
		if err != nil {
			t.Fatalf("init command failed: %v\nStderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, fmt.Sprintf("Secret file '%s' already exists. Overwrite? (y/N):", filepath.Base(defaultFilePath))) ||
			!strings.Contains(stdout, "Initialization cancelled.") {
			t.Errorf("init command output incorrect.\nStdout: %s\nStderr: %s", stdout, stderr)
		}
		content, _ := ioutil.ReadFile(defaultFilePath)
		if string(content) != originalContent {
			t.Errorf("File was unexpectedly modified.\nExpected: %s\nActual: %s", originalContent, string(content))
		}
		os.Remove(defaultFilePath)
	})

	// 4. Test file exists, no force overwrite, user chooses to overwrite
	t.Run("InitFileExistsNoForceOverwrite", func(t *testing.T) {
		ioutil.WriteFile(defaultFilePath, []byte(`{"old":"value"}`), 0644)

		stdout, stderr, err := runCLI(t, []string{"init"}, "y\n", tempDir)
		if err != nil {
			t.Fatalf("init command failed: %v\nStderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, fmt.Sprintf("Secret file '%s' already exists. Overwrite? (y/N):", filepath.Base(defaultFilePath))) ||
			!strings.Contains(stdout, "Random password generated. Please keep this password safe:") ||
			!strings.Contains(stdout, "Password: ") ||
			!strings.Contains(stdout, fmt.Sprintf("Secret file '%s' successfully initialized.", filepath.Base(defaultFilePath))) {
			t.Errorf("init command output incorrect.\nStdout: %s\nStderr: %s", stdout, stderr)
		}
		sf, err := file.ReadSecretFile(defaultFilePath)
		if err != nil {
			t.Errorf("Failed to read initialized file: %v", err)
		}
		if len(sf.Secrets) != 0 || sf.Hash == "" {
			t.Errorf("File was not properly overwritten or content is incorrect.")
		}
		os.Remove(defaultFilePath)
	})

	// 5. Test file exists, force overwrite
	t.Run("InitFileExistsForceOverwrite", func(t *testing.T) {
		ioutil.WriteFile(defaultFilePath, []byte(`{"old":"value"}`), 0644)

		stdout, stderr, err := runCLI(t, []string{"init", "-F"}, "", tempDir)
		if err != nil {
			t.Fatalf("init command failed: %v\nStderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, "Random password generated. Please keep this password safe:") ||
			!strings.Contains(stdout, "Password: ") ||
			!strings.Contains(stdout, fmt.Sprintf("Secret file '%s' successfully initialized.", filepath.Base(defaultFilePath))) ||
			strings.Contains(stdout, "Overwrite?") {
			t.Errorf("init command output incorrect.\nStdout: %s\nStderr: %s", stdout, stderr)
		}
		sf, err := file.ReadSecretFile(defaultFilePath)
		if err != nil {
			t.Errorf("Failed to read initialized file: %v", err)
		}
		if len(sf.Secrets) != 0 || sf.Hash == "" {
			t.Errorf("File was not properly overwritten or content is incorrect.")
		}
		os.Remove(defaultFilePath)
	})

	// 6. Test missing password (when specifying file)
	t.Run("InitMissingPasswordForCustomFile", func(t *testing.T) {
		stdout, stderr, err := runCLI(t, []string{"init", customFilePath}, "", tempDir)
		if err == nil {
			t.Errorf("init command succeeded but was expected to fail due to missing password.")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 1 {
			t.Errorf("Expected exit code 1, actual: %v", err)
		}
		if !strings.Contains(stderr, "When specifying a file, password must be provided via -p or --password flag.") {
			t.Errorf("init command stderr output incorrect.\nStdout: %s\nStderr: %s", stdout, stderr)
		}
		if _, err := os.Stat(customFilePath); !os.IsNotExist(err) {
			t.Errorf("File should not have been created, but it exists: %s", customFilePath)
		}
	})

	// 7. Test write file failure (simulate permission issue)
	t.Run("InitWriteFileFailure", func(t *testing.T) {
		readOnlyDir := filepath.Join(tempDir, "readonly_dir")
		os.Mkdir(readOnlyDir, 0555)
		defer os.RemoveAll(readOnlyDir)

		readOnlyFilePath := filepath.Join(readOnlyDir, "test.json")
		stdout, stderr, err := runCLI(t, []string{"init", readOnlyFilePath, "-p", testPassword}, "", tempDir)
		if err == nil {
			t.Errorf("init command succeeded but was expected to fail due to write failure.")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 1 {
			t.Errorf("Expected exit code 1, actual: %v", err)
		}
		if !strings.Contains(stderr, fmt.Sprintf("Error: Failed to create secret file '%s':", readOnlyFilePath)) {
			t.Errorf("init command stderr output incorrect.\nStdout: %s\nStderr: %s", stdout, stderr)
		}
		if _, err := os.Stat(readOnlyFilePath); !os.IsNotExist(err) {
			t.Errorf("File should not have been created, but it exists: %s", readOnlyFilePath)
		}
		os.Remove(readOnlyFilePath)
	})
}

// TestSetCommand tests the set command
func TestSetCommand(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "go-secret-test-set-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	secretFilePath := filepath.Join(tempDir, "test-secrets.json")
	testPassword := "setTestPassword"
	key1, value1 := "MY_API_KEY", "12345abcdef"
	key2, value2 := "DATABASE_URL", "postgres://user:pass@host:port/db"

	createEncryptedFile := func(filePath, password string, secrets map[string]string) {
		passwordBytes := []byte(password)
		defer func() {
			for i := range passwordBytes {
				passwordBytes[i] = 0
			}
		}()
		encryptedSecrets := make(map[string]string)
		for k, v := range secrets {
			encVal, err := crypto.Encrypt(v, passwordBytes)
			if err != nil {
				t.Fatalf("Failed to encrypt secret for test setup: %v", err)
			}
			encryptedSecrets[k] = encVal
		}
		hash := file.CalculateSecretsHash(secrets)
		sf := &file.SecretFile{
			Secrets: encryptedSecrets,
			Hash:    hash,
		}
		if err := file.WriteSecretFile(filePath, sf); err != nil {
			t.Fatalf("Failed to write secret file for test setup: %v", err)
		}
	}

	t.Run("SetNormal", func(t *testing.T) {
		secretsToSet := map[string]string{key1: value1, key2: value2}
		createEncryptedFile(secretFilePath, testPassword, secretsToSet)

		stdout, stderr, err := runCLI(t, []string{"set", secretFilePath, "-p", testPassword}, "", tempDir)
		if err != nil {
			t.Fatalf("set command failed: %v\nStderr: %s", err, stderr)
		}

		if !strings.Contains(stdout, fmt.Sprintf("Setting environment variables from '%s'...", secretFilePath)) {
			t.Errorf("Expected setup message not found in stdout.\nStdout: %s", stdout)
		}
		if !strings.Contains(stdout, fmt.Sprintf("Environment variable set: %s", key1)) {
			t.Errorf("Expected set message for %s not found in stdout.\nStdout: %s", key1, stdout)
		}
		if !strings.Contains(stdout, fmt.Sprintf("Environment variable set: %s", key2)) {
			t.Errorf("Expected set message for %s not found in stdout.\nStdout: %s", key2, stdout)
		}
		if !strings.Contains(stdout, "Environment variables setup completed.") {
			t.Errorf("Expected completion message not found in stdout.\nStdout: %s", stdout)
		}
		os.Remove(secretFilePath)
	})

	t.Run("SetFileNotFound", func(t *testing.T) {
		nonExistentFile := filepath.Join(tempDir, "nonexistent.json")
		_, stderr, err := runCLI(t, []string{"set", nonExistentFile, "-p", testPassword}, "", tempDir)
		if err == nil {
			t.Fatalf("set command succeeded but was expected to fail for non-existent file.")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() == 0 {
			t.Errorf("Expected non-zero exit code for non-existent file, actual: %v", err)
		}
		expectedErrorMsg := "Secret file hash verification failed"
		if !strings.Contains(stderr, expectedErrorMsg) {
			t.Errorf("Expected error message containing '%s' not found in stderr.\nStderr: %s", expectedErrorMsg, stderr)
		}
	})

	t.Run("SetIncorrectPassword", func(t *testing.T) {
		secretsToSet := map[string]string{key1: value1}
		createEncryptedFile(secretFilePath, testPassword, secretsToSet)

		_, stderr, err := runCLI(t, []string{"set", secretFilePath, "-p", "wrongPassword"}, "", tempDir)
		if err == nil {
			t.Fatalf("set command succeeded but was expected to fail due to incorrect password.")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() == 0 {
			t.Errorf("Expected non-zero exit code for incorrect password, actual: %v", err)
		}
		expectedErrorMsg := "Secret file hash verification failed, and one or more secrets decryption failed"
		if !strings.Contains(stderr, expectedErrorMsg) {
			t.Errorf("Expected error message containing '%s' not found in stderr.\nStderr: %s", expectedErrorMsg, stderr)
		}
		expectedWarning := fmt.Sprintf("Warning: Cannot decrypt key '%s'", key1)
		if !strings.Contains(stderr, expectedWarning) {
			t.Errorf("Expected warning message '%s' not found in stderr.\nStderr: %s", expectedWarning, stderr)
		}
		os.Remove(secretFilePath)
	})

	t.Run("SetHashMismatch", func(t *testing.T) {
		secretsToSet := map[string]string{key1: value1}
		createEncryptedFile(secretFilePath, testPassword, secretsToSet)

		sfRead, _ := file.ReadSecretFile(secretFilePath)
		sfRead.Hash = "tamperedhash"
		file.WriteSecretFile(secretFilePath, sfRead)

		_, stderr, err := runCLI(t, []string{"set", secretFilePath, "-p", testPassword}, "", tempDir)
		if err == nil {
			t.Fatalf("set command succeeded but was expected to fail due to hash mismatch.")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() == 0 {
			t.Errorf("Expected non-zero exit code, actual: %v", err)
		}
		expectedErrorMsg := "Secret file hash verification failed"
		if !strings.Contains(stderr, expectedErrorMsg) {
			t.Errorf("Expected error message '%s' not found in stderr.\nStderr: %s", expectedErrorMsg, stderr)
		}
		os.Remove(secretFilePath)
	})

	t.Run("SetInvalidJSONStructure", func(t *testing.T) {
		invalidJSONContent := `{"key1": "value1", "nested_key": {"subkey": "subvalue"}, "__hash__": "somehash"}`
		ioutil.WriteFile(secretFilePath, []byte(invalidJSONContent), 0644)

		_, stderr, err := runCLI(t, []string{"set", secretFilePath, "-p", testPassword}, "", tempDir)
		if err == nil {
			t.Fatalf("set command succeeded but was expected to fail due to invalid JSON structure.")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() == 0 {
			t.Errorf("Expected non-zero exit code, actual: %v", err)
		}
		expectedErrorMsg := "nested objects are not supported"
		if !strings.Contains(stderr, expectedErrorMsg) {
			t.Errorf("Expected error message '%s' not found in stderr.\nStderr: %s", expectedErrorMsg, stderr)
		}
		os.Remove(secretFilePath)
	})
}

// TestUnsetCommand tests the unset command
func TestUnsetCommand(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "go-secret-test-unset-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	secretFilePath := filepath.Join(tempDir, "test-secrets-unset.json")
	testPassword := "unsetTestPassword"
	key1, value1 := "MY_UNSET_KEY", "unset_value_1"
	key2, value2 := "ANOTHER_KEY", "unset_value_2"

	createEncryptedFile := func(filePath, password string, secrets map[string]string) {
		passwordBytes := []byte(password)
		defer func() {
			for i := range passwordBytes {
				passwordBytes[i] = 0
			}
		}()
		encryptedSecrets := make(map[string]string)
		for k, v := range secrets {
			encVal, err := crypto.Encrypt(v, passwordBytes)
			if err != nil {
				t.Fatalf("Failed to encrypt secret for test setup: %v", err)
			}
			encryptedSecrets[k] = encVal
		}
		hash := file.CalculateSecretsHash(secrets)
		sf := &file.SecretFile{
			Secrets: encryptedSecrets,
			Hash:    hash,
		}
		if err := file.WriteSecretFile(filePath, sf); err != nil {
			t.Fatalf("Failed to write secret file for test setup: %v", err)
		}
	}

	t.Run("UnsetNormal", func(t *testing.T) {
		secretsToUnset := map[string]string{key1: value1, key2: value2}
		createEncryptedFile(secretFilePath, testPassword, secretsToUnset)

		stdout, stderr, err := runCLI(t, []string{"unset", secretFilePath, "-p", testPassword}, "", tempDir)
		if err != nil {
			t.Fatalf("unset command failed: %v\nStderr: %s", err, stderr)
		}

		if !strings.Contains(stdout, fmt.Sprintf("unset %s", key1)) {
			t.Errorf("Expected unset command for %s not found in stdout.\nStdout: %s", key1, stdout)
		}
		if !strings.Contains(stdout, fmt.Sprintf("unset %s", key2)) {
			t.Errorf("Expected unset command for %s not found in stdout.\nStdout: %s", key2, stdout)
		}
		if !strings.Contains(stdout, "# Please execute the following commands in your shell to unset environment variables:") {
			t.Errorf("Expected instructional comment not found in stdout.\nStdout: %s", stdout)
		}
		os.Remove(secretFilePath)
	})

	t.Run("UnsetFileNotFound", func(t *testing.T) {
		nonExistentFile := filepath.Join(tempDir, "nonexistent-unset.json")
		_, stderr, err := runCLI(t, []string{"unset", nonExistentFile, "-p", testPassword}, "", tempDir)
		if err == nil {
			t.Fatalf("unset command succeeded but was expected to fail for non-existent file.")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() == 0 {
			t.Errorf("Expected non-zero exit code, actual: %v", err)
		}
		expectedErrorMsg := "Secret file hash verification failed"
		if !strings.Contains(stderr, expectedErrorMsg) {
			t.Errorf("Expected error message containing '%s' not found in stderr.\nStderr: %s", expectedErrorMsg, stderr)
		}
	})

	t.Run("UnsetIncorrectPassword", func(t *testing.T) {
		secretsToUnset := map[string]string{key1: value1}
		createEncryptedFile(secretFilePath, testPassword, secretsToUnset)

		stdout, stderr, err := runCLI(t, []string{"unset", secretFilePath, "-p", "wrongPassword"}, "", tempDir)
		if err == nil {
			t.Fatalf("unset command succeeded but was expected to fail due to incorrect password leading to hash mismatch.")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() == 0 {
			t.Errorf("Expected non-zero exit code for incorrect password, actual: %v", err)
		}

		expectedErrorMsg := "Secret file hash verification failed, and one or more secrets decryption failed"
		if !strings.Contains(stderr, expectedErrorMsg) {
			t.Errorf("Expected error message containing '%s' not found in stderr.\nStderr: %s", expectedErrorMsg, stderr)
		}
		expectedWarning := fmt.Sprintf("Warning: Cannot decrypt key '%s'", key1)
		if !strings.Contains(stderr, expectedWarning) {
			t.Errorf("Expected warning message for key '%s' not found in stderr.\nStderr: %s", key1, stderr)
		}
		if strings.Contains(stdout, fmt.Sprintf("unset %s", key1)) {
			t.Errorf("Unset command for %s found in stdout, but command should have failed earlier.\nStdout: %s", key1, stdout)
		}
		os.Remove(secretFilePath)
	})

	t.Run("UnsetHashMismatch", func(t *testing.T) {
		secretsToUnset := map[string]string{key1: value1}
		createEncryptedFile(secretFilePath, testPassword, secretsToUnset)

		sfRead, _ := file.ReadSecretFile(secretFilePath)
		sfRead.Hash = "tamperedhash"
		file.WriteSecretFile(secretFilePath, sfRead)

		_, stderr, err := runCLI(t, []string{"unset", secretFilePath, "-p", testPassword}, "", tempDir)
		if err == nil {
			t.Fatalf("unset command succeeded but was expected to fail due to hash mismatch.")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() == 0 {
			t.Errorf("Expected non-zero exit code, actual: %v", err)
		}
		expectedErrorMsg := "Secret file hash verification failed"
		if !strings.Contains(stderr, expectedErrorMsg) {
			t.Errorf("Expected error message '%s' not found in stderr.\nStderr: %s", expectedErrorMsg, stderr)
		}
		os.Remove(secretFilePath)
	})
}

// TestExportCommand tests the export command
func TestExportCommand(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "go-secret-test-export-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	secretFilePath := filepath.Join(tempDir, "test-secrets-export.json")
	testPassword := "exportTestPassword"
	key1, value1 := "EXPORT_KEY_1", "export_value_1"
	key2, value2 := "EXPORT_KEY_2", "export_value_2"

	createEncryptedFile := func(filePath, password string, secrets map[string]string) {
		passwordBytes := []byte(password)
		defer func() {
			for i := range passwordBytes {
				passwordBytes[i] = 0
			}
		}()
		encryptedSecrets := make(map[string]string)
		for k, v := range secrets {
			encVal, err := crypto.Encrypt(v, passwordBytes)
			if err != nil {
				t.Fatalf("Failed to encrypt secret for test setup: %v", err)
			}
			encryptedSecrets[k] = encVal
		}
		hash := file.CalculateSecretsHash(secrets)
		sf := &file.SecretFile{
			Secrets: encryptedSecrets,
			Hash:    hash,
		}
		if err := file.WriteSecretFile(filePath, sf); err != nil {
			t.Fatalf("Failed to write secret file for test setup: %v", err)
		}
	}

	// 1. Test normal export to JSON
	t.Run("ExportToJsonNormal", func(t *testing.T) {
		secretsToExport := map[string]string{key1: value1, key2: value2}
		createEncryptedFile(secretFilePath, testPassword, secretsToExport)

		outputJsonPath := filepath.Join(tempDir, "exported.json")
		stdout, stderr, err := runCLI(t, []string{"export", secretFilePath, "-p", testPassword, "-o", outputJsonPath}, "", tempDir)
		if err != nil {
			t.Fatalf("export command failed: %v\nStderr: %s", err, stderr)
		}

		if !strings.Contains(stdout, fmt.Sprintf("Secrets successfully exported to JSON file '%s'.", outputJsonPath)) {
			t.Errorf("Expected success message not found in stdout.\nStdout: %s", stdout)
		}

		// Verify output JSON file content
		exportedData, err := ioutil.ReadFile(outputJsonPath)
		if err != nil {
			t.Fatalf("Failed to read exported JSON file: %v", err)
		}

		var exportedSecrets map[string]string
		if err := json.Unmarshal(exportedData, &exportedSecrets); err != nil {
			t.Fatalf("Failed to unmarshal exported JSON: %v", err)
		}

		if _, ok := exportedSecrets[file.HashField]; ok {
			t.Errorf("Exported JSON should not contain __hash__ field.")
		}
		if len(exportedSecrets) != len(secretsToExport) {
			t.Errorf("Exported secrets count mismatch. Expected %d, Got %d", len(secretsToExport), len(exportedSecrets))
		}
		for k, v := range secretsToExport {
			if exportedSecrets[k] != v {
				t.Errorf("Exported secret mismatch for key '%s'. Expected '%s', Got '%s'", k, v, exportedSecrets[k])
			}
		}
		os.Remove(secretFilePath)
		os.Remove(outputJsonPath)
	})

	// 2. Test normal export to .env
	t.Run("ExportToEnvNormal", func(t *testing.T) {
		secretsToExport := map[string]string{key1: value1, key2: value2}
		createEncryptedFile(secretFilePath, testPassword, secretsToExport)

		outputEnvPath := filepath.Join(tempDir, "exported.env")
		stdout, stderr, err := runCLI(t, []string{"export", secretFilePath, "-p", testPassword, "-o", outputEnvPath}, "", tempDir)
		if err != nil {
			t.Fatalf("export command failed: %v\nStderr: %s", err, stderr)
		}

		if !strings.Contains(stdout, fmt.Sprintf("Secrets successfully exported to .env file '%s'.", outputEnvPath)) {
			t.Errorf("Expected success message not found in stdout.\nStdout: %s", stdout)
		}

		// Verify output .env file content
		exportedData, err := ioutil.ReadFile(outputEnvPath)
		if err != nil {
			t.Fatalf("Failed to read exported .env file: %v", err)
		}

		contentLines := strings.Split(strings.TrimSpace(string(exportedData)), "\n")
		if len(contentLines) != len(secretsToExport) {
			t.Errorf("Exported .env lines count mismatch. Expected %d, Got %d", len(secretsToExport), len(contentLines))
		}

		exportedMap := make(map[string]string)
		for _, line := range contentLines {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				exportedMap[parts[0]] = parts[1]
			}
		}

		for k, v := range secretsToExport {
			if exportedMap[k] != v {
				t.Errorf("Exported .env secret mismatch for key '%s'. Expected '%s', Got '%s'", k, v, exportedMap[k])
			}
		}
		os.Remove(secretFilePath)
		os.Remove(outputEnvPath)
	})

	// 3. Test input file not found
	t.Run("ExportInputFileNotFound", func(t *testing.T) {
		nonExistentFile := filepath.Join(tempDir, "nonexistent-input.json")
		outputJsonPath := filepath.Join(tempDir, "output.json")
		_, stderr, err := runCLI(t, []string{"export", nonExistentFile, "-p", testPassword, "-o", outputJsonPath}, "", tempDir)
		if err == nil {
			t.Fatalf("export command succeeded but was expected to fail for non-existent input file.")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() == 0 {
			t.Errorf("Expected non-zero exit code, actual: %v", err)
		}
		expectedErrorMsg := "Secret file hash verification failed, file may have been tampered with or password is incorrect."
		if !strings.Contains(stderr, expectedErrorMsg) {
			t.Errorf("Expected error message containing '%s' not found in stderr.\nStderr: %s", expectedErrorMsg, stderr)
		}
	})

	// 4. Test incorrect password
	t.Run("ExportIncorrectPassword", func(t *testing.T) {
		secretsToExport := map[string]string{key1: value1}
		createEncryptedFile(secretFilePath, testPassword, secretsToExport)

		outputJsonPath := filepath.Join(tempDir, "output.json")
		_, stderr, err := runCLI(t, []string{"export", secretFilePath, "-p", "wrongPassword", "-o", outputJsonPath}, "", tempDir)
		if err == nil {
			t.Fatalf("export command succeeded but was expected to fail due to incorrect password.")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() == 0 {
			t.Errorf("Expected non-zero exit code, actual: %v", err)
		}
		expectedErrorMsg := fmt.Sprintf("Error: Cannot decrypt key '%s':", key1)
		if !strings.Contains(stderr, expectedErrorMsg) {
			t.Errorf("Expected error message containing '%s' not found in stderr.\nStderr: %s", expectedErrorMsg, stderr)
		}
		os.Remove(secretFilePath)
	})

	// 5. Test hash mismatch (tampered file)
	t.Run("ExportHashMismatch", func(t *testing.T) {
		secretsToExport := map[string]string{key1: value1}
		createEncryptedFile(secretFilePath, testPassword, secretsToExport)

		sfRead, _ := file.ReadSecretFile(secretFilePath)
		sfRead.Hash = "tamperedhash" // Tamper with the hash
		file.WriteSecretFile(secretFilePath, sfRead)

		outputJsonPath := filepath.Join(tempDir, "output.json")
		_, stderr, err := runCLI(t, []string{"export", secretFilePath, "-p", testPassword, "-o", outputJsonPath}, "", tempDir)
		if err == nil {
			t.Fatalf("export command succeeded but was expected to fail due to hash mismatch.")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() == 0 {
			t.Errorf("Expected non-zero exit code, actual: %v", err)
		}
		expectedErrorMsg := "Secret file hash verification failed, file may have been tampered with or password is incorrect."
		if !strings.Contains(stderr, expectedErrorMsg) {
			t.Errorf("Expected error message '%s' not found in stderr.\nStderr: %s", expectedErrorMsg, stderr)
		}
		os.Remove(secretFilePath)
	})

	// 6. Test missing output file flag
	t.Run("ExportMissingOutputFlag", func(t *testing.T) {
		secretsToExport := map[string]string{key1: value1}
		createEncryptedFile(secretFilePath, testPassword, secretsToExport)

		_, stderr, err := runCLI(t, []string{"export", secretFilePath, "-p", testPassword}, "", tempDir) // Missing -o
		if err == nil {
			t.Fatalf("export command succeeded but was expected to fail due to missing output flag.")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() == 0 {
			t.Errorf("Expected non-zero exit code, actual: %v", err)
		}
		expectedErrorMsg := "Error: required flag(s) \"output\" not set" // Cobra's default error message
		if !strings.Contains(stderr, expectedErrorMsg) {
			t.Errorf("Expected error message '%s' not found in stderr.\nStderr: %s", expectedErrorMsg, stderr)
		}
		os.Remove(secretFilePath)
	})

	// 7. Test unsupported output format
	t.Run("ExportUnsupportedFormat", func(t *testing.T) {
		secretsToExport := map[string]string{key1: value1}
		createEncryptedFile(secretFilePath, testPassword, secretsToExport)

		outputTxtPath := filepath.Join(tempDir, "exported.txt")
		_, stderr, err := runCLI(t, []string{"export", secretFilePath, "-p", testPassword, "-o", outputTxtPath}, "", tempDir)
		if err == nil {
			t.Fatalf("export command succeeded but was expected to fail due to unsupported format.")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() == 0 {
			t.Errorf("Expected non-zero exit code, actual: %v", err)
		}
		expectedErrorMsg := "Error: Unsupported output file format. Output file must end with '.json' or '.env'."
		if !strings.Contains(stderr, expectedErrorMsg) {
			t.Errorf("Expected error message '%s' not found in stderr.\nStderr: %s", expectedErrorMsg, stderr)
		}
		os.Remove(secretFilePath)
	})

	// 8. Test export of an empty secrets file (only __hash__)
	t.Run("ExportEmptySecretsFile", func(t *testing.T) {
		// Create an empty secrets file using init command
		initPassword := "emptyfilepass"
		initFilePath := filepath.Join(tempDir, "empty-secrets.json")
		_, initStderr, initErr := runCLI(t, []string{"init", initFilePath, "-p", initPassword}, "", tempDir)
		if initErr != nil {
			t.Fatalf("Failed to init empty secrets file for test setup: %v\nStderr: %s", initErr, initStderr)
		}

		outputJsonPath := filepath.Join(tempDir, "exported_empty.json")
		stdout, stderr, err := runCLI(t, []string{"export", initFilePath, "-p", initPassword, "-o", outputJsonPath}, "", tempDir)
		if err != nil {
			t.Fatalf("export command failed for empty file: %v\nStderr: %s", err, stderr)
		}

		if !strings.Contains(stdout, fmt.Sprintf("Secrets successfully exported to JSON file '%s'.", outputJsonPath)) {
			t.Errorf("Expected success message not found in stdout for empty file export.\nStdout: %s", stdout)
		}

		exportedData, err := ioutil.ReadFile(outputJsonPath)
		if err != nil {
			t.Fatalf("Failed to read exported empty JSON file: %v", err)
		}

		var exportedSecrets map[string]string
		if err := json.Unmarshal(exportedData, &exportedSecrets); err != nil {
			t.Fatalf("Failed to unmarshal exported empty JSON: %v", err)
		}

		if len(exportedSecrets) != 0 {
			t.Errorf("Exported JSON for empty file should be empty. Got %v", exportedSecrets)
		}
		os.Remove(initFilePath)
		os.Remove(outputJsonPath)
	})
}

// TestImportCommand tests the import command
func TestImportCommand(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "go-secret-test-import-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	plainInputPath := filepath.Join(tempDir, "plain-secrets.json")
	encryptedOutputPath := filepath.Join(tempDir, "encrypted-secrets.json")
	testPassword := "importTestPassword"
	key1, value1 := "IMPORT_KEY_1", "import_value_1"
	key2, value2 := "IMPORT_KEY_2", "import_value_2"

	// Helper to create a plain JSON file
	createPlainJSONFile := func(filePath string, secrets map[string]string) {
		data, err := json.MarshalIndent(secrets, "", "  ")
		if err != nil {
			t.Fatalf("Failed to marshal plain JSON for test setup: %v", err)
		}
		if err := ioutil.WriteFile(filePath, data, 0644); err != nil {
			t.Fatalf("Failed to write plain JSON file for test setup: %v", err)
		}
	}

	// 1. Test normal import
	t.Run("ImportNormal", func(t *testing.T) {
		secretsToImport := map[string]string{key1: value1, key2: value2}
		createPlainJSONFile(plainInputPath, secretsToImport)

		stdout, stderr, err := runCLI(t, []string{"import", plainInputPath, "-p", testPassword, "-o", encryptedOutputPath}, "", tempDir)
		if err != nil {
			t.Fatalf("import command failed: %v\nStderr: %s", err, stderr)
		}

		if !strings.Contains(stdout, fmt.Sprintf("Secrets successfully imported from unencrypted file '%s' and encrypted to '%s'.", plainInputPath, encryptedOutputPath)) {
			t.Errorf("Expected success message not found in stdout.\nStdout: %s", stdout)
		}

		// Verify output encrypted file content
		sf, err := file.ReadSecretFile(encryptedOutputPath)
		if err != nil {
			t.Fatalf("Failed to read encrypted output file: %v", err)
		}

		// Decrypt and verify
		decryptedSecrets := make(map[string]string)
		passwordBytes := []byte(testPassword)
		defer func() {
			for i := range passwordBytes {
				passwordBytes[i] = 0
			}
		}()
		for k, encryptedValue := range sf.Secrets {
			if k == file.HashField {
				continue
			}
			decryptedValue, err := crypto.Decrypt(encryptedValue, passwordBytes)
			if err != nil {
				t.Errorf("Failed to decrypt key '%s' from imported file: %v", k, err)
				continue
			}
			decryptedSecrets[k] = decryptedValue
		}

		if !file.VerifySecretsHash(decryptedSecrets, sf.Hash) {
			t.Errorf("Hash verification failed for imported file.")
		}

		if len(decryptedSecrets) != len(secretsToImport) {
			t.Errorf("Decrypted secrets count mismatch. Expected %d, Got %d", len(secretsToImport), len(decryptedSecrets))
		}
		for k, v := range secretsToImport {
			if decryptedSecrets[k] != v {
				t.Errorf("Decrypted secret mismatch for key '%s'. Expected '%s', Got '%s'", k, v, decryptedSecrets[k])
			}
		}
		os.Remove(plainInputPath)
		os.Remove(encryptedOutputPath)
	})

	// 2. Test input file not found
	t.Run("ImportInputFileNotFound", func(t *testing.T) {
		nonExistentFile := filepath.Join(tempDir, "nonexistent-plain.json")
		_, stderr, err := runCLI(t, []string{"import", nonExistentFile, "-p", testPassword, "-o", encryptedOutputPath}, "", tempDir)
		if err == nil {
			t.Fatalf("import command succeeded but was expected to fail for non-existent input file.")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() == 0 {
			t.Errorf("Expected non-zero exit code, actual: %v", err)
		}
		expectedErrorMsg := fmt.Sprintf("Error: Cannot read input file '%s':", nonExistentFile)
		if !strings.Contains(stderr, expectedErrorMsg) {
			t.Errorf("Expected error message containing '%s' not found in stderr.\nStderr: %s", expectedErrorMsg, stderr)
		}
	})

	// 3. Test missing password
	t.Run("ImportMissingPassword", func(t *testing.T) {
		secretsToImport := map[string]string{key1: value1}
		createPlainJSONFile(plainInputPath, secretsToImport)

		_, stderr, err := runCLI(t, []string{"import", plainInputPath, "-o", encryptedOutputPath}, "", tempDir) // Missing -p
		if err == nil {
			t.Fatalf("import command succeeded but was expected to fail due to missing password.")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() == 0 {
			t.Errorf("Expected non-zero exit code, actual: %v", err)
		}
		expectedErrorMsg := "Error: Password must be provided via -p or --password flag."
		if !strings.Contains(stderr, expectedErrorMsg) {
			t.Errorf("Expected error message '%s' not found in stderr.\nStderr: %s", expectedErrorMsg, stderr)
		}
		os.Remove(plainInputPath)
	})

	// 4. Test missing output file flag
	t.Run("ImportMissingOutputFlag", func(t *testing.T) {
		secretsToImport := map[string]string{key1: value1}
		createPlainJSONFile(plainInputPath, secretsToImport)

		_, stderr, err := runCLI(t, []string{"import", plainInputPath, "-p", testPassword}, "", tempDir) // Missing -o
		if err == nil {
			t.Fatalf("import command succeeded but was expected to fail due to missing output flag.")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() == 0 {
			t.Errorf("Expected non-zero exit code, actual: %v", err)
		}
		expectedErrorMsg := "Error: required flag(s) \"output\" not set"
		if !strings.Contains(stderr, expectedErrorMsg) {
			t.Errorf("Expected error message '%s' not found in stderr.\nStderr: %s", expectedErrorMsg, stderr)
		}
		os.Remove(plainInputPath)
	})

	// 5. Test invalid input JSON (malformed JSON)
	t.Run("ImportMalformedJSON", func(t *testing.T) {
		malformedJSONPath := filepath.Join(tempDir, "malformed.json")
		ioutil.WriteFile(malformedJSONPath, []byte(`{"key1": "value1", "key2":`), 0644) // Incomplete JSON

		_, stderr, err := runCLI(t, []string{"import", malformedJSONPath, "-p", testPassword, "-o", encryptedOutputPath}, "", tempDir)
		if err == nil {
			t.Fatalf("import command succeeded but was expected to fail due to malformed JSON.")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() == 0 {
			t.Errorf("Expected non-zero exit code, actual: %v", err)
		}
		expectedErrorMsg := fmt.Sprintf("Error: Failed to parse input JSON file '%s':", malformedJSONPath)
		if !strings.Contains(stderr, expectedErrorMsg) {
			t.Errorf("Expected error message containing '%s' not found in stderr.\nStderr: %s", expectedErrorMsg, stderr)
		}
		os.Remove(malformedJSONPath)
	})

	// 6. Test invalid input JSON (nested object)
	t.Run("ImportNestedObjectJSON", func(t *testing.T) {
		nestedJSONPath := filepath.Join(tempDir, "nested.json")
		ioutil.WriteFile(nestedJSONPath, []byte(`{"key1": "value1", "nested": {"subkey": "subvalue"}}`), 0644)

		_, stderr, err := runCLI(t, []string{"import", nestedJSONPath, "-p", testPassword, "-o", encryptedOutputPath}, "", tempDir)
		if err == nil {
			t.Fatalf("import command succeeded but was expected to fail due to nested object.")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() == 0 {
			t.Errorf("Expected non-zero exit code, actual: %v", err)
		}
		expectedErrorMsg := fmt.Sprintf("Error: Input JSON file '%s' contains nested objects, import not supported.", nestedJSONPath)
		if !strings.Contains(stderr, expectedErrorMsg) {
			t.Errorf("Expected error message '%s' not found in stderr.\nStderr: %s", expectedErrorMsg, stderr)
		}
		os.Remove(nestedJSONPath)
	})

	// 7. Test invalid input JSON (nested array)
	t.Run("ImportNestedArrayJSON", func(t *testing.T) {
		nestedArrayPath := filepath.Join(tempDir, "nested_array.json")
		ioutil.WriteFile(nestedArrayPath, []byte(`{"key1": "value1", "array": ["item1", "item2"]}`), 0644)

		_, stderr, err := runCLI(t, []string{"import", nestedArrayPath, "-p", testPassword, "-o", encryptedOutputPath}, "", tempDir)
		if err == nil {
			t.Fatalf("import command succeeded but was expected to fail due to nested array.")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() == 0 {
			t.Errorf("Expected non-zero exit code, actual: %v", err)
		}
		expectedErrorMsg := fmt.Sprintf("Error: Input JSON file '%s' contains nested arrays, import not supported.", nestedArrayPath)
		if !strings.Contains(stderr, expectedErrorMsg) {
			t.Errorf("Expected error message '%s' not found in stderr.\nStderr: %s", expectedErrorMsg, stderr)
		}
		os.Remove(nestedArrayPath)
	})

	// 8. Test invalid input JSON (non-string value)
	t.Run("ImportNonStringValueJSON", func(t *testing.T) {
		nonStringValuePath := filepath.Join(tempDir, "non_string.json")
		ioutil.WriteFile(nonStringValuePath, []byte(`{"key1": "value1", "number_key": 123}`), 0644)

		_, stderr, err := runCLI(t, []string{"import", nonStringValuePath, "-p", testPassword, "-o", encryptedOutputPath}, "", tempDir)
		if err == nil {
			t.Fatalf("import command succeeded but was expected to fail due to non-string value.")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() == 0 {
			t.Errorf("Expected non-zero exit code, actual: %v", err)
		}
		expectedErrorMsg := fmt.Sprintf("Error: Value for key 'number_key' in input JSON file '%s' is not a string type.", nonStringValuePath)
		if !strings.Contains(stderr, expectedErrorMsg) {
			t.Errorf("Expected error message '%s' not found in stderr.\nStderr: %s", expectedErrorMsg, stderr)
		}
		os.Remove(nonStringValuePath)
	})

	// 9. Test output file write failure (e.g., permissions)
	t.Run("ImportWriteFileFailure", func(t *testing.T) {
		secretsToImport := map[string]string{key1: value1}
		createPlainJSONFile(plainInputPath, secretsToImport)

		readOnlyDir := filepath.Join(tempDir, "readonly_dir")
		os.Mkdir(readOnlyDir, 0555) // 0555 means read-only directory, but allows entry
		defer os.RemoveAll(readOnlyDir)

		readOnlyOutputPath := filepath.Join(readOnlyDir, "test.json")
		_, stderr, err := runCLI(t, []string{"import", plainInputPath, "-p", testPassword, "-o", readOnlyOutputPath}, "", tempDir)
		if err == nil {
			t.Fatalf("import command succeeded but was expected to fail due to write failure.")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 1 {
			t.Errorf("Expected exit code 1, actual: %v", err)
		}
		expectedErrorMsg := fmt.Sprintf("Error: Failed to write output secret file '%s':", readOnlyOutputPath)
		if !strings.Contains(stderr, expectedErrorMsg) {
			t.Errorf("Expected error message containing '%s' not found in stderr.\nStderr: %s", expectedErrorMsg, stderr)
		}
		if _, err := os.Stat(readOnlyOutputPath); !os.IsNotExist(err) {
			t.Errorf("File should not have been created, but it exists: %s", readOnlyOutputPath)
		}
		os.Remove(plainInputPath)
	})
}

// TestEditCommand tests the edit command
func TestEditCommand(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "go-secret-test-edit-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	secretFilePath := filepath.Join(tempDir, "test-secrets-edit.json")
	testPassword := "editTestPassword"
	key1, value1 := "EDIT_KEY_1", "edit_value_1"
	key2, value2 := "EDIT_KEY_2", "edit_value_2"
	key3, value3 := "NEW_KEY", "new_value"

	createEncryptedFile := func(filePath, password string, secrets map[string]string) {
		passwordBytes := []byte(password)
		defer func() {
			for i := range passwordBytes {
				passwordBytes[i] = 0
			}
		}()
		encryptedSecrets := make(map[string]string)
		for k, v := range secrets {
			encVal, err := crypto.Encrypt(v, passwordBytes)
			if err != nil {
				t.Fatalf("Failed to encrypt secret for test setup: %v", err)
			}
			encryptedSecrets[k] = encVal
		}
		hash := file.CalculateSecretsHash(secrets)
		sf := &file.SecretFile{
			Secrets: encryptedSecrets,
			Hash:    hash,
		}
		if err := file.WriteSecretFile(filePath, sf); err != nil {
			t.Fatalf("Failed to write secret file for test setup: %v", err)
		}
	}

	// Helper to read and decrypt a secret file for verification
	readAndDecryptFile := func(filePath, password string) (map[string]string, error) {
		passwordBytes := []byte(password)
		defer func() {
			for i := range passwordBytes {
				passwordBytes[i] = 0
			}
		}()
		sf, err := file.ReadSecretFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read secret file: %w", err)
		}
		decryptedSecrets := make(map[string]string)
		for k, encryptedValue := range sf.Secrets {
			if k == file.HashField {
				continue
			}
			decryptedValue, err := crypto.Decrypt(encryptedValue, passwordBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt key '%s': %w", k, err)
			}
			decryptedSecrets[k] = decryptedValue
		}
		if !file.VerifySecretsHash(decryptedSecrets, sf.Hash) {
			return nil, fmt.Errorf("hash verification failed for file: %s", filePath)
		}
		return decryptedSecrets, nil
	}

	// 1. Test normal edit: add, modify, delete, then save
	t.Run("EditNormal_AddModifyDeleteSave", func(t *testing.T) {
		initialSecrets := map[string]string{key1: value1, key2: value2}
		createEncryptedFile(secretFilePath, testPassword, initialSecrets)

		// Simulate user input: add new, modify existing, delete one, then save
		input := fmt.Sprintf(`%s: "%s"
%s: "%s"
%s:
/save
`, key3, value3, key1, "modified_value_1", key2)

		stdout, stderr, err := runCLI(t, []string{"edit", secretFilePath, "-p", testPassword}, input, tempDir)
		if err != nil {
			t.Fatalf("edit command failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
		}

		// Check for key messages, allowing for ANSI color codes
		expectedOutputs := []string{
			"Entering interactive edit mode",
			key3, // Just check that NEW_KEY appears somewhere in output
			"modified_value_1",
			fmt.Sprintf("Key '%s' deleted.", key2),
			"Saving changes...",
			"successfully updated",
		}

		for _, msg := range expectedOutputs {
			if !strings.Contains(stdout, msg) {
				t.Errorf("Edit command output missing expected message: '%s'.\nStdout: %s\nStderr: %s", msg, stdout, stderr)
			}
		}

		// Verify the file content after saving
		finalSecrets, err := readAndDecryptFile(secretFilePath, testPassword)
		if err != nil {
			t.Fatalf("Failed to read and decrypt file after edit: %v", err)
		}

		expectedSecrets := map[string]string{
			key1: "modified_value_1",
			key3: value3,
		}

		if len(finalSecrets) != len(expectedSecrets) {
			t.Errorf("Final secrets count mismatch. Expected %d, Got %d. Final: %v", len(expectedSecrets), len(finalSecrets), finalSecrets)
		}
		for k, v := range expectedSecrets {
			if finalSecrets[k] != v {
				t.Errorf("Final secret mismatch for key '%s'. Expected '%s', Got '%s'", k, v, finalSecrets[k])
			}
		}
		if _, exists := finalSecrets[key2]; exists {
			t.Errorf("Key '%s' should have been deleted but still exists.", key2)
		}
		os.Remove(secretFilePath)
	})

	// 2. Test edit: quit without saving
	t.Run("EditNormal_QuitWithoutSave", func(t *testing.T) {
		initialSecrets := map[string]string{key1: value1}
		createEncryptedFile(secretFilePath, testPassword, initialSecrets)

		// Simulate user input: modify, then quit
		input := fmt.Sprintf(`%s: "%s"
/quit
`, key1, "unsaved_value")

		stdout, stderr, err := runCLI(t, []string{"edit", secretFilePath, "-p", testPassword}, input, tempDir)
		if err != nil {
			t.Fatalf("edit command failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
		}

		if !strings.Contains(stdout, "Entering interactive edit mode.") ||
			!strings.Contains(stdout, "Exiting edit mode, changes not saved.") {
			t.Errorf("Edit command output missing expected messages.\nStdout: %s\nStderr: %s", stdout, stderr)
		}

		// Verify the file content remains unchanged
		finalSecrets, err := readAndDecryptFile(secretFilePath, testPassword)
		if err != nil {
			t.Fatalf("Failed to read and decrypt file after quit: %v", err)
		}

		if len(finalSecrets) != len(initialSecrets) {
			t.Errorf("File content changed unexpectedly. Expected %d secrets, Got %d.", len(initialSecrets), len(finalSecrets))
		}
		if finalSecrets[key1] != value1 { // Should remain original if input was invalid
			t.Errorf("Secret '%s' was unexpectedly modified. Expected '%s', Got '%s'", key1, value1, finalSecrets[key1])
		}
		os.Remove(secretFilePath)
	})

	// 3. Test incorrect password
	t.Run("EditIncorrectPassword", func(t *testing.T) {
		initialSecrets := map[string]string{key1: value1}
		createEncryptedFile(secretFilePath, testPassword, initialSecrets)

		_, stderr, err := runCLI(t, []string{"edit", secretFilePath, "-p", "wrongPassword"}, "", tempDir)
		if err == nil {
			t.Fatalf("edit command succeeded but was expected to fail due to incorrect password.")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() == 0 {
			t.Errorf("Expected non-zero exit code, actual: %v", err)
		}
		expectedErrorMsg := fmt.Sprintf("Error: Cannot decrypt key '%s', please check if password is correct or file is corrupted:", key1)
		if !strings.Contains(stderr, expectedErrorMsg) {
			t.Errorf("Expected error message containing '%s' not found in stderr.\nStderr: %s", expectedErrorMsg, stderr)
		}
		os.Remove(secretFilePath)
	})

	// 4. Test file not found
	t.Run("EditFileNotFound", func(t *testing.T) {
		nonExistentFile := filepath.Join(tempDir, "nonexistent-edit.json")
		_, stderr, err := runCLI(t, []string{"edit", nonExistentFile, "-p", testPassword}, "", tempDir)
		if err == nil {
			t.Fatalf("edit command succeeded but was expected to fail for non-existent file.")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() == 0 {
			t.Errorf("Expected non-zero exit code, actual: %v", err)
		}
		expectedErrorMsg := "Secret file hash verification failed, file may have been tampered with or password is incorrect."
		if !strings.Contains(stderr, expectedErrorMsg) {
			t.Errorf("Expected error message containing '%s' not found in stderr.\nStderr: %s", expectedErrorMsg, stderr)
		}
	})

	// 5. Test invalid input format during interactive session
	t.Run("EditInvalidInputFormat", func(t *testing.T) {
		initialSecrets := map[string]string{key1: value1}
		createEncryptedFile(secretFilePath, testPassword, initialSecrets)

		// Simulate user input: invalid format, then save
		input := fmt.Sprintf(`invalid input
%s = "value"
%s: value_without_quotes
/save
`, key1, key2)

		stdout, stderr, err := runCLI(t, []string{"edit", secretFilePath, "-p", testPassword}, input, tempDir)
		if err != nil {
			t.Fatalf("edit command failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
		}

		if !strings.Contains(stdout, "Invalid input format. Please use 'key: \"value\"' or commands.") ||
			!strings.Contains(stdout, "Value must be enclosed in double quotes, e.g.: 'key: \"value\"'.") ||
			!strings.Contains(stdout, fmt.Sprintf("Secret file '%s' successfully updated.", secretFilePath)) {
			t.Errorf("Edit command output missing expected error messages or success message.\nStdout: %s\nStderr: %s", stdout, stderr)
		}

		// Verify that only valid changes were saved (if any)
		finalSecrets, err := readAndDecryptFile(secretFilePath, testPassword)
		if err != nil {
			t.Fatalf("Failed to read and decrypt file after invalid input: %v", err)
		}
		if finalSecrets[key1] != value1 { // Should remain original if input was invalid
			t.Errorf("Secret '%s' was unexpectedly modified. Expected '%s', Got '%s'", key1, value1, finalSecrets[key1])
		}
		if _, exists := finalSecrets[key2]; exists {
			t.Errorf("Key '%s' should not have been added with invalid input.", key2)
		}
		os.Remove(secretFilePath)
	})

	// 6. Test editing an empty file, adding secrets, and saving
	t.Run("EditEmptyFile_AddSave", func(t *testing.T) {
		// Create an empty secrets file using init command
		initPassword := "emptyeditpass"
		initFilePath := filepath.Join(tempDir, "empty-edit.json")
		_, initStderr, initErr := runCLI(t, []string{"init", initFilePath, "-p", initPassword}, "", tempDir)
		if initErr != nil {
			t.Fatalf("Failed to init empty secrets file for test setup: %v\nStderr: %s", initErr, initStderr)
		}

		// Simulate user input: add two new secrets, then save
		input := fmt.Sprintf(`%s: "%s"
%s: "%s"
/save
`, key1, value1, key2, value2)

		stdout, stderr, err := runCLI(t, []string{"edit", initFilePath, "-p", initPassword}, input, tempDir)
		if err != nil {
			t.Fatalf("edit command failed for empty file: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
		}

		expectedOutputs := []string{
			"(No secrets)", // Should show no secrets initially
			key1, // Just check that EDIT_KEY_1 appears somewhere in output
			key2, // Just check that EDIT_KEY_2 appears somewhere in output  
			"Saving changes...",
			"successfully updated",
		}

		for _, msg := range expectedOutputs {
			if !strings.Contains(stdout, msg) {
				t.Errorf("Edit empty file output missing expected message: '%s'.\nStdout: %s\nStderr: %s", msg, stdout, stderr)
			}
		}

		// Verify the file content after saving
		finalSecrets, err := readAndDecryptFile(initFilePath, initPassword)
		if err != nil {
			t.Fatalf("Failed to read and decrypt file after empty edit: %v", err)
		}

		expectedSecrets := map[string]string{
			key1: value1,
			key2: value2,
		}

		if len(finalSecrets) != len(expectedSecrets) {
			t.Errorf("Final secrets count mismatch. Expected %d, Got %d. Final: %v", len(expectedSecrets), len(finalSecrets), finalSecrets)
		}
		for k, v := range expectedSecrets {
			if finalSecrets[k] != v {
				t.Errorf("Final secret mismatch for key '%s'. Expected '%s', Got '%s'", k, v, finalSecrets[k])
			}
		}
		os.Remove(initFilePath)
	})
}