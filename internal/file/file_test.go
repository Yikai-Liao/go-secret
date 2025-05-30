package file

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCalculateSecretsHash(t *testing.T) {
	secrets1 := map[string]string{
		"key1": "value1",
		"key2": "value2",
	}
	secrets2 := map[string]string{
		"key2": "value2",
		"key1": "value1", // different order
	}
	secrets3 := map[string]string{
		"key1": "value1",
		"key2": "newValue",
	}
	emptySecrets := map[string]string{}

	hash1 := CalculateSecretsHash(secrets1)
	hash2 := CalculateSecretsHash(secrets2)
	hash3 := CalculateSecretsHash(secrets3)
	emptyHash := CalculateSecretsHash(emptySecrets)

	if hash1 != hash2 {
		t.Errorf("Hash calculation inconsistent for same content with different order.\nHash1: %s\nHash2: %s", hash1, hash2)
	}
	if hash1 == hash3 {
		t.Errorf("Hash calculation same for different content, expected different.")
	}
	if emptyHash == "" {
		t.Errorf("Hash for empty map should not be empty.")
	}
}

func TestVerifySecretsHash(t *testing.T) {
	secrets := map[string]string{
		"key1": "value1",
		"key2": "value2",
	}
	correctHash := CalculateSecretsHash(secrets)
	wrongHash := "wronghash"

	if !VerifySecretsHash(secrets, correctHash) {
		t.Errorf("Correct hash verification failed.")
	}
	if VerifySecretsHash(secrets, wrongHash) {
		t.Errorf("Wrong hash verification succeeded, expected failure.")
	}
}

func TestSecretFileMarshalUnmarshalJSON(t *testing.T) {
	// Normal case
	sf := SecretFile{
		Secrets: map[string]string{
			"key1": "value1",
			"key2": "value2",
		},
		Hash: "somehash",
	}

	data, err := json.Marshal(sf)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	var unmarshaledSf SecretFile
	err = json.Unmarshal(data, &unmarshaledSf)
	if err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	if unmarshaledSf.Hash != sf.Hash {
		t.Errorf("Unmarshaled hash doesn't match. Expected: %s, Actual: %s", sf.Hash, unmarshaledSf.Hash)
	}
	if len(unmarshaledSf.Secrets) != len(sf.Secrets) {
		t.Errorf("Unmarshaled secret count doesn't match. Expected: %d, Actual: %d", len(sf.Secrets), len(unmarshaledSf.Secrets))
	}
	for k, v := range sf.Secrets {
		if unmarshaledSf.Secrets[k] != v {
			t.Errorf("Unmarshaled secret value doesn't match. Key: %s, Expected: %s, Actual: %s", k, v, unmarshaledSf.Secrets[k])
		}
	}

	// Test without hash field should fail validation
	noHashJSON := `{"keyA": "valueA"}`
	var sfNoHashTest SecretFile
	err = json.Unmarshal([]byte(noHashJSON), &sfNoHashTest)
	if err == nil {
		t.Errorf("UnmarshalJSON without __hash__ field succeeded, expected failure.")
	}
	if !strings.Contains(err.Error(), "secret file is missing required '__hash__' field") {
		t.Errorf("Missing hash field error message incorrect: %v", err)
	}

	// Error case: nested object (with hash field)
	nestedJSON := `{"key": "value", "nested": {"subKey": "subValue"}, "__hash__": "hash123"}`
	var sfNested SecretFile
	err = json.Unmarshal([]byte(nestedJSON), &sfNested)
	if err == nil {
		t.Errorf("UnmarshalJSON succeeded with nested object, expected failure.")
	}
	if !strings.Contains(err.Error(), "nested objects are not supported") {
		t.Errorf("Nested object error message incorrect: %v", err)
	}

	// Error case: nested array (with hash field)
	arrayJSON := `{"key": "value", "array": ["item1", "item2"], "__hash__": "hash123"}`
	var sfArray SecretFile
	err = json.Unmarshal([]byte(arrayJSON), &sfArray)
	if err == nil {
		t.Errorf("UnmarshalJSON succeeded with nested array, expected failure.")
	}
	if !strings.Contains(err.Error(), "nested arrays are not supported") {
		t.Errorf("Nested array error message incorrect: %v", err)
	}

	// Error case: non-string value (with hash field)
	nonStringValueJSON := `{"key": 123, "__hash__": "hash123"}`
	var sfNonString SecretFile
	err = json.Unmarshal([]byte(nonStringValueJSON), &sfNonString)
	if err == nil {
		t.Errorf("UnmarshalJSON succeeded with non-string value, expected failure.")
	}
	if !strings.Contains(err.Error(), "must be a string") {
		t.Errorf("Non-string value error message incorrect: %v", err)
	}

	// Error case: __hash__ field not string
	hashNotStringJSON := `{"key": "value", "__hash__": 123}`
	var sfHashNotString SecretFile
	err = json.Unmarshal([]byte(hashNotStringJSON), &sfHashNotString)
	if err == nil {
		t.Errorf("UnmarshalJSON succeeded with non-string hash, expected failure.")
	}
	if !strings.Contains(err.Error(), "'__hash__' field must be a string") {
		t.Errorf("Non-string hash error message incorrect: %v", err)
	}
}

func TestReadWriteSecretFile(t *testing.T) {
	// Create temporary file
	tmpfile, err := ioutil.TempFile("", "secret_test_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name()) // Clean up after test
	tmpfile.Close()                 // Close file handle for subsequent writes

	filePath := tmpfile.Name()

	// Test write
	sfWrite := &SecretFile{
		Secrets: map[string]string{
			"testKey1": "testValue1",
			"testKey2": "testValue2",
		},
		Hash: "testHash",
	}
	err = WriteSecretFile(filePath, sfWrite)
	if err != nil {
		t.Fatalf("Failed to write secret file: %v", err)
	}

	// Verify written content
	readData, err := ioutil.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read written file: %v", err)
	}
	var rawMap map[string]string
	err = json.Unmarshal(readData, &rawMap)
	if err != nil {
		t.Fatalf("Failed to parse written file content: %v", err)
	}
	if rawMap["testKey1"] != "testValue1" || rawMap["testKey2"] != "testValue2" || rawMap[HashField] != "testHash" {
		t.Errorf("Written file content incorrect.")
	}

	// Test read
	sfRead, err := ReadSecretFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read secret file: %v", err)
	}
	if sfRead.Hash != sfWrite.Hash {
		t.Errorf("Read hash doesn't match. Expected: %s, Actual: %s", sfWrite.Hash, sfRead.Hash)
	}
	if len(sfRead.Secrets) != len(sfWrite.Secrets) {
		t.Errorf("Read secret count doesn't match. Expected: %d, Actual: %d", len(sfWrite.Secrets), len(sfRead.Secrets))
	}
	for k, v := range sfWrite.Secrets {
		if sfRead.Secrets[k] != v {
			t.Errorf("Read secret value doesn't match. Key: %s, Expected: %s, Actual: %s", k, v, sfRead.Secrets[k])
		}
	}

	// Test read non-existent file
	nonExistentPath := filepath.Join(os.TempDir(), "non_existent_secret_file.json")
	sfNonExistent, err := ReadSecretFile(nonExistentPath)
	if err != nil {
		t.Fatalf("Error reading non-existent file, expected empty SecretFile: %v", err)
	}
	if sfNonExistent == nil || len(sfNonExistent.Secrets) != 0 || sfNonExistent.Hash != "" {
		t.Errorf("Non-existent file didn't return empty SecretFile.")
	}

	// Test read invalid JSON file
	invalidJSONPath := filepath.Join(os.TempDir(), "invalid_json_file.json")
	err = ioutil.WriteFile(invalidJSONPath, []byte(`{"key": "value", "nested": {"subKey": "subValue"}}`), 0644)
	if err != nil {
		t.Fatalf("Failed to write invalid JSON file: %v", err)
	}
	defer os.Remove(invalidJSONPath)

	_, err = ReadSecretFile(invalidJSONPath)
	if err == nil {
		t.Errorf("Read invalid JSON succeeded, expected failure.")
	}
	if !strings.Contains(err.Error(), "secret file is missing required '__hash__' field") {
		t.Errorf("Invalid JSON error message incorrect: %v", err)
	}

	// Test write failure (simulate permission issue)
	readOnlyDir := filepath.Join(os.TempDir(), "readonly_test_dir")
	os.Mkdir(readOnlyDir, 0444) // Create read-only directory
	defer os.RemoveAll(readOnlyDir)

	readOnlyFilePath := filepath.Join(readOnlyDir, "test.json")
	err = WriteSecretFile(readOnlyFilePath, sfWrite)
	if err == nil {
		t.Errorf("Write to read-only directory succeeded, expected failure.")
	}
	if !strings.Contains(err.Error(), "写入文件失败") {
		t.Errorf("Read-only directory error message incorrect: %v", err)
	}
}

// TestTransformations tests JSON-to-encrypted and encrypted-to-JSON transformations
func TestTransformations(t *testing.T) {
	// Mock encrypt/decrypt functions
	encryptFunc := func(s string) (string, error) {
		return "encrypted_" + s, nil
	}
	decryptFunc := func(s string) (string, error) {
		return strings.TrimPrefix(s, "encrypted_"), nil
	}

	// Test data
	jsonData := []byte(`{
		"key1": "value1",
		"key2": "value2",
		"key3": "value3"
	}`)

	// Transform JSON to encrypted
	encrypted, hash, err := TransformJSONToEncrypted(jsonData, encryptFunc)
	if err != nil {
		t.Fatalf("TransformJSONToEncrypted failed: %v", err)
	}

	// Verify encrypted data
	if len(encrypted) != 3 {
		t.Errorf("Expected 3 encrypted keys, got %d", len(encrypted))
	}
	for _, v := range encrypted {
		if !strings.HasPrefix(v, "encrypted_") {
			t.Errorf("Encrypted value doesn't have expected prefix: %s", v)
		}
	}

	// Transform encrypted to JSON
	decrypted, err := TransformEncryptedToJSON(encrypted, decryptFunc)
	if err != nil {
		t.Fatalf("TransformEncryptedToJSON failed: %v", err)
	}

	// Verify decrypted data
	if len(decrypted) != 3 {
		t.Errorf("Expected 3 decrypted keys, got %d", len(decrypted))
	}
	for _, v := range decrypted {
		if strings.HasPrefix(v, "encrypted_") {
			t.Errorf("Decrypted value still has encrypted prefix: %s", v)
		}
	}

	// Verify hash matches
	recomputedHash := CalculateSecretsHash(decrypted)
	if recomputedHash != hash {
		t.Errorf("Recomputed hash doesn't match. Expected: %s, Actual: %s", hash, recomputedHash)
	}
}

// TestTransformJSONToEncryptedErrors tests error cases for TransformJSONToEncrypted
func TestTransformJSONToEncryptedErrors(t *testing.T) {
	// Invalid JSON
	_, _, err := TransformJSONToEncrypted([]byte(`{invalid}`), nil)
	if err == nil {
		t.Errorf("Expected error for invalid JSON")
	}

	// Encryption error
	encryptErr := func(s string) (string, error) {
		return "", fmt.Errorf("encryption failed")
	}
	_, _, err = TransformJSONToEncrypted([]byte(`{"key":"value"}`), encryptErr)
	if err == nil || !strings.Contains(err.Error(), "encryption failed for key") {
		t.Errorf("Expected encryption error, got: %v", err)
	}
}

// TestTransformEncryptedToJSONErrors tests error cases for TransformEncryptedToJSON
func TestTransformEncryptedToJSONErrors(t *testing.T) {
	// Decryption error
	decryptErr := func(s string) (string, error) {
		return "", fmt.Errorf("decryption failed")
	}
	_, err := TransformEncryptedToJSON(map[string]string{"key": "value"}, decryptErr)
	if err == nil || !strings.Contains(err.Error(), "decryption failed for key") {
		t.Errorf("Expected decryption error, got: %v", err)
	}
}

// TestSecretFileMarshalJSONNoHash tests marshaling without hash field
func TestSecretFileMarshalJSONNoHash(t *testing.T) {
	// Test marshaling SecretFile without hash field
	sf := SecretFile{
		Secrets: map[string]string{
			"key1": "value1",
			"key2": "value2",
		},
		Hash: "", // Empty hash should not be included in JSON
	}

	data, err := json.Marshal(sf)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	// Verify that __hash__ field is not in the JSON
	if strings.Contains(string(data), HashField) {
		t.Errorf("MarshalJSON included empty hash field, should be omitted")
	}
}

// TestReadSecretFileVariousErrors tests various error scenarios
func TestReadSecretFileVariousErrors(t *testing.T) {
	// Test reading file with read permission error
	tmpfile, err := ioutil.TempFile("", "secret_test_readonly_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())

	// Write valid content first
	validContent := `{"key1": "value1", "__hash__": "hash123"}`
	err = ioutil.WriteFile(tmpfile.Name(), []byte(validContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write valid content: %v", err)
	}

	// Change permissions to make file unreadable
	err = os.Chmod(tmpfile.Name(), 0000)
	if err != nil {
		t.Fatalf("Failed to change file permissions: %v", err)
	}
	defer os.Chmod(tmpfile.Name(), 0644) // Restore permissions for cleanup

	_, err = ReadSecretFile(tmpfile.Name())
	if err == nil {
		t.Errorf("ReadSecretFile succeeded on unreadable file, expected failure")
	}
	if !strings.Contains(err.Error(), "读取文件失败") {
		t.Errorf("Unreadable file error message incorrect: %v", err)
	}
}

// TestWriteSecretFileDirectoryNotExists tests writing to non-existent directory
func TestWriteSecretFileDirectoryNotExists(t *testing.T) {
	sf := &SecretFile{
		Secrets: map[string]string{"key": "value"},
		Hash:    "hash123",
	}

	nonExistentPath := filepath.Join(os.TempDir(), "non_existent_dir", "test.json")
	err := WriteSecretFile(nonExistentPath, sf)
	if err == nil {
		t.Errorf("WriteSecretFile succeeded for non-existent directory, expected failure")
		os.Remove(nonExistentPath) // Cleanup if it somehow succeeded
	}
	if !strings.Contains(err.Error(), "写入文件失败") {
		t.Errorf("Non-existent directory error message incorrect: %v", err)
	}
}

// TestTransformJSONToEncryptedEdgeCases tests edge cases for transformation
func TestTransformJSONToEncryptedEdgeCases(t *testing.T) {
	encryptFunc := func(s string) (string, error) {
		return "encrypted_" + s, nil
	}

	// Test empty JSON object
	emptyJSON := []byte(`{}`)
	encrypted, hash, err := TransformJSONToEncrypted(emptyJSON, encryptFunc)
	if err != nil {
		t.Fatalf("TransformJSONToEncrypted failed for empty JSON: %v", err)
	}
	if len(encrypted) != 0 {
		t.Errorf("Expected empty encrypted map, got %d items", len(encrypted))
	}
	if hash == "" {
		t.Errorf("Hash should not be empty even for empty JSON")
	}

	// Test JSON with special characters
	specialJSON := []byte(`{"key with spaces": "value with\nnewlines", "unicode": "测试🔐"}`)
	encrypted, hash, err = TransformJSONToEncrypted(specialJSON, encryptFunc)
	if err != nil {
		t.Fatalf("TransformJSONToEncrypted failed for special characters: %v", err)
	}
	if len(encrypted) != 2 {
		t.Errorf("Expected 2 encrypted keys, got %d", len(encrypted))
	}

	// Test JSON with nested objects (should fail)
	nestedJSON := []byte(`{"key": "value", "nested": {"subkey": "subvalue"}}`)
	_, _, err = TransformJSONToEncrypted(nestedJSON, encryptFunc)
	if err == nil {
		t.Errorf("Expected error for nested JSON")
	}
	if !strings.Contains(err.Error(), "cannot unmarshal object") {
		t.Errorf("Nested object error message incorrect: %v", err)
	}

	// Test JSON with arrays (should fail)
	arrayJSON := []byte(`{"key": "value", "array": ["item1", "item2"]}`)
	_, _, err = TransformJSONToEncrypted(arrayJSON, encryptFunc)
	if err == nil {
		t.Errorf("Expected error for array JSON")
	}
	if !strings.Contains(err.Error(), "cannot unmarshal array") {
		t.Errorf("Array error message incorrect: %v", err)
	}

	// Test JSON with non-string values (should fail)
	nonStringJSON := []byte(`{"key": "value", "number": 123}`)
	_, _, err = TransformJSONToEncrypted(nonStringJSON, encryptFunc)
	if err == nil {
		t.Errorf("Expected error for non-string JSON")
	}
	if !strings.Contains(err.Error(), "cannot unmarshal number") {
		t.Errorf("Non-string error message incorrect: %v", err)
	}
}

// TestTransformEncryptedToJSONEdgeCases tests edge cases for decryption transformation
func TestTransformEncryptedToJSONEdgeCases(t *testing.T) {
	decryptFunc := func(s string) (string, error) {
		return strings.TrimPrefix(s, "encrypted_"), nil
	}

	// Test empty encrypted map
	emptyEncrypted := map[string]string{}
	decrypted, err := TransformEncryptedToJSON(emptyEncrypted, decryptFunc)
	if err != nil {
		t.Fatalf("TransformEncryptedToJSON failed for empty map: %v", err)
	}
	if len(decrypted) != 0 {
		t.Errorf("Expected empty decrypted map, got %d items", len(decrypted))
	}

	// Test encrypted map with many items
	manyEncrypted := make(map[string]string)
	for i := 0; i < 100; i++ {
		key := fmt.Sprintf("key%d", i)
		value := fmt.Sprintf("encrypted_value%d", i)
		manyEncrypted[key] = value
	}
	
	decrypted, err = TransformEncryptedToJSON(manyEncrypted, decryptFunc)
	if err != nil {
		t.Fatalf("TransformEncryptedToJSON failed for many items: %v", err)
	}
	if len(decrypted) != 100 {
		t.Errorf("Expected 100 decrypted items, got %d", len(decrypted))
	}
	
	// Verify all items were decrypted correctly
	for i := 0; i < 100; i++ {
		key := fmt.Sprintf("key%d", i)
		expectedValue := fmt.Sprintf("value%d", i)
		if decrypted[key] != expectedValue {
			t.Errorf("Decrypted value mismatch for key %s: expected %s, got %s", key, expectedValue, decrypted[key])
			break
		}
	}
}
