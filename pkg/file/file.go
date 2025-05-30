package file

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strings"
)

const HashField = "__hash__"

// CalculateSecretsHash calculates the overall hash of all key-value pairs after decryption
func CalculateSecretsHash(secrets map[string]string) string {
	var keys []string
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys) // Ensure consistent ordering

	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteString(":")
		sb.WriteString(secrets[k])
		sb.WriteString("\n")
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(sb.String())))
}

// VerifySecretsHash verifies if the decrypted data matches the stored __hash__ field
func VerifySecretsHash(secrets map[string]string, storedHash string) bool {
	calculatedHash := CalculateSecretsHash(secrets)
	return calculatedHash == storedHash
}

// SecretFile represents a JSON file structure containing secrets and hash
type SecretFile struct {
	Secrets map[string]string `json:"-"` // 忽略此字段的JSON编码/解码
	Hash    string            `json:"__hash__,omitempty"`
}

// MarshalJSON 自定义SecretFile的JSON编码
func (sf SecretFile) MarshalJSON() ([]byte, error) {
	// 创建一个临时map来包含所有秘密和哈希字段
	tempMap := make(map[string]string)
	for k, v := range sf.Secrets {
		tempMap[k] = v
	}
	if sf.Hash != "" {
		tempMap[HashField] = sf.Hash
	}
	return json.MarshalIndent(tempMap, "", "  ")
}

// UnmarshalJSON 自定义SecretFile的JSON解码
func (sf *SecretFile) UnmarshalJSON(data []byte) error {
	var rawMap map[string]interface{}
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Validate file structure
	if err := validateSecretFile(rawMap); err != nil {
		return err
	}

	sf.Secrets = make(map[string]string)
	for k, v := range rawMap {
		if k == HashField {
			sf.Hash = v.(string)
			continue
		}
		sf.Secrets[k] = v.(string)
	}
	return nil
}

// validateSecretFile checks the structure of the secret file
func validateSecretFile(rawMap map[string]interface{}) error {
	// Check for __hash__ field
	if _, exists := rawMap[HashField]; !exists {
		return fmt.Errorf("secret file is missing required '%s' field", HashField)
	}

	// Check for flat structure and valid types
	for k, v := range rawMap {
		if k == HashField {
			if _, ok := v.(string); !ok {
				return fmt.Errorf("'%s' field must be a string", HashField)
			}
			continue
		}

		// Check for nested structures
		if _, isMap := v.(map[string]interface{}); isMap {
			return fmt.Errorf("nested objects are not supported (found in key '%s')", k)
		}
		if _, isArray := v.([]interface{}); isArray {
			return fmt.Errorf("nested arrays are not supported (found in key '%s')", k)
		}

		// Check value type
		if _, ok := v.(string); !ok {
			return fmt.Errorf("value for key '%s' must be a string", k)
		}
	}
	return nil
}

// TransformJSONToEncrypted transforms plain JSON to encrypted format while preserving key order
func TransformJSONToEncrypted(jsonData []byte, encryptFunc func(string) (string, error)) (map[string]string, string, error) {
	var rawMap map[string]string
	if err := json.Unmarshal(jsonData, &rawMap); err != nil {
		return nil, "", fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Remove __hash__ field if present
	delete(rawMap, HashField)

	// Preserve original key order
	keys := make([]string, 0, len(rawMap))
	for k := range rawMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Encrypt values while preserving order
	encrypted := make(map[string]string)
	for _, k := range keys {
		encryptedValue, err := encryptFunc(rawMap[k])
		if err != nil {
			return nil, "", fmt.Errorf("encryption failed for key '%s': %w", k, err)
		}
		encrypted[k] = encryptedValue
	}

	// Compute hash of original values
	hash := CalculateSecretsHash(rawMap)

	return encrypted, hash, nil
}

// TransformEncryptedToJSON transforms encrypted data to plain JSON while preserving key order
func TransformEncryptedToJSON(encryptedData map[string]string, decryptFunc func(string) (string, error)) (map[string]string, error) {
	// Get keys in sorted order to preserve original order
	keys := make([]string, 0, len(encryptedData))
	for k := range encryptedData {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Decrypt values while preserving order
	decrypted := make(map[string]string)
	for _, k := range keys {
		decryptedValue, err := decryptFunc(encryptedData[k])
		if err != nil {
			return nil, fmt.Errorf("decryption failed for key '%s': %w", k, err)
		}
		decrypted[k] = decryptedValue
	}

	return decrypted, nil
}

// ReadSecretFile 从指定路径读取并解析JSON文件
func ReadSecretFile(path string) (*SecretFile, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &SecretFile{Secrets: make(map[string]string)}, nil // 文件不存在时返回空结构
		}
		return nil, fmt.Errorf("读取文件失败: %w", err)
	}

	var sf SecretFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("解析秘密文件失败: %w", err)
	}
	return &sf, nil
}

// WriteSecretFile 将SecretFile结构写入指定路径的JSON文件
func WriteSecretFile(path string, sf *SecretFile) error {
	data, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化秘密文件失败: %w", err)
	}

	if err := ioutil.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("写入文件失败: %w", err)
	}
	return nil
}
