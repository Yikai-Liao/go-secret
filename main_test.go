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
	"go-secret/internal/file"   // 导入 internal/file 包以访问 SecretFile 结构和常量
)

// runCLI 辅助函数用于编译并执行 go-secret CLI命令
// 返回标准输出、标准错误和错误
func runCLI(t *testing.T, args []string, stdinInput string, tempDir string) (string, string, error) {
	// 确保在临时目录中执行命令
	originalCwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("获取当前工作目录失败: %v", err)
	}
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("切换到临时目录失败: %v", err)
	}
	defer os.Chdir(originalCwd) // 确保测试结束后切换回原始目录

	// 编译 go-secret
	cmd := exec.Command("go", "build", "-o", "go-secret", originalCwd)
	cmd.Dir = originalCwd // 编译命令在项目根目录执行
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("编译 go-secret 失败: %v\n%s", err, output)
	}

	// 构建 CLI 命令
	cliCmd := exec.Command(filepath.Join(originalCwd, "go-secret"), args...)

	// 模拟标准输入
	if stdinInput != "" {
		cliCmd.Stdin = strings.NewReader(stdinInput)
	}

	var stdout, stderr bytes.Buffer
	cliCmd.Stdout = &stdout
	cliCmd.Stderr = &stderr

	err = cliCmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// 如果是 ExitError，表示程序以非零状态码退出
			return stdout.String(), stderr.String(), exitErr
		}
		// 其他类型的错误
		return stdout.String(), stderr.String(), err
	}

	return stdout.String(), stderr.String(), nil
}

// TestInitCommand 测试 init 命令
func TestInitCommand(t *testing.T) {
	// 创建临时目录
	tempDir, err := ioutil.TempDir("", "go-secret-test-init-*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tempDir) // 确保测试结束后清理临时目录

	defaultFilePath := filepath.Join(tempDir, "go-secret.json")
	customFilePath := filepath.Join(tempDir, "my-secrets.json")
	testPassword := "testpassword"

	// 1. 测试正常初始化 (无文件参数，生成随机密码)
	t.Run("InitDefaultFileWithRandomPassword", func(t *testing.T) {
		stdout, stderr, err := runCLI(t, []string{"init"}, "", tempDir)
		if err != nil {
			t.Fatalf("init 命令失败: %v\nStderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, "已生成随机密码。请务必妥善保管此密码：") ||
			!strings.Contains(stdout, "密码: ") ||
			!strings.Contains(stdout, fmt.Sprintf("秘密文件 '%s' 已成功初始化。", filepath.Base(defaultFilePath))) {
			t.Errorf("init 命令输出不正确。\nStdout: %s\nStderr: %s", stdout, stderr)
		}
		if _, err := os.Stat(defaultFilePath); os.IsNotExist(err) {
			t.Errorf("默认秘密文件未创建: %s", defaultFilePath)
		}
		sf, err := file.ReadSecretFile(defaultFilePath)
		if err != nil {
			t.Errorf("读取初始化文件失败: %v", err)
		}
		if sf.Hash == "" {
			t.Errorf("初始化文件中的哈希字段为空。")
		}
		os.Remove(defaultFilePath)
	})

	// 2. 测试正常初始化 (带文件参数和密码)
	t.Run("InitCustomFileWithPassword", func(t *testing.T) {
		stdout, stderr, err := runCLI(t, []string{"init", customFilePath, "-p", testPassword}, "", tempDir)
		if err != nil {
			t.Fatalf("init 命令失败: %v\nStderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, fmt.Sprintf("秘密文件 '%s' 已成功初始化。", customFilePath)) {
			t.Errorf("init 命令输出不正确。\nStdout: %s\nStderr: %s", stdout, stderr)
		}
		if _, err := os.Stat(customFilePath); os.IsNotExist(err) {
			t.Errorf("自定义秘密文件未创建: %s", customFilePath)
		}
		os.Remove(customFilePath)
	})

	// 3. 测试文件已存在，不强制覆盖，用户选择不覆盖
	t.Run("InitFileExistsNoForceNoOverwrite", func(t *testing.T) {
		originalContent := `{"old":"value"}`
		ioutil.WriteFile(defaultFilePath, []byte(originalContent), 0644)

		stdout, stderr, err := runCLI(t, []string{"init"}, "n\n", tempDir)
		if err != nil {
			t.Fatalf("init 命令失败: %v\nStderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, fmt.Sprintf("秘密文件 '%s' 已存在。是否覆盖？(y/N):", filepath.Base(defaultFilePath))) ||
			!strings.Contains(stdout, "初始化已取消。") {
			t.Errorf("init 命令输出不正确。\nStdout: %s\nStderr: %s", stdout, stderr)
		}
		content, _ := ioutil.ReadFile(defaultFilePath)
		if string(content) != originalContent {
			t.Errorf("文件被意外修改。\n期望: %s\n实际: %s", originalContent, string(content))
		}
		os.Remove(defaultFilePath)
	})

	// 4. 测试文件已存在，不强制覆盖，用户选择覆盖
	t.Run("InitFileExistsNoForceOverwrite", func(t *testing.T) {
		ioutil.WriteFile(defaultFilePath, []byte(`{"old":"value"}`), 0644)

		stdout, stderr, err := runCLI(t, []string{"init"}, "y\n", tempDir)
		if err != nil {
			t.Fatalf("init 命令失败: %v\nStderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, fmt.Sprintf("秘密文件 '%s' 已存在。是否覆盖？(y/N):", filepath.Base(defaultFilePath))) ||
			!strings.Contains(stdout, "已生成随机密码。请务必妥善保管此密码：") ||
			!strings.Contains(stdout, "密码: ") ||
			!strings.Contains(stdout, fmt.Sprintf("秘密文件 '%s' 已成功初始化。", filepath.Base(defaultFilePath))) {
			t.Errorf("init 命令输出不正确。\nStdout: %s\nStderr: %s", stdout, stderr)
		}
		sf, err := file.ReadSecretFile(defaultFilePath)
		if err != nil {
			t.Errorf("读取初始化文件失败: %v", err)
		}
		if len(sf.Secrets) != 0 || sf.Hash == "" {
			t.Errorf("文件未被正确覆盖或内容不正确。")
		}
		os.Remove(defaultFilePath)
	})

	// 5. 测试文件已存在，强制覆盖
	t.Run("InitFileExistsForceOverwrite", func(t *testing.T) {
		ioutil.WriteFile(defaultFilePath, []byte(`{"old":"value"}`), 0644)

		stdout, stderr, err := runCLI(t, []string{"init", "-F"}, "", tempDir)
		if err != nil {
			t.Fatalf("init 命令失败: %v\nStderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, "已生成随机密码。请务必妥善保管此密码：") ||
			!strings.Contains(stdout, "密码: ") ||
			!strings.Contains(stdout, fmt.Sprintf("秘密文件 '%s' 已成功初始化。", filepath.Base(defaultFilePath))) ||
			strings.Contains(stdout, "是否覆盖？") {
			t.Errorf("init 命令输出不正确。\nStdout: %s\nStderr: %s", stdout, stderr)
		}
		sf, err := file.ReadSecretFile(defaultFilePath)
		if err != nil {
			t.Errorf("读取初始化文件失败: %v", err)
		}
		if len(sf.Secrets) != 0 || sf.Hash == "" {
			t.Errorf("文件未被正确覆盖或内容不正确。")
		}
		os.Remove(defaultFilePath)
	})

	// 6. 测试密码未提供 (当指定文件时)
	t.Run("InitMissingPasswordForCustomFile", func(t *testing.T) {
		stdout, stderr, err := runCLI(t, []string{"init", customFilePath}, "", tempDir)
		if err == nil {
			t.Errorf("init command succeeded but was expected to fail due to missing password.")
		}
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 1 {
			t.Errorf("Expected exit code 1, actual: %v", err)
		}
		if !strings.Contains(stderr, "当指定文件时，必须通过 -p 或 --password 标志提供密码。") {
			t.Errorf("init command stderr output incorrect.\nStdout: %s\nStderr: %s", stdout, stderr)
		}
		if _, err := os.Stat(customFilePath); !os.IsNotExist(err) {
			t.Errorf("File should not have been created, but it exists: %s", customFilePath)
		}
	})

	// 7. 测试写入文件失败 (模拟权限问题)
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
		if !strings.Contains(stderr, fmt.Sprintf("Error: 创建秘密文件 '%s' 失败:", readOnlyFilePath)) {
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

		if !strings.Contains(stdout, fmt.Sprintf("正在从 '%s' 设置环境变量...", secretFilePath)) {
			t.Errorf("Expected setup message not found in stdout.\nStdout: %s", stdout)
		}
		if !strings.Contains(stdout, fmt.Sprintf("已设置环境变量: %s", key1)) {
			t.Errorf("Expected set message for %s not found in stdout.\nStdout: %s", key1, stdout)
		}
		if !strings.Contains(stdout, fmt.Sprintf("已设置环境变量: %s", key2)) {
			t.Errorf("Expected set message for %s not found in stdout.\nStdout: %s", key2, stdout)
		}
		if !strings.Contains(stdout, "环境变量设置完成。") {
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
		expectedErrorMsg := "秘密文件哈希校验失败"
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
		expectedErrorMsg := "秘密文件哈希校验失败，且一个或多个秘密解密失败"
		if !strings.Contains(stderr, expectedErrorMsg) {
			t.Errorf("Expected error message containing '%s' not found in stderr.\nStderr: %s", expectedErrorMsg, stderr)
		}
		expectedWarning := fmt.Sprintf("警告: 无法解密键 '%s'", key1)
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
		expectedErrorMsg := "秘密文件哈希校验失败"
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
		expectedErrorMsg := "JSON文件包含嵌套对象，不支持"
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
		if !strings.Contains(stdout, "# 请在您的shell中执行以下命令以取消设置环境变量：") {
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
		expectedErrorMsg := "秘密文件哈希校验失败"
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

		expectedErrorMsg := "秘密文件哈希校验失败，且一个或多个秘密解密失败"
		if !strings.Contains(stderr, expectedErrorMsg) {
			t.Errorf("Expected error message containing '%s' not found in stderr.\nStderr: %s", expectedErrorMsg, stderr)
		}
		expectedWarning := fmt.Sprintf("警告: 无法解密键 '%s'", key1)
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
		expectedErrorMsg := "秘密文件哈希校验失败"
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

		if !strings.Contains(stdout, fmt.Sprintf("秘密已成功导出到JSON文件 '%s'。", outputJsonPath)) {
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

		if !strings.Contains(stdout, fmt.Sprintf("秘密已成功导出到.env文件 '%s'。", outputEnvPath)) {
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
		expectedErrorMsg := "秘密文件哈希校验失败，文件可能已被篡改或密码不正确。"
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
		expectedErrorMsg := fmt.Sprintf("Error: 无法解密键 '%s': GCM解密失败: cipher: message authentication failed", key1)
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
		expectedErrorMsg := "秘密文件哈希校验失败，文件可能已被篡改或密码不正确。"
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
		expectedErrorMsg := "Error: 不支持的输出文件格式。输出文件必须以 '.json' 或 '.env' 结尾。"
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

		if !strings.Contains(stdout, fmt.Sprintf("秘密已成功导出到JSON文件 '%s'。", outputJsonPath)) {
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

		if !strings.Contains(stdout, fmt.Sprintf("秘密已成功从非加密文件 '%s' 导入并加密到 '%s'。", plainInputPath, encryptedOutputPath)) {
			t.Errorf("Expected success message not found in stdout.\nStdout: %s", stdout)
		}

		// Verify output encrypted file content
		sf, err := file.ReadSecretFile(encryptedOutputPath)
		if err != nil {
			t.Fatalf("Failed to read encrypted output file: %v", err)
		}

		// Decrypt and verify
		decryptedSecrets := make(map[string]string)
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
		expectedErrorMsg := fmt.Sprintf("Error: 无法读取输入文件 '%s':", nonExistentFile)
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
		expectedErrorMsg := "Error: 必须通过 -p 或 --password 标志提供密码。"
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
		expectedErrorMsg := fmt.Sprintf("Error: 解析输入JSON文件 '%s' 失败:", malformedJSONPath)
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
		expectedErrorMsg := fmt.Sprintf("Error: 输入JSON文件 '%s' 包含嵌套对象，不支持导入。", nestedJSONPath)
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
		expectedErrorMsg := fmt.Sprintf("Error: 输入JSON文件 '%s' 包含嵌套数组，不支持导入。", nestedArrayPath)
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
		expectedErrorMsg := fmt.Sprintf("Error: 输入JSON文件 '%s' 中键 'number_key' 的值不是字符串类型。", nonStringValuePath)
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
		expectedErrorMsg := fmt.Sprintf("Error: 写入输出秘密文件 '%s' 失败:", readOnlyOutputPath)
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

		// Check for key messages, allowing for interactive prompts in between
		expectedOutputs := []string{
			"进入交互式编辑模式。",
			fmt.Sprintf("输入命令或键值对: 已更新/添加秘密: %s: \"%s\"", key3, value3),
			fmt.Sprintf("输入命令或键值对: 已更新/添加秘密: %s: \"%s\"", key1, "modified_value_1"),
			fmt.Sprintf("输入命令或键值对: 已删除键 '%s'。", key2),
			"输入命令或键值对: 正在保存更改...",
			fmt.Sprintf("秘密文件 '%s' 已成功更新。", secretFilePath),
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

		if !strings.Contains(stdout, "进入交互式编辑模式。") ||
			!strings.Contains(stdout, "退出编辑模式，未保存更改。") {
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
		expectedErrorMsg := fmt.Sprintf("Error: 无法解密键 '%s'，请检查密码是否正确或文件是否损坏: GCM解密失败: cipher: message authentication failed", key1)
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
		expectedErrorMsg := "秘密文件哈希校验失败，文件可能已被篡改或密码不正确。"
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

		if !strings.Contains(stdout, "无效输入格式。请使用 'key: \"value\"' 或命令。") ||
			!strings.Contains(stdout, "值必须用双引号括起来，例如: 'key: \"value\"'。") ||
			!strings.Contains(stdout, fmt.Sprintf("秘密文件 '%s' 已成功更新。", secretFilePath)) {
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
			"（无秘密）", // Should show no secrets initially
			fmt.Sprintf("输入命令或键值对: 已更新/添加秘密: %s: \"%s\"", key1, value1),
			fmt.Sprintf("输入命令或键值对: 已更新/添加秘密: %s: \"%s\"", key2, value2),
			"输入命令或键值对: 正在保存更改...",
			fmt.Sprintf("秘密文件 '%s' 已成功更新。", initFilePath),
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
