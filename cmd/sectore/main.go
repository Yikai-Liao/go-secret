package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/Yikai-Liao/sectore/pkg/crypto"
	"github.com/Yikai-Liao/sectore/pkg/file"

	"github.com/spf13/cobra"
)

var (
	secretFilePath string
	password       string
	forceOverwrite bool // New: force overwrite flag
	passwordBytes  []byte // New: for secure password handling
)

var rootCmd = &cobra.Command{
	Use:   "sectore",
	Short: "sectore is a secure CLI tool for managing encrypted key-value pairs", 
	Long: `sectore is a powerful CLI tool for securely storing, retrieving, and managing encrypted key-value pairs.
It provides enterprise-grade encryption for environment variables and configuration secrets with integrity verification.`,
	RunE: func(cmd *cobra.Command, args []string) error {
	// Default behavior: show help
	cmd.Help()
	return nil
},
}

var setCmd = &cobra.Command{
	Use:   "set [file]",
	Short: "Set environment variables from encrypted file",
	Long:  `The set command reads an encrypted JSON file, decrypts its contents, and sets its key-value pairs as environment variables for the current session.`,
	Args:  cobra.ExactArgs(1), // Only need one file path argument
 	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0] // Get file path

		sf, err := file.ReadSecretFile(filePath) // Read specified file
		if err != nil {
			return fmt.Errorf("failed to read secret file '%s': %w", filePath, err)
		}

		// Decrypt secrets first for hash verification
		decryptedSecrets := make(map[string]string)
		anyDecryptionFailed := false
		for k, encryptedValue := range sf.Secrets {
			if k == file.HashField { // Ensure we use the constant
				continue
			}
			passwordBytes := []byte(password)
			defer func() {
				for i := range passwordBytes {
					passwordBytes[i] = 0
				}
			}()
			decryptedValue, err := crypto.Decrypt(encryptedValue, passwordBytes)
			if err != nil {
				// If any key fails to decrypt with the given password, the hash check will likely fail
				// or the user has the wrong password.
				fmt.Fprintf(os.Stderr, "Warning: Cannot decrypt key '%s' (possible password error or data corruption): %v\n", k, err)
				anyDecryptionFailed = true
				// We can't put this decrypted value in the map, so skip it.
				// The hash verification will be based on successfully decrypted secrets.
				// Or, we can decide that if any decryption fails, the whole operation fails.
				// For 'set', perhaps it's better to be strict. If a key can't be decrypted, it's an issue.
				// However, the original logic was to warn and continue.
				// Let's stick to original intent for now: warn and continue for individual keys,
				// but the hash check will use what was *successfully* decrypted.
				// This means if password is wrong, decryptedSecrets will be empty or partial.
				decryptedSecrets[k] = "" // Or some placeholder, or skip
				continue // Skip adding this key if decryption fails
			}
			decryptedSecrets[k] = decryptedValue
		}

		// Verify hash against the (successfully) decrypted secrets
		// If the password was wrong, decryptedSecrets might be empty or incomplete,
		// leading to a hash mismatch if the original file was not empty.
		if !file.VerifySecretsHash(decryptedSecrets, sf.Hash) {
			// If any decryption failed, this message might be more accurate
			if anyDecryptionFailed {
				return fmt.Errorf("Secret file hash verification failed, and one or more secrets decryption failed (possible password error or file tampering).")
			}
			return fmt.Errorf("Secret file hash verification failed, file may have been tampered with.")
		}
		
		// If all decryptions failed due to wrong password, and original secrets map was empty, hash could still pass.
		// This case needs careful thought. If sf.Secrets was empty to begin with (e.g. init file),
		// decryptedSecrets would be empty, and CalculateSecretsHash on empty map would match sf.Hash.
		// If sf.Secrets was NOT empty, but all decryptions failed, decryptedSecrets would be empty.
		// CalculateSecretsHash(empty) would NOT match sf.Hash (which was based on non-empty original data).
		// So the hash check *should* catch wrong password if there was data.

		fmt.Printf("Setting environment variables from '%s'...\n", filePath)
		// Iterate over successfully decrypted secrets to set them
		for k, decryptedValue := range decryptedSecrets {
			// We already handled decryption errors above.
			// If a key is in decryptedSecrets, it means it was successfully decrypted.
			os.Setenv(k, decryptedValue)
			fmt.Printf("Environment variable set: %s\n", k)
		}
		if len(decryptedSecrets) == 0 && len(sf.Secrets) > 0 && !anyDecryptionFailed {
			// This case implies sf.Secrets had entries but none were added to decryptedSecrets,
			// which shouldn't happen if anyDecryptionFailed is false.
			// This might indicate an issue if sf.Secrets only contained __hash__.
		} else if anyDecryptionFailed && len(decryptedSecrets) == 0 && len(sf.Secrets) > 0 {
		           fmt.Fprintln(os.Stderr, "Warning: No environment variables set due to all secrets decryption failures. Please check password.")
		      }

		fmt.Println("Environment variables setup completed. These variables are only valid for the current session.")
		return nil
	},
}

var unsetCmd = &cobra.Command{
	Use:   "unset [file]",
	Short: "Unset environment variables from encrypted file",
	Long:  `The unset command reads an encrypted JSON file, decrypts its contents, and provides shell commands to unset the corresponding environment variables.`,
	Args:  cobra.ExactArgs(1), // Only need one file path argument
 	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0] // Get file path

		sf, err := file.ReadSecretFile(filePath) // Read specified file
		if err != nil {
			return fmt.Errorf("failed to read secret file '%s': %w", filePath, err)
		}

		// Decrypt secrets first for hash verification
		decryptedSecrets := make(map[string]string)
		anyDecryptionFailed := false
		hasSecretsToProcess := false // To check if sf.Secrets had anything other than hash

		for k, encryptedValue := range sf.Secrets {
			if k == file.HashField {
				continue
			}
			hasSecretsToProcess = true
			passwordBytes := []byte(password)
			defer func() {
				for i := range passwordBytes {
					passwordBytes[i] = 0
				}
			}()
			decryptedValue, err := crypto.Decrypt(encryptedValue, passwordBytes)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Cannot decrypt key '%s' (possible password error or data corruption), will still attempt to generate unset command: %v\n", k, err)
				anyDecryptionFailed = true
				// For unset, we still want to list the key even if decryption fails.
				// We don't add it to decryptedSecrets for hash verification if decryption fails.
			} else {
				decryptedSecrets[k] = decryptedValue // Store successfully decrypted for hash check
			}
		}

		// Verify hash against the (successfully) decrypted secrets
		if !file.VerifySecretsHash(decryptedSecrets, sf.Hash) {
			if anyDecryptionFailed {
				return fmt.Errorf("Secret file hash verification failed, and one or more secrets decryption failed (possible password error or file tampering).")
			}
			return fmt.Errorf("Secret file hash verification failed, file may have been tampered with.")
		}

		fmt.Printf("Here are the commands to unset environment variables read from '%s':\n", filePath)
		fmt.Println("# Please execute the following commands in your shell to unset environment variables:")
		
		keysToList := make([]string, 0, len(sf.Secrets))
		for k := range sf.Secrets { // Iterate original keys from file
			if k == file.HashField {
				continue
			}
			keysToList = append(keysToList, k)
		}
		sort.Strings(keysToList) // Ensure consistent order

		for _, k := range keysToList {
			fmt.Printf("unset %s\n", k)
		}
		
		if !hasSecretsToProcess { // Check if there were any actual secrets (not just hash)
		          fmt.Println("(No secrets to unset)")
		      }

		fmt.Println("Please note: These commands need to be manually executed in the current shell session to take effect.")
		return nil
	},
}

var exportCmd = &cobra.Command{
	Use:   "export [input_file]",
	Short: "Export encrypted secrets to specified file",
	Long: `The export command reads an encrypted JSON file, decrypts its contents, and exports its key-value pairs to a specified output file.
Supports export to JSON format (removes __hash__ field) or .env format.`,
	Args: cobra.ExactArgs(1), // Only need one input file path argument
 	RunE: func(cmd *cobra.Command, args []string) error {
		inputFilePath := args[0]
		outputFilePath, _ := cmd.Flags().GetString("output")

		if outputFilePath == "" {
			return fmt.Errorf("Output file path must be specified (-o or --output).")
		}

		sf, err := file.ReadSecretFile(inputFilePath)
		if err != nil {
			return fmt.Errorf("Cannot read input secret file '%s': %w", inputFilePath, err)
		}

		decryptedSecrets := make(map[string]string)
		for k, encryptedValue := range sf.Secrets {
			if k == file.HashField { // Skip __hash__ field as it exists before decryption
				continue
			}
			passwordBytes := []byte(password)
			defer func() {
				for i := range passwordBytes {
					passwordBytes[i] = 0
				}
			}()
			decryptedValue, err := crypto.Decrypt(encryptedValue, passwordBytes)
			if err != nil {
				return fmt.Errorf("Cannot decrypt key '%s': %w", k, err) // Decryption failure is fatal error, stop export
			}
			decryptedSecrets[k] = decryptedValue
		}

		// Verify if decrypted data matches original hash
		if !file.VerifySecretsHash(decryptedSecrets, sf.Hash) {
			return fmt.Errorf("Secret file hash verification failed, file may have been tampered with or password is incorrect.")
		}

		// Determine export format based on output file extension
		if strings.HasSuffix(outputFilePath, ".json") {
			// Export as JSON
			outputSF := &file.SecretFile{Secrets: decryptedSecrets}
			// 注意：WriteSecretFile会自动处理__hash__字段的写入，但这里我们希望导出的是纯净的解密JSON，
			// 所以我们直接使用decryptedSecrets，并且不设置Hash字段，让MarshalJSON只导出Secrets。
			// SecretFile的MarshalJSON方法会检查sf.Hash是否为空，如果为空则不写入__hash__。
			outputSF.Hash = "" // 确保不写入__hash__字段

			if err := file.WriteSecretFile(outputFilePath, outputSF); err != nil {
				return fmt.Errorf("Failed to write output JSON file '%s': %w", outputFilePath, err)
			}
			fmt.Printf("Secrets successfully exported to JSON file '%s'.\n", outputFilePath)
		} else if strings.HasSuffix(outputFilePath, ".env") {
			// Export as .env
			var envContent strings.Builder
			var keys []string
			for k := range decryptedSecrets {
				keys = append(keys, k)
			}
			sort.Strings(keys) // Ensure consistent order

			for _, k := range keys {
				envContent.WriteString(fmt.Sprintf("%s=%s\n", k, decryptedSecrets[k]))
			}

			if err := os.WriteFile(outputFilePath, []byte(envContent.String()), 0644); err != nil {
				return fmt.Errorf("Failed to write output .env file '%s': %w", outputFilePath, err)
			}
			fmt.Printf("Secrets successfully exported to .env file '%s'.\n", outputFilePath)
		} else {
			return fmt.Errorf("Unsupported output file format. Output file must end with '.json' or '.env'.")
		}
		return nil
	},
}

var initCmd = &cobra.Command{
	Use:   "init [file]",
	Short: "Initialize secret storage",
	Long: `The init command initializes a new secret storage file.
If no file is specified, defaults to 'sectore.json' and generates a random password.
If a file is specified, a password must be provided via -p or --password flag.`,
	Args: cobra.MaximumNArgs(1), // At most one file path argument
 	RunE: func(cmd *cobra.Command, args []string) error {
		targetFilePath := "sectore.json" // 默认文件路径
		if len(args) > 0 {
			targetFilePath = args[0]
		}

		// 检查文件是否存在
		_, err := os.Stat(targetFilePath)
		if err == nil {
			// 文件已存在
			if !forceOverwrite {
				fmt.Printf("Secret file '%s' already exists. Overwrite? (y/N): ", targetFilePath)
				var response string
				fmt.Scanln(&response)
				if strings.ToLower(response) != "y" {
					fmt.Println("Initialization cancelled.")
					return nil // User chose not to overwrite, not an error
				}
			}
		} else if !os.IsNotExist(err) {
			// 其他文件检查错误
			return fmt.Errorf("Failed to check file '%s': %w", targetFilePath, err)
		}

		var initPassword string
		if len(args) == 0 {
			// 无参数模式：生成随机密码
			randomPassword, err := crypto.GenerateRandomPassword(32) // 生成32位随机密码
			if err != nil {
				return fmt.Errorf("Failed to generate random password: %w", err)
			}
			initPassword = randomPassword
			fmt.Println("Random password generated. Please keep this password safe:")
			fmt.Printf("Password: %s\n", initPassword)
			fmt.Println("This password is used to encrypt and decrypt your secret files.")
		} else {
			// 带参数模式：使用指定密码
			if password == "" {
				return fmt.Errorf("When specifying a file, password must be provided via -p or --password flag.")
			}
			initPassword = password
		}

		// 加密一个空的键值对集合
		emptySecrets := make(map[string]string)
		encryptedEmptySecrets := make(map[string]string)
		for k, v := range emptySecrets {
			initPasswordBytes := []byte(initPassword)
			defer func() {
				for i := range initPasswordBytes {
					initPasswordBytes[i] = 0
				}
			}()
			encryptedValue, err := crypto.Encrypt(v, initPasswordBytes)
			if err != nil {
				return fmt.Errorf("Failed to encrypt empty secrets: %w", err)
			}
			encryptedEmptySecrets[k] = encryptedValue
		}

		// 计算哈希
		hash := file.CalculateSecretsHash(emptySecrets) // 对解密后的空数据计算哈希

		sf := &file.SecretFile{
			Secrets: encryptedEmptySecrets,
			Hash:    hash,
		}

		if err := file.WriteSecretFile(targetFilePath, sf); err != nil {
			return fmt.Errorf("Failed to create secret file '%s': %w", targetFilePath, err)
		}

		fmt.Printf("Secret file '%s' successfully initialized.\n", targetFilePath)
		return nil
	},
}

var importCmd = &cobra.Command{
	Use:   "import [input_file]",
	Short: "Import secrets from unencrypted JSON file and encrypt",
	Long: `The import command reads an unencrypted JSON file, validates its format (no nesting allowed),
	encrypts all values using the provided password, calculates hash, and writes the encrypted data to a new secret file.`,
	Args: cobra.ExactArgs(1), // Only need one input file path argument
 	RunE: func(cmd *cobra.Command, args []string) error {
		inputFilePath := args[0]
		outputFilePath, _ := cmd.Flags().GetString("output")

		if password == "" {
			return fmt.Errorf("Password must be provided via -p or --password flag.")
		}

		if outputFilePath == "" {
			return fmt.Errorf("Output file path must be specified (-o or --output).")
		}

		// 1. 读取输入JSON文件
		data, err := ioutil.ReadFile(inputFilePath)
		if err != nil {
			return fmt.Errorf("Cannot read input file '%s': %w", inputFilePath, err)
		}

		// 2. 严格校验输入JSON文件，确保其是单纯的键值对，没有嵌套。
		// 但这里我们实际上是导入非加密的纯JSON，所以需要一个临时的map来接收
		var rawSecrets map[string]interface{}
		if err := json.Unmarshal(data, &rawSecrets); err != nil {
			return fmt.Errorf("Failed to parse input JSON file '%s': %w", inputFilePath, err)
		}

		plainSecrets := make(map[string]string)
		for k, v := range rawSecrets {
			// 检查是否有嵌套结构
			if _, isMap := v.(map[string]interface{}); isMap {
				return fmt.Errorf("Input JSON file '%s' contains nested objects, import not supported.", inputFilePath)
			}
			if _, isArray := v.([]interface{}); isArray {
				return fmt.Errorf("Input JSON file '%s' contains nested arrays, import not supported.", inputFilePath)
			}
			strVal, ok := v.(string)
			if !ok {
				return fmt.Errorf("Value for key '%s' in input JSON file '%s' is not a string type.", k, inputFilePath)
			}
			plainSecrets[k] = strVal
		}

		// 3. 使用提供的密码加密输入JSON文件中的所有值。
		encryptedSecrets := make(map[string]string)
		for k, plaintextValue := range plainSecrets {
			passwordBytes := []byte(password)
			defer func() {
				for i := range passwordBytes {
					passwordBytes[i] = 0
				}
			}()
			encryptedValue, err := crypto.Encrypt(plaintextValue, passwordBytes)
			if err != nil {
				return fmt.Errorf("Failed to encrypt value for key '%s': %w", k, err)
			}
			encryptedSecrets[k] = encryptedValue
		}

		// 4. 计算加密后所有键值对的整体哈希值，并将其存储在 __hash__ 字段中。
		// 注意：哈希是基于解密后的原始数据计算的，而不是加密后的数据。
		// 任务要求“计算加密后所有键值对的整体哈希值”，这与现有VerifySecretsHash的逻辑冲突。
		// 现有逻辑是基于解密后的数据计算哈希。为了保持一致性，我们应该基于原始的plainSecrets计算哈希。
		// 如果任务确实要求基于加密后的数据计算哈希，那么需要修改CalculateSecretsHash。
		// 考虑到“哈希校验失败，文件可能已被篡改或密码不正确”的提示，哈希应该基于原始数据，
		// 这样才能在解密后验证数据的完整性。
		// 暂时按照现有逻辑，基于plainSecrets计算哈希。
		hash := file.CalculateSecretsHash(plainSecrets)

		// 5. 将加密后的键值对和 __hash__ 写入到指定的输出JSON文件。
		outputSF := &file.SecretFile{
			Secrets: encryptedSecrets,
			Hash:    hash,
		}

		if err := file.WriteSecretFile(outputFilePath, outputSF); err != nil {
			return fmt.Errorf("Failed to write output secret file '%s': %w", outputFilePath, err)
		}

		// 6. 成功导入后，向用户提供确认信息。
		fmt.Printf("Secrets successfully imported from unencrypted file '%s' and encrypted to '%s'.\n", inputFilePath, outputFilePath)
		return nil
	},
}

var editCmd = &cobra.Command{
	Use:   "edit [file]",
	Short: "Interactively edit secret file",
	Long: `The edit command interactively edits encrypted secret files.
It decrypts file contents, allows users to add, modify, or delete key-value pairs, and re-encrypts when saving.`,
	Args: cobra.ExactArgs(1), // Only need one file path argument
 	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0] // 获取文件路径

		if password == "" {
			return fmt.Errorf("Password must be provided via -p or --password flag.")
		}

		sf, err := file.ReadSecretFile(filePath)
		if err != nil {
			return fmt.Errorf("Cannot read secret file '%s': %w", filePath, err)
		}

		// 解密所有秘密到内存中
		decryptedSecrets := make(map[string]string)
		for k, encryptedValue := range sf.Secrets {
			if k == file.HashField {
				continue
			}
			passwordBytes := []byte(password)
			defer func() {
				for i := range passwordBytes {
					passwordBytes[i] = 0
				}
			}()
			decryptedValue, err := crypto.Decrypt(encryptedValue, passwordBytes)
			if err != nil {
				return fmt.Errorf("Cannot decrypt key '%s', please check if password is correct or file is corrupted: %w", k, err) // Decryption failure is fatal error, exit editing
			}
			decryptedSecrets[k] = decryptedValue
		}

		// 验证解密后的数据与原始哈希是否匹配
		if !file.VerifySecretsHash(decryptedSecrets, sf.Hash) {
			return fmt.Errorf("Secret file hash verification failed, file may have been tampered with or password is incorrect.")
		}

		reader := bufio.NewReader(os.Stdin)
		fmt.Println("Entering interactive edit mode. Enter 'key: \"value\"' to update/add secrets, 'key:' or 'key: null' to delete secrets.")
		fmt.Println("Enter '/save' or '/s' to save and exit, enter '/quit' or '/q' to exit without saving.")

		for {
			fmt.Println("\n--- Current Secrets ---")
			if len(decryptedSecrets) == 0 {
				fmt.Println("(No secrets)")
			} else {
				var keys []string
				for k := range decryptedSecrets {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					// 使用ANSI颜色码高亮键和值
					fmt.Printf("\033[1;34m%s\033[0m: \033[0;32m\"%s\"\033[0m\n", k, decryptedSecrets[k])
				}
			}
			fmt.Println("-----------------")

			fmt.Print("Enter command or key-value pair: ")
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(input)

			switch strings.ToLower(input) {
			case "/save", "/s":
				fmt.Println("Saving changes...")
				// 重新加密并保存
				newEncryptedSecrets := make(map[string]string)
				for k, decryptedValue := range decryptedSecrets {
					passwordBytes := []byte(password)
					defer func() {
						for i := range passwordBytes {
							passwordBytes[i] = 0
						}
					}()
					encryptedValue, err := crypto.Encrypt(decryptedValue, passwordBytes)
					if err != nil {
						return fmt.Errorf("Failed to re-encrypt key '%s': %w", k, err) // Encryption failure is fatal error, exit
					}
					newEncryptedSecrets[k] = encryptedValue
				}

				sf.Secrets = newEncryptedSecrets
				sf.Hash = file.CalculateSecretsHash(decryptedSecrets) // 哈希基于解密后的数据计算

				if err := file.WriteSecretFile(filePath, sf); err != nil {
					return fmt.Errorf("Failed to write secret file '%s': %w", filePath, err)
				}
				fmt.Printf("Secret file '%s' successfully updated.\n", filePath)
				return nil // 退出循环和命令
			case "/quit", "/q":
				fmt.Println("Exiting edit mode, changes not saved.")
				return nil // 退出循环和命令
			default:
				// 尝试解析键值对
				parts := strings.SplitN(input, ":", 2)
				if len(parts) != 2 {
					fmt.Println("Invalid input format. Please use 'key: \"value\"' or commands.")
					continue
				}

				key := strings.TrimSpace(parts[0])
				valueStr := strings.TrimSpace(parts[1])

				if key == "" {
					fmt.Println("Key cannot be empty.")
					continue
				}

				// 处理删除操作：key: 或 key: null
				if valueStr == "" || strings.ToLower(valueStr) == "null" {
					if _, exists := decryptedSecrets[key]; exists {
						delete(decryptedSecrets, key)
						fmt.Printf("Key '%s' deleted.\n", key)
					} else {
						fmt.Printf("Key '%s' does not exist, no need to delete.\n", key)
					}
					continue
				}

				// 尝试解析带引号的字符串值
				if strings.HasPrefix(valueStr, "\"") && strings.HasSuffix(valueStr, "\"") {
					// 移除引号并处理转义字符
					unquotedValue, err := strconv.Unquote(valueStr)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error: Failed to parse value '%s', please ensure string is properly quoted and escaped: %v\n", valueStr, err)
						continue
					}
					decryptedSecrets[key] = unquotedValue
					fmt.Printf("Secret updated/added: \033[1;34m%s\033[0m: \033[0;32m\"%s\"\033[0m\n", key, unquotedValue)
				} else {
					fmt.Println("Value must be enclosed in double quotes, e.g.: 'key: \"value\"'.")
				}
			}
		}
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&secretFilePath, "file", "f", "sectore.json", "Default secret file path")
	rootCmd.PersistentFlags().StringVarP(&password, "password", "p", "", "Password for encryption/decryption")
	// Password is no longer required for all commands, only checked when needed
	// rootCmd.MarkPersistentFlagRequired("password")

	// Add force flag for initCmd
	initCmd.Flags().BoolVarP(&forceOverwrite, "force", "F", false, "Force overwrite if file already exists")

	// Add output flag for exportCmd
	exportCmd.Flags().StringP("output", "o", "", "Output file path (.json or .env)")
	exportCmd.MarkFlagRequired("output") // Output file path is required

	// Add output flag for importCmd
	importCmd.Flags().StringP("output", "o", "", "Output secret file path")
	importCmd.MarkFlagRequired("output") // Output file path is required

	rootCmd.AddCommand(setCmd)
	rootCmd.AddCommand(unsetCmd)
	rootCmd.AddCommand(exportCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(importCmd)
	rootCmd.AddCommand(editCmd)
}

func Execute() error {
	return rootCmd.Execute()
}

func main() {
	if err := Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}