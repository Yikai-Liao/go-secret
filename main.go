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

	"go-secret/internal/crypto"
	"go-secret/internal/file"

	"github.com/spf13/cobra"
)

var (
	secretFilePath string
	password       string
	forceOverwrite bool // 新增：强制覆盖标志
	passwordBytes  []byte // 新增：用于安全处理密码
)

var rootCmd = &cobra.Command{
	Use:   "go-secret",
	Short: "go-secret 是一个用于管理加密键值对的CLI工具",
	Long: `go-secret 是一个强大的CLI工具，用于安全地存储、检索和管理加密的键值对。
它支持多种操作，如设置、取消设置、导出、初始化、导入和编辑秘密。`,
	RunE: func(cmd *cobra.Command, args []string) error {
	// 默认行为：显示帮助信息
	cmd.Help()
	return nil
},
}

var setCmd = &cobra.Command{
	Use:   "set [file]",
	Short: "从加密文件设置环境变量",
	Long:  `set 命令用于读取一个加密的JSON文件，解密其内容，并将其键值对设置为当前会话的环境变量。`,
	Args:  cobra.ExactArgs(1), // 只需要一个文件路径参数
 	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0] // 获取文件路径

		sf, err := file.ReadSecretFile(filePath) // 读取指定文件
		if err != nil {
			return fmt.Errorf("无法读取秘密文件 '%s': %w", filePath, err)
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
				fmt.Fprintf(os.Stderr, "警告: 无法解密键 '%s' (可能是密码错误或数据损坏): %v\n", k, err)
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
				return fmt.Errorf("秘密文件哈希校验失败，且一个或多个秘密解密失败 (可能是密码错误或文件被篡改)。")
			}
			return fmt.Errorf("秘密文件哈希校验失败，文件可能已被篡改。")
		}
		
		// If all decryptions failed due to wrong password, and original secrets map was empty, hash could still pass.
		// This case needs careful thought. If sf.Secrets was empty to begin with (e.g. init file),
		// decryptedSecrets would be empty, and CalculateSecretsHash on empty map would match sf.Hash.
		// If sf.Secrets was NOT empty, but all decryptions failed, decryptedSecrets would be empty.
		// CalculateSecretsHash(empty) would NOT match sf.Hash (which was based on non-empty original data).
		// So the hash check *should* catch wrong password if there was data.

		fmt.Printf("正在从 '%s' 设置环境变量...\n", filePath)
		// Iterate over successfully decrypted secrets to set them
		for k, decryptedValue := range decryptedSecrets {
			// We already handled decryption errors above.
			// If a key is in decryptedSecrets, it means it was successfully decrypted.
			os.Setenv(k, decryptedValue)
			fmt.Printf("已设置环境变量: %s\n", k)
		}
		if len(decryptedSecrets) == 0 && len(sf.Secrets) > 0 && !anyDecryptionFailed {
			// This case implies sf.Secrets had entries but none were added to decryptedSecrets,
			// which shouldn't happen if anyDecryptionFailed is false.
			// This might indicate an issue if sf.Secrets only contained __hash__.
		} else if anyDecryptionFailed && len(decryptedSecrets) == 0 && len(sf.Secrets) > 0 {
		           fmt.Fprintln(os.Stderr, "警告: 由于所有秘密解密失败，未设置任何环境变量。请检查密码。")
		      }

		fmt.Println("环境变量设置完成。这些变量仅在当前会话中有效。")
		return nil
	},
}

var unsetCmd = &cobra.Command{
	Use:   "unset [file]",
	Short: "从加密文件取消设置环境变量",
	Long:  `unset 命令用于读取一个加密的JSON文件，解密其内容，并提供取消设置相应环境变量的shell命令。`,
	Args:  cobra.ExactArgs(1), // 只需要一个文件路径参数
 	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0] // 获取文件路径

		sf, err := file.ReadSecretFile(filePath) // 读取指定文件
		if err != nil {
			return fmt.Errorf("无法读取秘密文件 '%s': %w", filePath, err)
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
				fmt.Fprintf(os.Stderr, "警告: 无法解密键 '%s' (可能是密码错误或数据损坏)，将仍会尝试生成unset命令: %v\n", k, err)
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
				return fmt.Errorf("秘密文件哈希校验失败，且一个或多个秘密解密失败 (可能是密码错误或文件被篡改)。")
			}
			return fmt.Errorf("秘密文件哈希校验失败，文件可能已被篡改。")
		}

		fmt.Printf("以下是取消设置从 '%s' 读取的环境变量的命令：\n", filePath)
		fmt.Println("# 请在您的shell中执行以下命令以取消设置环境变量：")
		
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
		          fmt.Println("(无秘密可取消设置)")
		      }

		fmt.Println("请注意：这些命令需要在当前shell会话中手动执行才能生效。")
		return nil
	},
}

var exportCmd = &cobra.Command{
	Use:   "export [input_file]",
	Short: "导出加密的秘密到指定文件",
	Long: `export 命令用于读取一个加密的JSON文件，解密其内容，并将其键值对导出到指定的输出文件。
支持导出为JSON格式（移除__hash__字段）或.env格式。`,
	Args: cobra.ExactArgs(1), // 只需要一个输入文件路径参数
 	RunE: func(cmd *cobra.Command, args []string) error {
		inputFilePath := args[0]
		outputFilePath, _ := cmd.Flags().GetString("output")

		if outputFilePath == "" {
			return fmt.Errorf("必须指定输出文件路径 (-o 或 --output)。")
		}

		sf, err := file.ReadSecretFile(inputFilePath)
		if err != nil {
			return fmt.Errorf("无法读取输入秘密文件 '%s': %w", inputFilePath, err)
		}

		decryptedSecrets := make(map[string]string)
		for k, encryptedValue := range sf.Secrets {
			if k == file.HashField { // 跳过__hash__字段，因为它在解密前就存在
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
				return fmt.Errorf("无法解密键 '%s': %w", k, err) // 解密失败是致命错误，停止导出
			}
			decryptedSecrets[k] = decryptedValue
		}

		// 验证解密后的数据与原始哈希是否匹配
		if !file.VerifySecretsHash(decryptedSecrets, sf.Hash) {
			return fmt.Errorf("秘密文件哈希校验失败，文件可能已被篡改或密码不正确。")
		}

		// 根据输出文件后缀决定导出格式
		if strings.HasSuffix(outputFilePath, ".json") {
			// 导出为JSON
			outputSF := &file.SecretFile{Secrets: decryptedSecrets}
			// 注意：WriteSecretFile会自动处理__hash__字段的写入，但这里我们希望导出的是纯净的解密JSON，
			// 所以我们直接使用decryptedSecrets，并且不设置Hash字段，让MarshalJSON只导出Secrets。
			// SecretFile的MarshalJSON方法会检查sf.Hash是否为空，如果为空则不写入__hash__。
			outputSF.Hash = "" // 确保不写入__hash__字段

			if err := file.WriteSecretFile(outputFilePath, outputSF); err != nil {
				return fmt.Errorf("写入输出JSON文件失败 '%s': %w", outputFilePath, err)
			}
			fmt.Printf("秘密已成功导出到JSON文件 '%s'。\n", outputFilePath)
		} else if strings.HasSuffix(outputFilePath, ".env") {
			// 导出为.env
			var envContent strings.Builder
			var keys []string
			for k := range decryptedSecrets {
				keys = append(keys, k)
			}
			sort.Strings(keys) // 确保顺序一致性

			for _, k := range keys {
				envContent.WriteString(fmt.Sprintf("%s=%s\n", k, decryptedSecrets[k]))
			}

			if err := os.WriteFile(outputFilePath, []byte(envContent.String()), 0644); err != nil {
				return fmt.Errorf("写入输出.env文件失败 '%s': %w", outputFilePath, err)
			}
			fmt.Printf("秘密已成功导出到.env文件 '%s'。\n", outputFilePath)
		} else {
			return fmt.Errorf("不支持的输出文件格式。输出文件必须以 '.json' 或 '.env' 结尾。")
		}
		return nil
	},
}

var initCmd = &cobra.Command{
	Use:   "init [file]",
	Short: "初始化秘密存储",
	Long: `init 命令用于初始化一个新的秘密存储文件。
如果未指定文件，则默认为 'go-secret.json' 并生成随机密码。
如果指定文件，则必须通过 -p 或 --password 标志提供密码。`,
	Args: cobra.MaximumNArgs(1), // 最多一个文件路径参数
 	RunE: func(cmd *cobra.Command, args []string) error {
		targetFilePath := "go-secret.json" // 默认文件路径
		if len(args) > 0 {
			targetFilePath = args[0]
		}

		// 检查文件是否存在
		_, err := os.Stat(targetFilePath)
		if err == nil {
			// 文件已存在
			if !forceOverwrite {
				fmt.Printf("秘密文件 '%s' 已存在。是否覆盖？(y/N): ", targetFilePath)
				var response string
				fmt.Scanln(&response)
				if strings.ToLower(response) != "y" {
					fmt.Println("初始化已取消。")
					return nil // 用户选择不覆盖，不是错误
				}
			}
		} else if !os.IsNotExist(err) {
			// 其他文件检查错误
			return fmt.Errorf("检查文件 '%s' 失败: %w", targetFilePath, err)
		}

		var initPassword string
		if len(args) == 0 {
			// 无参数模式：生成随机密码
			randomPassword, err := crypto.GenerateRandomPassword(32) // 生成32位随机密码
			if err != nil {
				return fmt.Errorf("生成随机密码失败: %w", err)
			}
			initPassword = randomPassword
			fmt.Println("已生成随机密码。请务必妥善保管此密码：")
			fmt.Printf("密码: %s\n", initPassword)
			fmt.Println("此密码用于加密和解密您的秘密文件。")
		} else {
			// 带参数模式：使用指定密码
			if password == "" {
				return fmt.Errorf("当指定文件时，必须通过 -p 或 --password 标志提供密码。")
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
				return fmt.Errorf("加密空秘密失败: %w", err)
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
			return fmt.Errorf("创建秘密文件 '%s' 失败: %w", targetFilePath, err)
		}

		fmt.Printf("秘密文件 '%s' 已成功初始化。\n", targetFilePath)
		return nil
	},
}

var importCmd = &cobra.Command{
	Use:   "import [input_file]",
	Short: "从非加密JSON文件导入秘密并加密",
	Long: `import 命令用于读取一个非加密的JSON文件，校验其格式（不允许嵌套），
	使用提供的密码加密所有值，计算哈希，并将加密后的数据写入新的秘密文件。`,
	Args: cobra.ExactArgs(1), // 只需要一个输入文件路径参数
 	RunE: func(cmd *cobra.Command, args []string) error {
		inputFilePath := args[0]
		outputFilePath, _ := cmd.Flags().GetString("output")

		if password == "" {
			return fmt.Errorf("必须通过 -p 或 --password 标志提供密码。")
		}

		if outputFilePath == "" {
			return fmt.Errorf("必须指定输出文件路径 (-o 或 --output)。")
		}

		// 1. 读取输入JSON文件
		data, err := ioutil.ReadFile(inputFilePath)
		if err != nil {
			return fmt.Errorf("无法读取输入文件 '%s': %w", inputFilePath, err)
		}

		// 2. 严格校验输入JSON文件，确保其是单纯的键值对，没有嵌套。
		// 但这里我们实际上是导入非加密的纯JSON，所以需要一个临时的map来接收
		var rawSecrets map[string]interface{}
		if err := json.Unmarshal(data, &rawSecrets); err != nil {
			return fmt.Errorf("解析输入JSON文件 '%s' 失败: %w", inputFilePath, err)
		}

		plainSecrets := make(map[string]string)
		for k, v := range rawSecrets {
			// 检查是否有嵌套结构
			if _, isMap := v.(map[string]interface{}); isMap {
				return fmt.Errorf("输入JSON文件 '%s' 包含嵌套对象，不支持导入。", inputFilePath)
			}
			if _, isArray := v.([]interface{}); isArray {
				return fmt.Errorf("输入JSON文件 '%s' 包含嵌套数组，不支持导入。", inputFilePath)
			}
			strVal, ok := v.(string)
			if !ok {
				return fmt.Errorf("输入JSON文件 '%s' 中键 '%s' 的值不是字符串类型。", inputFilePath, k)
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
				return fmt.Errorf("加密键 '%s' 的值失败: %w", k, err)
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
			return fmt.Errorf("写入输出秘密文件 '%s' 失败: %w", outputFilePath, err)
		}

		// 6. 成功导入后，向用户提供确认信息。
		fmt.Printf("秘密已成功从非加密文件 '%s' 导入并加密到 '%s'。\n", inputFilePath, outputFilePath)
		return nil
	},
}

var editCmd = &cobra.Command{
	Use:   "edit [file]",
	Short: "交互式编辑秘密文件",
	Long: `edit 命令用于交互式地编辑加密的秘密文件。
它会解密文件内容，允许用户添加、修改或删除键值对，并在保存时重新加密。`,
	Args: cobra.ExactArgs(1), // 只需要一个文件路径参数
 	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0] // 获取文件路径

		if password == "" {
			return fmt.Errorf("必须通过 -p 或 --password 标志提供密码。")
		}

		sf, err := file.ReadSecretFile(filePath)
		if err != nil {
			return fmt.Errorf("无法读取秘密文件 '%s': %w", filePath, err)
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
				return fmt.Errorf("无法解密键 '%s'，请检查密码是否正确或文件是否损坏: %w", k, err) // 解密失败是致命错误，退出编辑
			}
			decryptedSecrets[k] = decryptedValue
		}

		// 验证解密后的数据与原始哈希是否匹配
		if !file.VerifySecretsHash(decryptedSecrets, sf.Hash) {
			return fmt.Errorf("秘密文件哈希校验失败，文件可能已被篡改或密码不正确。")
		}

		reader := bufio.NewReader(os.Stdin)
		fmt.Println("进入交互式编辑模式。输入 'key: \"value\"' 更新/添加秘密，'key:' 或 'key: null' 删除秘密。")
		fmt.Println("输入 '/save' 或 '/s' 保存并退出，输入 '/quit' 或 '/q' 退出不保存。")

		for {
			fmt.Println("\n--- 当前秘密 ---")
			if len(decryptedSecrets) == 0 {
				fmt.Println("（无秘密）")
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

			fmt.Print("输入命令或键值对: ")
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(input)

			switch strings.ToLower(input) {
			case "/save", "/s":
				fmt.Println("正在保存更改...")
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
						return fmt.Errorf("重新加密键 '%s' 失败: %w", k, err) // 加密失败是致命错误，退出
					}
					newEncryptedSecrets[k] = encryptedValue
				}

				sf.Secrets = newEncryptedSecrets
				sf.Hash = file.CalculateSecretsHash(decryptedSecrets) // 哈希基于解密后的数据计算

				if err := file.WriteSecretFile(filePath, sf); err != nil {
					return fmt.Errorf("写入秘密文件 '%s' 失败: %w", filePath, err)
				}
				fmt.Printf("秘密文件 '%s' 已成功更新。\n", filePath)
				return nil // 退出循环和命令
			case "/quit", "/q":
				fmt.Println("退出编辑模式，未保存更改。")
				return nil // 退出循环和命令
			default:
				// 尝试解析键值对
				parts := strings.SplitN(input, ":", 2)
				if len(parts) != 2 {
					fmt.Println("无效输入格式。请使用 'key: \"value\"' 或命令。")
					continue
				}

				key := strings.TrimSpace(parts[0])
				valueStr := strings.TrimSpace(parts[1])

				if key == "" {
					fmt.Println("键不能为空。")
					continue
				}

				// 处理删除操作：key: 或 key: null
				if valueStr == "" || strings.ToLower(valueStr) == "null" {
					if _, exists := decryptedSecrets[key]; exists {
						delete(decryptedSecrets, key)
						fmt.Printf("已删除键 '%s'。\n", key)
					} else {
						fmt.Printf("键 '%s' 不存在，无需删除。\n", key)
					}
					continue
				}

				// 尝试解析带引号的字符串值
				if strings.HasPrefix(valueStr, "\"") && strings.HasSuffix(valueStr, "\"") {
					// 移除引号并处理转义字符
					unquotedValue, err := strconv.Unquote(valueStr)
					if err != nil {
						fmt.Fprintf(os.Stderr, "错误: 解析值 '%s' 失败，请确保字符串正确引用和转义: %v\n", valueStr, err)
						continue
					}
					decryptedSecrets[key] = unquotedValue
					fmt.Printf("已更新/添加秘密: \033[1;34m%s\033[0m: \033[0;32m\"%s\"\033[0m\n", key, unquotedValue)
				} else {
					fmt.Println("值必须用双引号括起来，例如: 'key: \"value\"'。")
				}
			}
		}
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&secretFilePath, "file", "f", "secrets.json", "默认秘密文件路径")
	rootCmd.PersistentFlags().StringVarP(&password, "password", "p", "", "用于加密/解密的密码")
	// 密码不再是所有命令的必需参数，只在需要时检查
	// rootCmd.MarkPersistentFlagRequired("password")

	// 为 initCmd 添加 force 标志
	initCmd.Flags().BoolVarP(&forceOverwrite, "force", "F", false, "如果文件已存在，则强制覆盖")

	// 为 exportCmd 添加 output 标志
	exportCmd.Flags().StringP("output", "o", "", "输出文件路径（.json 或 .env）")
	exportCmd.MarkFlagRequired("output") // 输出文件路径是必需的

	// 为 importCmd 添加 output 标志
	importCmd.Flags().StringP("output", "o", "", "输出秘密文件路径")
	importCmd.MarkFlagRequired("output") // 输出文件路径是必需的

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