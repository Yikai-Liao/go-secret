package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	plaintext := "这是一段需要加密的秘密信息。"
	passwordStr := "mySuperSecretPassword123"
	password := []byte(passwordStr)
	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()

	// 测试可逆性
	encryptedText, err := Encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	decryptedText, err := Decrypt(encryptedText, password)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}

	if decryptedText != plaintext {
		t.Errorf("解密后的文本与原始文本不匹配。\n期望: %s\n实际: %s", plaintext, decryptedText)
	}

	// 测试随机性 (盐和 nonce 应该不同)
	encryptedText2, err := Encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("第二次加密失败: %v", err)
	}

	if encryptedText == encryptedText2 {
		t.Errorf("两次加密相同明文和密码，密文相同，可能缺乏随机性。")
	}

	// 验证解密失败：密码错误
	wrongPasswordStr := "wrongPassword"
	wrongPassword := []byte(wrongPasswordStr)
	defer func() {
		for i := range wrongPassword {
			wrongPassword[i] = 0
		}
	}()
	_, err = Decrypt(encryptedText, wrongPassword)
	if err == nil {
		t.Errorf("使用错误密码解密成功，但预期失败。")
	}
	if !strings.Contains(err.Error(), "GCM解密失败") {
		t.Errorf("错误密码解密失败信息不正确: %v", err)
	}

	// 验证解密失败：加密数据太短
	shortData := base64.StdEncoding.EncodeToString([]byte("short"))
	_, err = Decrypt(shortData, password)
	if err == nil {
		t.Errorf("解密短数据成功，但预期失败。")
	}
	if !strings.Contains(err.Error(), "加密数据太短") {
		t.Errorf("短数据解密失败信息不正确: %v", err)
	}

	// 验证解密失败：Base64解码失败
	invalidBase64 := "!" + encryptedText
	_, err = Decrypt(invalidBase64, password)
	if err == nil {
		t.Errorf("解密无效Base64数据成功，但预期失败。")
	}
	if !strings.Contains(err.Error(), "Base64解码失败") {
		t.Errorf("无效Base64解密失败信息不正确: %v", err)
	}
}

func TestGenerateRandomPassword(t *testing.T) {
	// 测试正常长度
	length := 20
	password, err := GenerateRandomPassword(length)
	if err != nil {
		t.Fatalf("生成随机密码失败: %v", err)
	}
	if len(password) != length {
		t.Errorf("生成的密码长度不正确。期望: %d, 实际: %d", length, len(password))
	}

	// 验证字符集
	charset := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
	for _, char := range password {
		if !strings.ContainsRune(charset, char) {
			t.Errorf("生成的密码包含不在允许字符集中的字符: %c", char)
		}
	}

	// 测试随机性
	password2, err := GenerateRandomPassword(length)
	if err != nil {
		t.Fatalf("第二次生成随机密码失败: %v", err)
	}
	if password == password2 {
		t.Errorf("两次生成相同长度的密码，结果相同，可能缺乏随机性。")
	}

	// 测试长度为0
	_, err = GenerateRandomPassword(0)
	if err == nil {
		t.Errorf("生成长度为0的密码成功，但预期失败。")
	}
	if !strings.Contains(err.Error(), "密码长度必须大于0") {
		t.Errorf("长度为0的密码错误信息不正确: %v", err)
	}

	// 测试长度为负数
	_, err = GenerateRandomPassword(-5)
	if err == nil {
		t.Errorf("生成长度为负数的密码成功，但预期失败。")
	}
	if !strings.Contains(err.Error(), "密码长度必须大于0") {
		t.Errorf("长度为负数的密码错误信息不正确: %v", err)
	}
}

// TestEncryptEdgeCases tests edge cases for Encrypt function
func TestEncryptEdgeCases(t *testing.T) {
	password := []byte("testpassword")
	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()

	// Test empty plaintext
	encrypted, err := Encrypt("", password)
	if err != nil {
		t.Fatalf("加密空字符串失败: %v", err)
	}
	
	decrypted, err := Decrypt(encrypted, password)
	if err != nil {
		t.Fatalf("解密空字符串失败: %v", err)
	}
	
	if decrypted != "" {
		t.Errorf("解密空字符串结果不正确。期望: '', 实际: '%s'", decrypted)
	}

	// Test very long plaintext
	longText := strings.Repeat("A", 10000)
	encrypted, err = Encrypt(longText, password)
	if err != nil {
		t.Fatalf("加密长字符串失败: %v", err)
	}
	
	decrypted, err = Decrypt(encrypted, password)
	if err != nil {
		t.Fatalf("解密长字符串失败: %v", err)
	}
	
	if decrypted != longText {
		t.Errorf("解密长字符串结果不正确")
	}

	// Test unicode characters
	unicodeText := "🔐密码测试🔑"
	encrypted, err = Encrypt(unicodeText, password)
	if err != nil {
		t.Fatalf("加密Unicode字符串失败: %v", err)
	}
	
	decrypted, err = Decrypt(encrypted, password)
	if err != nil {
		t.Fatalf("解密Unicode字符串失败: %v", err)
	}
	
	if decrypted != unicodeText {
		t.Errorf("解密Unicode字符串结果不正确。期望: %s, 实际: %s", unicodeText, decrypted)
	}
}

// TestDecryptEdgeCases tests edge cases for Decrypt function
func TestDecryptEdgeCases(t *testing.T) {
	password := []byte("testpassword")
	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()

	// Test malformed encrypted data (just salt + nonce, no ciphertext)
	shortData := make([]byte, saltLen+nonceLen)
	_, err := io.ReadFull(rand.Reader, shortData)
	if err != nil {
		t.Fatalf("生成测试数据失败: %v", err)
	}
	
	shortEncoded := base64.StdEncoding.EncodeToString(shortData)
	_, err = Decrypt(shortEncoded, password)
	if err == nil {
		t.Errorf("解密仅包含salt和nonce的数据成功，但预期失败")
	}

	// Test corrupted ciphertext
	plaintext := "test data"
	encrypted, err := Encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("加密测试数据失败: %v", err)
	}
	
	// Decode, corrupt last byte, re-encode
	data, _ := base64.StdEncoding.DecodeString(encrypted)
	data[len(data)-1] ^= 0xFF // Flip all bits in last byte
	corruptedEncrypted := base64.StdEncoding.EncodeToString(data)
	
	_, err = Decrypt(corruptedEncrypted, password)
	if err == nil {
		t.Errorf("解密损坏的密文成功，但预期失败")
	}
	if !strings.Contains(err.Error(), "GCM解密失败") {
		t.Errorf("损坏密文解密失败信息不正确: %v", err)
	}
}

// TestGenerateRandomPasswordLarge tests large password generation
func TestGenerateRandomPasswordLarge(t *testing.T) {
	// Test generating very large password
	largeLength := 1000
	password, err := GenerateRandomPassword(largeLength)
	if err != nil {
		t.Fatalf("生成大密码失败: %v", err)
	}
	
	if len(password) != largeLength {
		t.Errorf("生成的大密码长度不正确。期望: %d, 实际: %d", largeLength, len(password))
	}
	
	// Verify all characters are from the charset
	charset := passwordCharset
	for i, char := range password {
		if !strings.ContainsRune(charset, char) {
			t.Errorf("生成的大密码在位置%d包含不在允许字符集中的字符: %c", i, char)
			break
		}
	}
}

// TestDeriveKey tests the deriveKey function indirectly
func TestDeriveKey(t *testing.T) {
	password := []byte("testpassword")
	
	// Test that same password + salt produces same key (by testing encryption consistency)
	plaintext := "consistent test"
	
	// Encrypt with same password and verify we can decrypt multiple times
	encrypted1, err := Encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("第一次加密失败: %v", err)
	}
	
	encrypted2, err := Encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("第二次加密失败: %v", err)
	}
	
	// Both should decrypt successfully with same password
	decrypted1, err := Decrypt(encrypted1, password)
	if err != nil {
		t.Fatalf("解密第一次加密失败: %v", err)
	}
	
	decrypted2, err := Decrypt(encrypted2, password)
	if err != nil {
		t.Fatalf("解密第二次加密失败: %v", err)
	}
	
	if decrypted1 != plaintext || decrypted2 != plaintext {
		t.Errorf("一致性测试失败")
	}
	
	// Clear password
	for i := range password {
		password[i] = 0
	}
}

// TestEncryptionErrorPaths tests various error paths in encryption/decryption
func TestEncryptionErrorPaths(t *testing.T) {
	password := []byte("testpassword")
	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()

	// Test with very short password
	shortPassword := []byte("a")
	defer func() {
		for i := range shortPassword {
			shortPassword[i] = 0
		}
	}()
	
	plaintext := "test data"
	encrypted, err := Encrypt(plaintext, shortPassword)
	if err != nil {
		t.Fatalf("加密短密码失败: %v", err)
	}
	
	decrypted, err := Decrypt(encrypted, shortPassword)
	if err != nil {
		t.Fatalf("解密短密码失败: %v", err)
	}
	
	if decrypted != plaintext {
		t.Errorf("短密码加解密不一致")
	}
	
	// Test edge case: data exactly at minimum length
	minimumData := make([]byte, saltLen+nonceLen)
	_, err = io.ReadFull(rand.Reader, minimumData)
	if err != nil {
		t.Fatalf("生成最小数据失败: %v", err)
	}
	
	minimumEncoded := base64.StdEncoding.EncodeToString(minimumData)
	_, err = Decrypt(minimumEncoded, password)
	// This should not fail due to length check but will fail during GCM decryption
	if err == nil {
		t.Errorf("解密最小长度数据成功，但预期失败")
	}
}