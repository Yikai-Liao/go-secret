package crypto

import (
	"encoding/base64"
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