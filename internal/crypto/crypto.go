package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/pbkdf2"
)

const (
	keyLen   = 32 // AES-256
	saltLen  = 16
	nonceLen = 12 // GCM nonce size
	// 密码字符集：大写字母、小写字母、数字和特殊字符
	passwordCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
)

// deriveKey 从密码和盐派生密钥
func deriveKey(password []byte, salt []byte) []byte {
	return pbkdf2.Key(password, salt, 100000, keyLen, sha256.New)
}

// Encrypt 使用密码加密数据
func Encrypt(plaintext string, password []byte) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("生成盐失败: %w", err)
	}

	key := deriveKey(password, salt)
	defer func() {
		// Zero out sensitive data
		for i := range key {
			key[i] = 0
		}
	}()

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("创建AES密码失败: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("创建GCM模式失败: %w", err)
	}

	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("生成nonce失败: %w", err)
	}

	ciphertext := aesGCM.Seal(nil, nonce, []byte(plaintext), nil)

	// 格式: salt + nonce + ciphertext
	encryptedData := append(salt, nonce...)
	encryptedData = append(encryptedData, ciphertext...)

	return base64.StdEncoding.EncodeToString(encryptedData), nil
}

// Decrypt 使用密码解密数据
func Decrypt(encryptedText string, password []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", fmt.Errorf("Base64解码失败: %w", err)
	}

	if len(data) < saltLen+nonceLen {
		return "", errors.New("加密数据太短")
	}

	salt := data[:saltLen]
	nonce := data[saltLen : saltLen+nonceLen]
	ciphertext := data[saltLen+nonceLen:]

	key := deriveKey(password, salt)
	defer func() {
		// Zero out sensitive data
		for i := range key {
			key[i] = 0
		}
	}()

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("创建AES密码失败: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("创建GCM模式失败: %w", err)
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("GCM解密失败: %w", err)
	}

	return string(plaintext), nil
}

// GenerateRandomPassword 生成指定长度的安全随机密码
func GenerateRandomPassword(length int) (string, error) {
	if length <= 0 {
		return "", errors.New("密码长度必须大于0")
	}

	password := make([]byte, length)
	charsetLen := big.NewInt(int64(len(passwordCharset)))

	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", fmt.Errorf("生成随机字符失败: %w", err)
		}
		password[i] = passwordCharset[num.Int64()]
	}

	return string(password), nil
}
