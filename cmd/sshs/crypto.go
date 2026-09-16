package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"

	"github.com/zalando/go-keyring"
)

const (
	encPrefix        = "ENC(v1:"
	encSuffix        = ")"
	saltLength       = 16
	nonceLength      = 12
	pbkdf2Rounds     = 100000
	aesKeyLength     = 32
	keyringService   = "sshs"
	keyringMasterKey = "master-key"
)

var (
	masterKeyLock    sync.RWMutex
	cachedMasterKey  string
	errCorruptedPass = errors.New("master password incorrect or ciphertext corrupted")
)

// IsEncrypted 判断字符串是否为 sshs 密文格式。
func IsEncrypted(password string) bool {
	return strings.HasPrefix(password, encPrefix) && strings.HasSuffix(password, encSuffix)
}

// EncryptPassword 使用主密码和 AES-256-GCM 对明文进行加密，返回 ENC(v1:...) 格式字符串。
func EncryptPassword(plainText, masterKey string) (string, error) {
	if masterKey == "" {
		return "", errors.New("master key cannot be empty")
	}

	salt := make([]byte, saltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	key := pbkdf2.Key([]byte(masterKey), salt, pbkdf2Rounds, aesKeyLength, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("new cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("new gcm: %w", err)
	}

	nonce := make([]byte, nonceLength)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	cipherText := aesGCM.Seal(nil, nonce, []byte(plainText), nil)

	// 打包 salt + nonce + cipherText
	payload := make([]byte, 0, len(salt)+len(nonce)+len(cipherText))
	payload = append(payload, salt...)
	payload = append(payload, nonce...)
	payload = append(payload, cipherText...)

	encoded := base64.RawURLEncoding.EncodeToString(payload)
	return fmt.Sprintf("%s%s%s", encPrefix, encoded, encSuffix), nil
}

// DecryptPassword 使用主密码对 ENC(v1:...) 密文字符串进行解密。
func DecryptPassword(encryptedPassword, masterKey string) (string, error) {
	if !IsEncrypted(encryptedPassword) {
		return "", errors.New("invalid encrypted password format")
	}
	if masterKey == "" {
		return "", errors.New("master key cannot be empty")
	}

	raw := strings.TrimSuffix(strings.TrimPrefix(encryptedPassword, encPrefix), encSuffix)
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("%w: base64 decode failed", errCorruptedPass)
	}

	minPayloadLen := saltLength + nonceLength + 16 // 16 为 GCM tag 长度
	if len(payload) < minPayloadLen {
		return "", errCorruptedPass
	}

	salt := payload[:saltLength]
	nonce := payload[saltLength : saltLength+nonceLength]
	cipherText := payload[saltLength+nonceLength:]

	key := pbkdf2.Key([]byte(masterKey), salt, pbkdf2Rounds, aesKeyLength, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("new cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("new gcm: %w", err)
	}

	plainText, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", errCorruptedPass
	}

	return string(plainText), nil
}

func getCachedMasterKey() string {
	masterKeyLock.RLock()
	defer masterKeyLock.RUnlock()
	return cachedMasterKey
}

func setCachedMasterKey(key string) {
	masterKeyLock.Lock()
	defer masterKeyLock.Unlock()
	cachedMasterKey = key
}

type KeyringProvider interface {
	Get(service, account string) (string, error)
	Set(service, account, password string) error
	Delete(service, account string) error
}

type defaultKeyringProvider struct{}

func (defaultKeyringProvider) Get(service, account string) (string, error) {
	return keyring.Get(service, account)
}

func (defaultKeyringProvider) Set(service, account, password string) error {
	return keyring.Set(service, account, password)
}

func (defaultKeyringProvider) Delete(service, account string) error {
	return keyring.Delete(service, account)
}

var activeKeyring KeyringProvider = defaultKeyringProvider{}

// GetKeyringMasterKey 查询系统钥匙串中当前存储的主密码。
func GetKeyringMasterKey() (string, error) {
	return activeKeyring.Get(keyringService, keyringMasterKey)
}

// SetKeyringMasterKey 向系统钥匙串设置或更新主密码。
func SetKeyringMasterKey(key string) error {
	if key == "" {
		return errors.New("master key cannot be empty")
	}
	if err := activeKeyring.Set(keyringService, keyringMasterKey, key); err != nil {
		return err
	}
	setCachedMasterKey(key)
	return nil
}

// DeleteKeyringMasterKey 从系统钥匙串中清除主密码。
func DeleteKeyringMasterKey() error {
	setCachedMasterKey("")
	return activeKeyring.Delete(keyringService, keyringMasterKey)
}

// ResolveMasterKey 获取用于解密的主密码：
// 1. 进程内内存缓存
// 2. 系统钥匙串 (keyring)
// 3. 终端无回显交互提示输入，并自动保存到系统钥匙串
func ResolveMasterKey(confirm bool) (string, error) {
	if key := getCachedMasterKey(); key != "" {
		return key, nil
	}

	if ringKey, err := activeKeyring.Get(keyringService, keyringMasterKey); err == nil && ringKey != "" {
		setCachedMasterKey(ringKey)
		return ringKey, nil
	}

	stdinFd := int(syscall.Stdin)
	if !stdinTerminalCheck(stdinFd) {
		return "", errors.New("master password required: set it via 'sshs master-key set' or run in an interactive terminal")
	}

	fmt.Fprint(os.Stderr, "Enter Master Password: ")
	passwordBytes, err := terminalPasswordReader(stdinFd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read master password: %w", err)
	}
	masterKey := strings.TrimSpace(string(passwordBytes))
	if masterKey == "" {
		return "", errors.New("master password cannot be empty")
	}

	if confirm {
		fmt.Fprint(os.Stderr, "Confirm Master Password: ")
		confirmBytes, err := terminalPasswordReader(stdinFd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("read confirm master password: %w", err)
		}
		if string(confirmBytes) != masterKey {
			return "", errors.New("master passwords do not match")
		}
	}

	// 自动写入系统钥匙串，后续免密
	if err := activeKeyring.Set(keyringService, keyringMasterKey, masterKey); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to save master key to keyring: %v\n", err)
	}

	setCachedMasterKey(masterKey)
	return masterKey, nil
}

// HasEncryptedPasswords 递归检查给定的配置列表中是否包含 ENC(v1:...) 加密密码。
func HasEncryptedPasswords(configs []Config) bool {
	for _, c := range configs {
		if IsEncrypted(c.Password) {
			return true
		}
		if c.Jumper != nil && HasEncryptedPasswords([]Config{*c.Jumper}) {
			return true
		}
		if len(c.Children) > 0 && HasEncryptedPasswords(c.Children) {
			return true
		}
	}
	return false
}

// EnsureMasterKey 确保系统钥匙串中已配置主口令。
// 首次使用时若钥匙串中未找到 master-key，强制要求用户在终端输入并确认，写入钥匙串后方可继续。
func EnsureMasterKey() error {
	if key := getCachedMasterKey(); key != "" {
		return nil
	}

	if ringKey, err := activeKeyring.Get(keyringService, keyringMasterKey); err == nil && ringKey != "" {
		setCachedMasterKey(ringKey)
		return nil
	}

	stdinFd := int(syscall.Stdin)
	if !stdinTerminalCheck(stdinFd) {
		return errors.New("master key is not configured in system keyring (set it via 'sshs master-key set' or run in an interactive terminal)")
	}

	fmt.Fprintln(os.Stderr, "Master key is not configured in system keyring. Please set it first:")
	fmt.Fprint(os.Stderr, "Enter Master Password: ")
	b1, err := terminalPasswordReader(stdinFd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return fmt.Errorf("read master password: %w", err)
	}
	masterKey := strings.TrimSpace(string(b1))
	if masterKey == "" {
		return errors.New("master password cannot be empty")
	}

	fmt.Fprint(os.Stderr, "Confirm Master Password: ")
	b2, err := terminalPasswordReader(stdinFd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return fmt.Errorf("read confirm master password: %w", err)
	}
	if string(b2) != masterKey {
		return errors.New("master passwords do not match")
	}

	if err := activeKeyring.Set(keyringService, keyringMasterKey, masterKey); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to save master key to keyring: %v\n", err)
	} else {
		fmt.Fprintln(os.Stderr, "Master key successfully saved to system keyring.")
	}

	setCachedMasterKey(masterKey)
	return nil
}

var (
	stdinTerminalCheck = func(fd int) bool {
		return term.IsTerminal(fd)
	}
	terminalPasswordReader = func(fd int) ([]byte, error) {
		return term.ReadPassword(fd)
	}
)

func PromptMasterKeyManual() (string, error) {
	stdinFd := int(syscall.Stdin)
	if !stdinTerminalCheck(stdinFd) {
		return "", errors.New("manual input required: interactive terminal required to input master password")
	}

	fmt.Fprint(os.Stderr, "Enter Master Password: ")
	passwordBytes, err := terminalPasswordReader(stdinFd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read master password: %w", err)
	}
	masterKey := strings.TrimSpace(string(passwordBytes))
	if masterKey == "" {
		return "", errors.New("master password cannot be empty")
	}
	return masterKey, nil
}

