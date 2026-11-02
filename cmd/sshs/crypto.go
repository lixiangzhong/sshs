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
	"io/fs"
	"os"
	"path/filepath"
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
	keyringService         = "sshs"
	keyringMasterKey       = "master-key"
	keyringDefaultPassword = "default-password"

	// masterKeyEnv 允许调用方（MCP、CI 等）在进程级注入主密码，优先级最高且不落盘。
	masterKeyEnv = "SSHS_MASTER_KEY"
	// masterKeyFileEnv 显式指定主密码文件路径；设置后不再访问系统钥匙串。
	masterKeyFileEnv = "SSHS_MASTER_KEY_FILE"
	// keyDirPerm/keyFilePerm 是主密码文件目录与文件权限：仅当前用户可访问。
	keyDirPerm  = 0700
	keyFilePerm = 0600
)

// masterKeySource 标识主密码来源，用于状态展示、自动加密策略判断与错误提示。
type masterKeySource string

const (
	masterKeySourceNone    masterKeySource = ""
	masterKeySourceEnv     masterKeySource = "env"
	masterKeySourceKeyring masterKeySource = "keyring"
	masterKeySourceFile    masterKeySource = "file"
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

// GetKeyringDefaultPassword 从系统钥匙串静默读取默认回退密码（service: sshs, account: default-password）。
// 该回退仅支持系统钥匙串（Linux 上需要可用的 Secret Service）；未配置时静默返回空字符串，绝不交互提示。
func GetKeyringDefaultPassword() string {
	pass, err := activeKeyring.Get(keyringService, keyringDefaultPassword)
	if err != nil {
		return ""
	}
	return pass
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

// masterKeyFileResolver 解析默认主密码文件路径；单测可替换以隔离真实用户目录。
var masterKeyFileResolver = defaultMasterKeyFilePath

// defaultMasterKeyFilePath 返回用户配置目录下的 sshs/master-key 路径。
func defaultMasterKeyFilePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "sshs", "master-key"), nil
}

// MasterKeyFilePath 返回主密码文件路径：优先 SSHS_MASTER_KEY_FILE，
// 否则使用用户配置目录下的 sshs/master-key（Linux 上即 ~/.config/sshs/master-key）。
func MasterKeyFilePath() (string, error) {
	if path := strings.TrimSpace(os.Getenv(masterKeyFileEnv)); path != "" {
		return path, nil
	}
	return masterKeyFileResolver()
}

// readMasterKeyFile 读取主密码文件；文件不存在时返回空字符串，不视为错误。
// 权限对 group/others 开放的主密码文件会被拒绝使用，避免凭据被静默泄露。
func readMasterKeyFile() (string, error) {
	path, err := MasterKeyFilePath()
	if err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("master key file %q is not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&0077 != 0 {
		return "", fmt.Errorf("master key file %q permissions %#o too open (expected 0600)", path, perm)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(content)), nil
}

// writeMasterKeyFile 以 0600 权限原子写入主密码文件，返回实际写入路径。
func writeMasterKeyFile(key string) (string, error) {
	path, err := MasterKeyFilePath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), keyDirPerm); err != nil {
		return "", err
	}
	if err := writeFileAtomic(path, []byte(key+"\n"), keyFilePerm); err != nil {
		return "", err
	}
	return path, nil
}

// deleteMasterKeyFile 删除主密码文件；文件不存在时视为成功。
func deleteMasterKeyFile() error {
	path, err := MasterKeyFilePath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// LoadMasterKey 按优先级静默读取主密码：SSHS_MASTER_KEY 环境变量 → 系统钥匙串 → 主密码文件。
// 全部未配置时返回空字符串；本函数绝不交互提示，供自动加密、doctor 等后台流程使用。
func LoadMasterKey() (string, masterKeySource) {
	if key := strings.TrimSpace(os.Getenv(masterKeyEnv)); key != "" {
		return key, masterKeySourceEnv
	}
	return loadPersistedMasterKey()
}

// loadPersistedMasterKey 从持久化后端（系统钥匙串 → 主密码文件）读取主密码。
// 自动加密只认可持久化来源，避免临时注入的 SSHS_MASTER_KEY 把配置加密成其他环境无法解密的内容。
func loadPersistedMasterKey() (string, masterKeySource) {
	if key, err := GetKeyringMasterKey(); err == nil && key != "" {
		return key, masterKeySourceKeyring
	}
	if key, err := readMasterKeyFile(); err == nil && key != "" {
		return key, masterKeySourceFile
	}
	return "", masterKeySourceNone
}

// SaveMasterKey 持久化主密码：显式设置 SSHS_MASTER_KEY_FILE 时只写文件；
// 否则优先写入系统钥匙串，不可用时降级写入 0600 文件。
// 返回来源与文件路径（文件后端时非空）。
func SaveMasterKey(key string) (masterKeySource, string, error) {
	if key == "" {
		return masterKeySourceNone, "", errors.New("master key cannot be empty")
	}
	if strings.TrimSpace(os.Getenv(masterKeyFileEnv)) != "" {
		path, err := writeMasterKeyFile(key)
		if err != nil {
			return masterKeySourceNone, "", fmt.Errorf("save master key to file: %w", err)
		}
		setCachedMasterKey(key)
		return masterKeySourceFile, path, nil
	}
	keyringErr := SetKeyringMasterKey(key)
	if keyringErr == nil {
		return masterKeySourceKeyring, "", nil
	}
	path, err := writeMasterKeyFile(key)
	if err != nil {
		return masterKeySourceNone, "", fmt.Errorf("save master key: keyring: %v; file: %w", keyringErr, err)
	}
	setCachedMasterKey(key)
	return masterKeySourceFile, path, nil
}

// DeleteMasterKey 清除已持久化的主密码（系统钥匙串与主密码文件都会尝试删除）。
// 通过 SSHS_MASTER_KEY 注入的主密码不落盘，无法在此删除。
func DeleteMasterKey() error {
	setCachedMasterKey("")
	keyringErr := DeleteKeyringMasterKey()
	fileErr := deleteMasterKeyFile()
	if fileErr == nil || keyringErr == nil {
		return nil
	}
	return fmt.Errorf("delete master key: keyring: %v; file: %v", keyringErr, fileErr)
}

// ResolveMasterKey 获取用于解密的主密码：
// 1. 进程内内存缓存
// 2. 环境变量 / 系统钥匙串 / 主密码文件
// 3. 交互终端下无回显提示输入，并持久化到可用后端
// 无交互终端且未配置主密码时返回带操作指引的错误，绝不阻塞等待输入。
func ResolveMasterKey() (string, error) {
	if key := getCachedMasterKey(); key != "" {
		return key, nil
	}

	if key, _ := LoadMasterKey(); key != "" {
		setCachedMasterKey(key)
		return key, nil
	}

	stdinFd := int(syscall.Stdin)
	if !stdinTerminalCheck(stdinFd) {
		return "", fmt.Errorf("master key is not configured: run 'sshs master-key set' in an interactive terminal, or provide %s / %s", masterKeyEnv, masterKeyFileEnv)
	}

	key, err := readPasswordFromTerminal(stdinFd, "Enter Master Password: ")
	if err != nil {
		return "", err
	}
	if _, _, saveErr := SaveMasterKey(key); saveErr != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to save master key: %v\n", saveErr)
	}
	setCachedMasterKey(key)
	return key, nil
}

// readPasswordFromTerminal 从终端无回显读取一次主密码，提示信息输出到 stderr 以免污染 stdout 管道。
func readPasswordFromTerminal(fd int, prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	passwordBytes, err := terminalPasswordReader(fd)
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

// readConfirmedPassword 连续读取两次主密码并要求一致，用于首次设置。
func readConfirmedPassword(fd int) (string, error) {
	first, err := readPasswordFromTerminal(fd, "Enter Master Password: ")
	if err != nil {
		return "", err
	}
	second, err := readPasswordFromTerminal(fd, "Confirm Master Password: ")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", errors.New("master passwords do not match")
	}
	return first, nil
}

// readMasterKeyFromStdin 从非终端 stdin（管道或重定向）读取主密码，供自动化场景使用。
// 第二个返回值表示 stdin 是否为管道/重定向数据；终端输入返回 false，交由交互提示处理。
func readMasterKeyFromStdin() (string, bool, error) {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return "", false, fmt.Errorf("stat stdin: %w", err)
	}
	if stat.Mode()&os.ModeCharDevice != 0 {
		return "", false, nil
	}
	content, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
	if err != nil {
		return "", false, fmt.Errorf("read master password from stdin: %w", err)
	}
	masterKey := strings.TrimSpace(string(content))
	if masterKey == "" {
		return "", false, errors.New("master password from stdin cannot be empty")
	}
	return masterKey, true, nil
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

// EnsureMasterKey 确保进程内已加载主密码。
// 交互终端下首次运行且未配置主密码时，强制提示设置并持久化（沿用原有安全设计）；
// 非交互环境（脚本、Agent、无 TTY 的 SSH 命令）静默跳过，把主密码需求推迟到真正解密或编辑时，
// 避免在没有系统钥匙串的 Linux 服务器上阻塞所有命令。
func EnsureMasterKey() error {
	if getCachedMasterKey() != "" {
		return nil
	}

	if key, _ := LoadMasterKey(); key != "" {
		setCachedMasterKey(key)
		return nil
	}

	stdinFd := int(syscall.Stdin)
	if !stdinTerminalCheck(stdinFd) {
		return nil
	}

	fmt.Fprintln(os.Stderr, "Master key is not configured. Please set it first:")
	key, err := readConfirmedPassword(stdinFd)
	if err != nil {
		return err
	}

	source, location, saveErr := SaveMasterKey(key)
	if saveErr != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to save master key: %v\n", saveErr)
	} else if source == masterKeySourceFile {
		fmt.Fprintf(os.Stderr, "Master key saved to %s (mode 0600).\n", location)
	} else {
		fmt.Fprintln(os.Stderr, "Master key saved to system keyring.")
	}

	setCachedMasterKey(key)
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
	return readPasswordFromTerminal(stdinFd, "Enter Master Password: ")
}

