package mobile

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// 生成随机盐值
func MakeSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	return salt, nil
}

func HashPassowrd(password string, salt []byte) string {
	// 将密码和盐值拼接起来
	saltedPassword := []byte(password + hex.EncodeToString(salt))

	// 使用 sha256 哈希函数进行加密
	hash := sha256.Sum256(saltedPassword)

	// 将哈希值转换成十六进制字符串
	hashString := hex.EncodeToString(hash[:])
	return hashString
}
