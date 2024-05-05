package nauth

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

type TokenData struct {
	Claims     map[string]string `json:"claims"`
	RandomSalt string            `json:"randomSalt"`
}

func (td *TokenData) Hash() (string, error) {
	// Generate a token using the claims and the random salt
	var hashString string

	// mapのkeyをソートして順番を固定
	claimKeys := make([]string, 0, len(td.Claims))
	for k := range td.Claims {
		claimKeys = append(claimKeys, k)
	}

	sort.Strings(claimKeys)
	for _, k := range claimKeys {
		hashString += fmt.Sprintf("%s=%s;", k, td.Claims[k])
	}

	hashString += td.RandomSalt

	hash := sha512.New384()
	hash.Write([]byte(hashString))
	checksum := hash.Sum(nil)

	return hex.EncodeToString(checksum), nil
}

func (td *TokenData) encrypt(secret string) (string, error) {
	// Encrypt the token using the environment secret
	jsonData, err := json.Marshal(td)
	if err != nil {
		return "", err
	}

	// Encrypt by AES256
	encryptedData, err := encrypt([]byte(secret), string(jsonData))
	if err != nil {
		return "", err
	}

	// decode with base64
	return base64.StdEncoding.EncodeToString(encryptedData), nil
}

func DecryptToken(token string, secret string) (TokenData, error) {
	// base64 decode
	decodedToken, err := base64.StdEncoding.DecodeString(token)

	decryptedJson, err := decrypt([]byte(secret), decodedToken)
	if err != nil {
		return TokenData{}, err
	}

	var tokenData TokenData
	err = json.Unmarshal([]byte(decryptedJson), &tokenData)
	if err != nil {
		return TokenData{}, err
	}

	return tokenData, nil
}

func GenerateToken(claims map[string]string, secret string) (string, string, error) {
	salt, err := generateRandomString(64)
	if err != nil {
		return "", "", err
	}

	data := TokenData{
		Claims:     claims,
		RandomSalt: salt,
	}

	checksum, err := data.Hash()
	if err != nil {
		return "", "", err
	}

	encryptedToken, err := data.encrypt(secret)
	if err != nil {
		return "", "", err
	}

	return encryptedToken, checksum, nil
}
