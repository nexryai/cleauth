package cleauth

import (
	"testing"
)

func TestToken(t *testing.T) {
	claims := map[string]string{
		"username": "test",
		"password": "test",
	}

	// secretが不正なら弾かれる
	_, _, err := GenerateToken(claims, "UNSAFE_STRING")
	if err == nil {
		t.Error("Expected error: invalid secret")
	}

	secret, err := generateRandomString(32)
	if err != nil {
		t.Error(err)
	}

	encryptedToken, hash, err := GenerateToken(claims, secret)
	if err != nil {
		t.Error(err)
	} else {
		t.Log("Encrypted token: ", encryptedToken)
		t.Log("Hash: ", hash)
	}

	// secretが間違ってるなら弾かれる
	dummySecret, _ := generateRandomString(32)
	_, err = DecryptToken(encryptedToken, dummySecret)
	if err == nil {
		t.Error("Expected error: invalid secret")
	}

	decryptedTokenData, err := DecryptToken(encryptedToken, secret)
	if err != nil {
		t.Error(err)
	}

	if decryptedTokenData.Claims["username"] != claims["username"] {
		t.Error("Username mismatch")
	}

	if decryptedTokenData.Claims["password"] != claims["password"] {
		t.Error("Password mismatch")
	}

	h, err := decryptedTokenData.Hash()
	if err != nil {
		t.Error(err)
	}

	if h != hash {
		t.Error("Hash mismatch: ", h, " != ", hash)
	} else {
		t.Log("Hash matched!")
	}
}
