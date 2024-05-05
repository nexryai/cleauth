package nauth

import "testing"

func TestEncryptAndDecrypt(t *testing.T) {
	secret, err := generateRandomString(32)
	if err != nil {
		t.Error(err)
	}

	plaintext := "Birds are born with no shackles"

	ciphertext, err := encrypt([]byte(secret), plaintext)
	if err != nil {
		t.Error(err)
	}

	decrypted, err := decrypt([]byte(secret), ciphertext)
	if err != nil {
		t.Error(err)
	}

	if decrypted != plaintext {
		t.Error("Decrypted text mismatch")
	}
}
