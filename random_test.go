package nauth

import (
	"math/rand"
	"testing"
)

func TestGenerateRandomString(t *testing.T) {
	// ランダムな長さ
	length := rand.Intn(256)

	randomString, err := generateRandomString(length)
	if err != nil {
		t.Error(err)
	}

	if len(randomString) != length {
		t.Error("Length mismatch")
	}
}
