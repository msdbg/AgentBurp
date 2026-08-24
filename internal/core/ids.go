package core

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func NewID(prefix string) string {
	return prefix + "_" + nanoid(12)
}

func nanoid(n int) string {
	result := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(fmt.Sprintf("crypto/rand failure during ID generation: %v", err))
		}
		result[i] = alphabet[idx.Int64()]
	}
	return string(result)
}

func TimestampNow() string {
	return time.Now().UTC().Format(time.RFC3339)
}
func ParsePrefix(id string) (string, error) {
	parts := strings.SplitN(id, "_", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid id format: %q (expected prefix_nanoid)", id)
	}
	return parts[0], nil
}

func ShortID(id string) string {
	if len(id) > 16 {
		return id[:16] + "…"
	}
	return id
}
