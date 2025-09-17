package util_password

import (
	"math/rand"
	"time"
)

func GeneratePassword() string {
	const (
		upper    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lower    = "abcdefghijklmnopqrstuvwxyz"
		digits   = "0123456789"
		special  = "!@#$%^&*"
		allChars = upper + lower + digits + special
	)

	rand.Seed(time.Now().UnixNano())

	password := make([]byte, 8)

	// Pastikan ada 1 huruf besar dan 1 karakter spesial
	password[0] = upper[rand.Intn(len(upper))]
	password[1] = special[rand.Intn(len(special))]

	// Sisa karakter diisi acak dari semua jenis karakter
	for i := 2; i < 8; i++ {
		password[i] = allChars[rand.Intn(len(allChars))]
	}

	// Acak urutan password biar nggak selalu huruf besar di depan
	rand.Shuffle(len(password), func(i, j int) {
		password[i], password[j] = password[j], password[i]
	})

	return string(password)
}
