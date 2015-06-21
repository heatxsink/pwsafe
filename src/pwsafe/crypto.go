package pwsafe

import "crypto/sha256"

// Compute stretched key similar to how PBKDF works
func computeStretchKey(salt, password []byte, iterations int) []byte {
	sha := sha256.New()

	sha.Write(password)
	sha.Write(salt)

	xi := sha.Sum(nil)

	for j := 0; j < iterations; j++ {
		result := sha256.Sum256(xi)
		xi = result[:]
	}
	return xi
}
