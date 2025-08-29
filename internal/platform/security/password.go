package security

import "github.com/alexedwards/argon2id"


func HashPassword(pw string) (string, error) {
	return argon2id.CreateHash(pw, argon2id.DefaultParams)
}
func CheckPassword(hash, pw string) (bool, error) {
	return argon2id.ComparePasswordAndHash(pw, hash)
}