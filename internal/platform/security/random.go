package security

import (
	"crypto/rand"
	"fmt"
)

func RandomDigits(n int) (string, error) {
	if n <= 0 {
		n = 6
	}
	// равномерно по [0..10^n-1]
	max := 1
	for i := 0; i < n; i++ {
		max *= 10
	}
	// берём достаточно байт и модулируем
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	// простая и достаточная для кода мод-редукция
	val := 0
	for _, b := range buf {
		val = (val<<8 + int(b)) % max
	}
	return fmt.Sprintf("%0*d", n, val), nil
}
