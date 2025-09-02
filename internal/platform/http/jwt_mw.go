package http

import (
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

func JWTAuth(secret []byte) fiber.Handler {
	return func(c *fiber.Ctx) error {
		h := c.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error_code": "UNAUTHORIZED",
				"message":    "Требуется авторизация",
			})
		}
		tokenStr := strings.TrimPrefix(h, "Bearer ")
		tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			// Ensure token uses an expected signing method (HMAC family)
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return secret, nil
		})
		if err != nil || !tok.Valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error_code": "UNAUTHORIZED",
				"message":    "Требуется авторизация",
			})
		}
		claims, ok := tok.Claims.(jwt.MapClaims)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error_code": "UNAUTHORIZED",
				"message":    "Требуется авторизация",
			})
		}
		if sub, _ := claims["sub"].(string); sub != "" {
			c.Locals("user_id", sub)
		}
		if role, _ := claims["role"].(string); role != "" {
			c.Locals("role", role)
		}
		if sid, _ := claims["sid"].(string); sid != "" {
			c.Locals("session_id", sid)
		}

		return c.Next()
	}
}
