package http

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"

	"auth/internal/modules/auth/domain"
	"auth/internal/modules/auth/infra" // in-memory
	pg "auth/internal/modules/auth/infra/pg"
	plathttp "auth/internal/platform/http"
	"auth/internal/platform/notify"
	"auth/internal/platform/security"
)

// Module wires up dependencies for the auth HTTP module.
type Module struct {
	userRepo    domain.UserRepo
	codeRepo    domain.CodeRepo
	sessionRepo domain.SessionRepo
	jwtSecret   []byte
	accessTTL   time.Duration

	mailer *notify.Mailer // << добавили
}

func (m *Module) WithMailer(ma *notify.Mailer) *Module {
	m.mailer = ma
	return m
}

func NewModule() *Module {
	return &Module{
		userRepo:    infra.NewMemUserRepo(),
		codeRepo:    infra.NewMemCodeRepo(),
		sessionRepo: infra.NewMemSessionRepo(),
		jwtSecret:   []byte("super-secret"),
		accessTTL:   15 * time.Minute,
	}
}

// NewModulePG creates PG-based repos.
func NewModulePG(db *pgxpool.Pool, jwtSecret string, accessTTL time.Duration) *Module {
	if accessTTL == 0 {
		accessTTL = 15 * time.Minute
	}
	return &Module{
		userRepo:    pg.NewUserRepo(db),
		codeRepo:    pg.NewCodeRepo(db),
		sessionRepo: pg.NewSessionRepo(db),
		jwtSecret:   []byte(jwtSecret),
		accessTTL:   accessTTL,
	}
}

func (m *Module) Register(r fiber.Router) {
	jwtMgr := security.NewJWTManager(string(m.jwtSecret), m.accessTTL)

	// -------- public --------
	r.Post("/sign-up", SignUpHandler(m.userRepo, m.codeRepo))
	r.Post("/sign-up/confirm", SignUpConfirmHandler(m.userRepo, m.codeRepo))
	r.Post("/sign-up/resend", SignUpResendHandler(m.userRepo, m.codeRepo))
	r.Post("/sign-in", SignInHandler(m.userRepo, m.sessionRepo, jwtMgr))
	r.Post("/forgot-password", ForgotPasswordHandler(m.userRepo, m.codeRepo))
	r.Post("/forgot-password/resend", ForgotPasswordResendHandler(m.userRepo, m.codeRepo))
	r.Post("/reset-password", ResetPasswordHandler(m.userRepo, m.codeRepo, m.sessionRepo))
	// OAuth провайдер (один раз, без дубликатов)
	r.Post("/auth/:provider", OAuthSignInHandler(m.userRepo, m.sessionRepo, jwtMgr))
	r.Post("/refresh", RefreshHandler(m.sessionRepo, jwtMgr))

	// -------- protected --------
	protected := r.Group("", plathttp.JWTAuth(m.jwtSecret))
	protected.Get("/user/devices", ListDevicesHandler(m.sessionRepo))
	protected.Delete("/user/devices/:device_id", DeleteDeviceHandler(m.sessionRepo))
	protected.Delete("/user/devices/others", DeleteOtherDevicesHandler(m.sessionRepo))
	protected.Delete("/session", DeleteCurrentSessionHandler(m.sessionRepo))
	protected.Get("/user", GetProfileHandler(m.userRepo))
	protected.Patch("/user", UpdateProfileHandler(m.userRepo))
	protected.Delete("/user", DeleteUserHandler(m.userRepo))

	// -------- совместимость под /auth/* --------
	auth := r.Group("/auth")
	auth.Get("/ping", func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"module": "auth", "ok": true}) })
	auth.Post("/sign-up", SignUpHandler(m.userRepo, m.codeRepo))
	auth.Post("/sign-up/confirm", SignUpConfirmHandler(m.userRepo, m.codeRepo))
	auth.Post("/sign-up/resend", SignUpResendHandler(m.userRepo, m.codeRepo))
	auth.Post("/sign-in", SignInHandler(m.userRepo, m.sessionRepo, jwtMgr))
	auth.Post("/forgot-password", ForgotPasswordHandler(m.userRepo, m.codeRepo))
	auth.Post("/forgot-password/resend", ForgotPasswordResendHandler(m.userRepo, m.codeRepo))
	auth.Post("/reset-password", ResetPasswordHandler(m.userRepo, m.codeRepo, m.sessionRepo))
	auth.Post("/refresh", RefreshHandler(m.sessionRepo, jwtMgr))
	// тут НЕ дублируем /:provider второй раз
	authProtected := auth.Group("", plathttp.JWTAuth(m.jwtSecret))
	authProtected.Get("/user/devices", ListDevicesHandler(m.sessionRepo))
	authProtected.Get("/user/devices", ListDevicesHandler(m.sessionRepo))
	authProtected.Delete("/user/devices/:device_id", DeleteDeviceHandler(m.sessionRepo))
	authProtected.Delete("/user/devices/others", DeleteOtherDevicesHandler(m.sessionRepo))
	authProtected.Delete("/session", DeleteCurrentSessionHandler(m.sessionRepo))
	authProtected.Get("/user", GetProfileHandler(m.userRepo))
	authProtected.Patch("/user", UpdateProfileHandler(m.userRepo))
	authProtected.Delete("/user", DeleteUserHandler(m.userRepo))
}
