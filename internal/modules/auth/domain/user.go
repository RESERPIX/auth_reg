package domain

import "time"

type Role string

const (
	RoleJournalist Role = "journalist"
	RoleGuide      Role = "guide"
	RoleRestaurant Role = "restaurant"
)

type User struct {
	ID             string
	Email          string
	Phone          *string
	FirstName      string
	LastName       string
	Role           Role
	PasswordHash   *string
	EmailConfirmed bool
	PhoneConfirmed bool
	IsBlocked      bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
	Providers      []string
}

type CreateUserParams struct {
	Email        string
	Phone        *string
	FirstName    string
	LastName     string
	Role         Role
	PasswordHash *string
}

type UserRepo interface {
	Create(u CreateUserParams) (*User, error)
	GetByEmail(email string) (*User, error)
	ExistsByEmail(email string) (bool, error)
	ConfirmEmail(userID string) error
	UpdatePassword(userID string, newHash string) error

	// НОВОЕ:
	GetByID(id string) (*User, error)
	UpdateProfile(userID string, firstName *string, lastName *string, phone *string) error
	Delete(id string) error
}
