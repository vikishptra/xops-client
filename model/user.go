package model

import (
	"fmt"
	"time"

	"github.com/go-playground/validator"
)

type User struct {
	Id                   string                 `gorm:"type:varchar(100);primary_key;not null" json:"id"`
	Name                 string                 `gorm:"type:varchar(100);not null;"`
	Email                string                 `gorm:"type:varchar(100);not null;uniqueIndex;" json:"email" `
	Password             string                 `gorm:"type:varchar(100);not null" json:"password"`
	IdRole               int                    `gorm:"type:varchar(50);not null"`
	IsVerified           bool                   `gorm:"not null;default:true"`
	IsTwoFA              bool                   `gorm:"not null; default:false" json:"is_2fa"`
	VerifiedCode         string                 `gorm:"type:varchar(100);not null" json:"verified_code"`
	TOTPKey              string                 `gorm:"type:varchar(255)" json:"totp_key"`
	RefreshToken         string                 `gorm:"type:text" json:"token"`
	ApiKey               string                 `gorm:"type:text" json:"api_key"`
	ActivityLogPentester []ActivityLogPentester `gorm:"foreignKey:IdUser;constraint:OnDelete:CASCADE"`
	Client               []Client               `gorm:"foreignKey:IdUser;constraint:OnDelete:CASCADE"`
	CreatedAt            time.Time              `gorm:"not null;default:now()"`
	UpdatedAt            time.Time              `gorm:"not null;defauslt:now()"`
}

var validate = validator.New()
var customMessages = map[string]string{
	"Code.required": "Verification code is required. Please enter it to continue",
}

type UserResponse struct {
	ID          string    `json:"id"`
	Email       string    `json:"email"`
	Username    string    `json:"username"`
	Verified    bool      `json:"verified"`
	IconProfile string    `json:"icon_profile"`
	ApiKey      string    `json:"api_key"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func ConvertUser(user *User) UserResponse {
	return UserResponse{
		ID:        user.Id,
		Email:     user.Email,
		Verified:  user.IsVerified,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
}

func ValidateStruct[T any](payload T) []string {
	var message []string
	err := validate.Struct(payload)

	if err != nil {
		for _, fieldErr := range err.(validator.ValidationErrors) {
			key := fmt.Sprintf("%s.%s", fieldErr.Field(), fieldErr.Tag())
			if msg, exists := customMessages[key]; exists {
				message = append(message, msg)
			} else {
				messagesss := fieldErr.Namespace() + " " + fieldErr.Tag()
				message = append(message, messagesss)
			}

		}
	}
	return message
}
