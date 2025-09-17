package postgres

import (
	"math/rand"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"xops-admin/domain"
	domain_user_auth "xops-admin/domain/user/auth"
	"xops-admin/helper/errorenum"
	"xops-admin/model"
	util_apikey "xops-admin/util/api_key"
	util_encode "xops-admin/util/encode"
)

type UserRepo struct {
	db *gorm.DB
}

func (u *UserRepo) CreateUser(req *domain_user_auth.CreateUserWithClientRequest) error {
	// Start transaction
	tx := u.db.Begin()
	if tx.Error != nil {
		return errorenum.SomethingError
	}

	// Rollback transaction on error
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Generate UUID for User
	userId := uuid.New().String()

	// Create User
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	rand.Seed(time.Now().UnixNano())

	b := make([]rune, 10)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return errorenum.SomethingError
	}
	user := &model.User{
		Id:           userId,
		Name:         string(b),
		Email:        req.Email,
		Password:     string(hashedPassword),
		IdRole:       req.IdRole,
		IsVerified:   req.IsVerified,
		IsTwoFA:      req.IsTwoFA,
		VerifiedCode: "-",
		TOTPKey:      "-",
		RefreshToken: "-",
		ApiKey:       util_apikey.GenerateSecureAPIKey(),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := tx.Create(user).Error; err != nil {
		tx.Rollback()
		databaseError := err.Error()
		if strings.Contains(databaseError, "duplicate key value violates unique") {
			return errorenum.DuplicateEmail
		}
		return errorenum.SomethingError
	}

	if req.IdRole == 3 {
		// Generate UUID for Client
		clientId := uuid.New().String()

		// Create Client
		client := &model.Client{
			Id:          clientId,
			IdUser:      userId,
			LogoCompany: req.LogoCompany,
			CompanyName: req.CompanyName,
			StartDate:   req.StartDate,
			EndDate:     req.EndDate,
		}

		if err := tx.Create(client).Error; err != nil {
			tx.Rollback()
			return errorenum.SomethingError
		}

		// Create DomainClient entries
		for _, domain := range req.Domains {
			domainClient := &model.DomainClient{
				Id:        uuid.New().String(),
				IdClient:  clientId,
				Domain:    domain,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}

			if err := tx.Create(domainClient).Error; err != nil {
				tx.Rollback()
				return errorenum.SomethingError
			}
		}
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		return errorenum.SomethingError
	}

	return nil
}

func (u *UserRepo) DeleteUser(id string) error {
	if result := u.db.Where("id = ?", id).Delete(&model.User{}); result.RowsAffected == 0 {
		return errorenum.DataNotFound
	}

	return nil
}

func (u *UserRepo) FindUserBYEmail(email string) (*model.User, error) {
	var user model.User
	if err := u.db.First(&user, "email = ?", strings.ToLower(email)); err.RowsAffected == 0 {
		return nil, errorenum.DataNotFound
	}
	return &user, nil
}

func (u *UserRepo) FindUserBYID(id string) (*model.User, error) {
	var user model.User
	if err := u.db.First(&user, "id = ?", id); err.RowsAffected == 0 {
		return nil, errorenum.DataNotFound
	}
	return &user, nil
}
func (u *UserRepo) FindUserBYName(name string) (*model.User, error) {
	var user model.User
	if err := u.db.First(&user, "name = ?", strings.ToUpper(name)); err.RowsAffected == 0 {
		return nil, errorenum.DataNotFound
	}
	return &user, nil
}

func (u *UserRepo) UpdateUser(user *model.User) error {
	if err := u.db.Save(user).Error; err != nil {
		return errorenum.SomethingError
	}
	return nil
}

func (u *UserRepo) UserVerifyEmail(idUser, code string, duration int64) (*model.User, error) {

	userDb, err := u.FindUserBYID(idUser)
	if err != nil {
		return nil, errorenum.FailedOtp
	}
	if !userDb.IsVerified {
		return nil, errorenum.FailedLogin
	}
	verification_code := util_encode.Encode(code)
	if err := u.db.First(userDb, "verified_code = ?", verification_code); err.RowsAffected == 0 {
		return nil, errorenum.FailedOtp
	}
	currentTime := time.Now()
	then := userDb.UpdatedAt.Add(time.Minute * time.Duration(duration))

	if currentTime.After(then) {
		return nil, errorenum.ExpiredOtp
	}
	userDb.UpdatedAt = time.Now()
	userDb.VerifiedCode = ""

	return userDb, nil
}

func NewUserRepo(db *gorm.DB) domain.UserRepository {
	return &UserRepo{
		db: db,
	}
}
