package util_jwttoken

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"

	util_uuid "xops-admin/util/uuid"
)

type TokenDetails struct {
	Token     *string
	TokenUuid string
	UserID    string
	ExpiresIn *int64
}

func GenerateTokenJwt(jwtTokenTime time.Duration, userID string, privateKey string) (*TokenDetails, error) {
	time := time.Now()
	tokenDetail := &TokenDetails{
		ExpiresIn: new(int64),
		Token:     new(string),
	}
	*tokenDetail.ExpiresIn = time.Add(jwtTokenTime).Unix()
	tokenDetail.TokenUuid = util_uuid.GenerateID()
	tokenDetail.UserID = userID
	//decode privatekey base64
	decodedPrivateKey, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("err: %w", err)
	}
	//verifikasi lewat rsa
	key, err := jwt.ParseRSAPrivateKeyFromPEM(decodedPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("err: %w", err)
	}

	atClaims := make(jwt.MapClaims)
	atClaims["sub"] = userID
	atClaims["token_uuid"] = tokenDetail.TokenUuid
	atClaims["exp"] = tokenDetail.ExpiresIn
	atClaims["iat"] = time.Unix()
	atClaims["nbf"] = time.Unix()

	*tokenDetail.Token, err = jwt.NewWithClaims(jwt.SigningMethodRS256, atClaims).SignedString(key)
	if err != nil {
		return nil, fmt.Errorf("create: sign token: %w", err)
	}

	return tokenDetail, nil
}

func ValidateToken(token string, publicKey string) (*TokenDetails, error) {
	decodedPublicKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, fmt.Errorf("err: %w", err)
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(decodedPublicKey)

	if err != nil {
		return nil, fmt.Errorf("err : %w", err)
	}

	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("err : %s", t.Header["alg"])
		}
		return key, nil
	})

	if err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		return nil, fmt.Errorf("validate: invalid token")
	}

	return &TokenDetails{
		TokenUuid: fmt.Sprint(claims["token_uuid"]),
		UserID:    fmt.Sprint(claims["sub"]),
	}, nil
}
