package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/subannn/auth/config"
	"github.com/subannn/auth/models"

	"github.com/golang-jwt/jwt/v4"
)

func GenerateJWTs(user models.User, accessExp, refreshExp int) (string, string, error) {
	accessToken, err := CreateAccessToken(user, accessExp)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := createRefreshToken(user, refreshExp)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func CreateAccessToken(user models.User, accessExp int) (string, error) {
	accessClaims := jwt.MapClaims{
		"Name":    user.Name,
		"Surname": user.Surname,
		"Email":   user.Email,
		"exp":     time.Now().Add(time.Duration(accessExp) * time.Minute).Unix(),
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(config.JWTCfg.SecretKey)
	if err != nil {
		return "", err
	}

	return accessTokenString, err
}

func createRefreshToken(user models.User, refreshExp int) (string, error) {
	refreshClaims := jwt.MapClaims{
		"Name":    user.Name,
		"Surname": user.Surname,
		"Email":   user.Email,
		"exp":     time.Now().Add(time.Duration(refreshExp) * time.Minute).Unix(),
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(config.JWTCfg.SecretKey)
	if err != nil {
		return "", err
	}

	return refreshTokenString, nil
}

func ValidateToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return config.JWTCfg.SecretKey, nil
	})

	if err != nil {
		return nil, errors.New("Can not parse token")
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Проверка на истечение срока действия (exp claim)
		if exp, ok := claims["exp"].(float64); ok && time.Unix(int64(exp), 0).After(time.Now()) {
			return claims, nil
		}
		return nil, errors.New("Token expired")
	}

	return nil, errors.New("Invalid token")
}

func MapClaimsToUser(claims jwt.MapClaims) (*models.User, error) {
	name, ok := claims["Name"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid claim: Name")
	}

	surname, ok := claims["Surname"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid claim: Surname")
	}

	email, ok := claims["Email"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid claim: Email")
	}

	return &models.User{
		Name:    name,
		Surname: surname,
		Email:   email,
	}, nil
}
