package api

import (
	"auth/models"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JwtAuth struct {
	Issuer            string
	TokenExpiry       time.Duration
	RefreshExpiry     time.Duration
	TokenRefreshCache map[string]JwtAuthCache
}

type JwtAuthCache struct {
	Count        int
	Secret       string
	RefreshToken string
}

// embeded jwt RegisteredClaims
type Claims struct {
	jwt.RegisteredClaims
}

func (j *JwtAuth) GenerateTopenPair(usr *models.User) (*models.TokenPairs, error) {
	usrID := usr.ID.Hex()

	//get cache key
	secret := j.TokenRefreshCache[usrID].Secret

	//create a token
	token := jwt.New(jwt.SigningMethodHS256)
	//set the claims
	claims := token.Claims.(jwt.MapClaims)
	claims["name"] = fmt.Sprintf("%s %s", usr.Profile.FisrtName, usr.Profile.LastNmae)
	claims["sub"] = usrID
	claims["aud"] = usr.UserAuth.Scope.Domain + "_" + usr.UserAuth.Scope.AppID
	claims["iss"] = j.Issuer
	claims["iat"] = time.Now().UTC().Unix()
	claims["typ"] = "JWT"

	//set expriry for JWT
	claims["exp"] = time.Now().UTC().Add(j.TokenExpiry).Unix()
	//create singed token
	signedAccessToken, err := token.SignedString([]byte(secret))
	if err != nil {
		log.Println(err)
		return nil, err
	}

	//create a refresh token and set clailms
	refreshToken := jwt.New(jwt.SigningMethodHS256)
	refreshClaims := refreshToken.Claims.(jwt.MapClaims)
	refreshClaims["sub"] = usr.ID.Hex()
	refreshClaims["iat"] = time.Now().UTC().Unix()
	refreshClaims["iss"] = j.Issuer
	//set the expiry for the refresh token
	refreshClaims["exp"] = time.Now().UTC().Add(j.RefreshExpiry).Unix()
	//create signed refresh token
	signedRefreshAccessToken, err := refreshToken.SignedString([]byte(secret))
	if err != nil {
		return nil, err
	}

	//create toke pairs with signed tokens
	var tokenPairs = models.TokenPairs{
		Token:        models.Token{PlainText: signedAccessToken, Expiry: j.TokenExpiry / time.Minute},
		RefreshToken: models.Token{PlainText: signedRefreshAccessToken, Expiry: j.RefreshExpiry / time.Hour},
	}
	//return token pairs

	return &tokenPairs, nil
}

func (j *JwtAuth) GetTokenFromHeaderAndVerify(w http.ResponseWriter, r *http.Request) (string, jwt.MapClaims, error) {
	w.Header().Add("Vary", "Authorization")

	//get auth herader
	authHeader := r.Header.Get("Authorization")

	//sanity check
	if authHeader == "" {
		return "", nil, errors.New("no auth")
	}

	//slpit the header
	headerParts := strings.Split(authHeader, " ")

	if len(headerParts) != 2 {
		return "", nil, errors.New("invalid auth header")
	}

	//check start
	if headerParts[0] != "Bearer" {
		return "", nil, errors.New("invalid auth header")
	}

	tokenStr := headerParts[1]

	token, _, err := new(jwt.Parser).ParseUnverified(tokenStr, jwt.MapClaims{})

	if err != nil {
		if strings.HasPrefix(err.Error(), "token is expired by") {
			return "", nil, errors.New("expired token")
		}

		return "", nil, err
	}

	jwtClaims, ok := token.Claims.(jwt.MapClaims)

	if !ok {
		return "", nil, err
	}

	exp := jwtClaims["exp"].(float64)

	if exp < float64(time.Now().UTC().Unix()) {
		return "", nil, errors.New("token is expired")
	}

	if jwtClaims["iss"] != j.Issuer {
		return "", nil, errors.New("invalid issuer")
	}

	//good token
	return tokenStr, jwtClaims, nil
}

// chache clean up
func (j *JwtAuth) CleanCache() {
	for {
		for k := range j.TokenRefreshCache {
			delete(j.TokenRefreshCache, k)
		}
		time.Sleep(24 * time.Hour)
	}
}

func (j *JwtAuth) CleanCacheWorker() {
	go j.CleanCache()
}
