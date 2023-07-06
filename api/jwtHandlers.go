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

func (app *Application) JwtAuthentication(w http.ResponseWriter, r *http.Request) {
	var user models.User
	err := app.readJSON(w, r, &user)

	if err != nil {
		log.Println(err.Error())
		app.errorJSON(w, err, http.StatusBadRequest)
		return
	}

	err = app.Validator.Struct(user)

	if err != nil {
		log.Println(err.Error())
		app.errorJSON(w, err, http.StatusBadRequest)
		return
	}
	//validate input secret key name
	if user.ThirdPartySecrets[0].KeyName == "" {
		app.errorJSON(w, errors.New("secret key name is required"), http.StatusBadRequest)
		return
	}

	//validateuser
	usr, userID, err := app.DB.ValidUserByLonginUser(&user.UserAuth)

	if err != nil {
		app.errorJSON(w, err, http.StatusBadRequest)
		return
	}

	//get jwt secret
	secretKey, err := app.DB.GetJwtSecret(userID, user.ThirdPartySecrets[0].KeyName)

	if err != nil {
		app.errorJSON(w, err, http.StatusBadRequest)
		return
	}

	secretKey = app.Decrypt(app.Domain+app.AppID, secretKey)

	app.JwtAuth.TokenRefreshCache[userID] = JwtAuthCache{
		Secret: secretKey,
		Count:  0,
	}

	//init jwt
	app.JwtAuth.TokenExpiry = time.Minute * 15
	app.JwtAuth.RefreshExpiry = time.Hour * 24

	tokens, err := app.JwtAuth.GenerateTopenPair(usr)

	if err != nil {
		app.errorJSON(w, err, http.StatusBadRequest)
		return
	}

	jwtAuthCatch := app.JwtAuth.TokenRefreshCache[userID]
	jwtAuthCatch.RefreshToken = tokens.Token.PlainText

	app.JwtAuth.TokenRefreshCache[userID] = jwtAuthCatch

	if err != nil {
		app.errorJSON(w, err, http.StatusBadRequest)
		return
	}

	resp := JSONResponse{

		Error:   false,
		Message: "jwt token",
		Data:    tokens,
	}
	app.writeJSON(w, http.StatusOK, resp)
}

func (app *Application) RegisterJwt(w http.ResponseWriter, r *http.Request) {
	updateJwtRegister(w, r, app, app.DbOperations.Create)
}

func (app *Application) UpdateJwtRegister(w http.ResponseWriter, r *http.Request) {
	updateJwtRegister(w, r, app, app.DbOperations.Update)
}

func updateJwtRegister(w http.ResponseWriter, r *http.Request, app *Application, operation string) {
	var user models.User
	err := app.readJSON(w, r, &user)

	if err != nil {
		log.Println(err.Error())
		app.errorJSON(w, err, http.StatusBadRequest)
		return
	}

	err = app.Validator.Struct(user)

	if err != nil {
		log.Println(err.Error())
		app.errorJSON(w, err, http.StatusBadRequest)
		return
	}

	if len(user.ThirdPartySecrets) != 1 {
		app.errorJSON(w, errors.New("missed required field or too many secrets"), http.StatusBadRequest)
		return
	}

	if user.ThirdPartySecrets[0].KeyName == "" {
		app.errorJSON(w, errors.New("missed required field"), http.StatusBadRequest)
		return
	}

	if operation == app.DbOperations.Create && user.ThirdPartySecrets[0].KeyValue == "" {
		app.errorJSON(w, errors.New("missed required field"), http.StatusBadRequest)
		return
	}

	user.ThirdPartySecrets[0].KeyValue = app.Encrypt(app.Domain+app.AppID, user.ThirdPartySecrets[0].KeyValue)

	//validate user
	userDetails, usrID, err := app.DB.ValidUserByLonginUser(&user.UserAuth)

	if err != nil {
		app.errorJSON(w, err, http.StatusBadRequest)
		return
	}

	//only admin user can register key
	if userDetails.UserAuth.Scope.Role.RoleNmae != "admin_user" {
		app.errorJSON(w, errors.New("not admin user"), http.StatusBadRequest)
		return
	}

	res, err := app.DB.UpdateThirdPartySecretsByID(usrID, user.ThirdPartySecrets, operation)

	if err != nil {
		log.Println(err.Error())
		app.errorJSON(w, err, http.StatusBadRequest)
		return
	}

	var msg string

	if operation == app.DbOperations.Create {
		msg = "jwt registed"
	} else if operation == app.DbOperations.Update {
		msg = "jwt udupated"
	}

	resp := JSONResponse{
		Error:   false,
		Message: msg,
		Data:    res,
	}

	app.writeJSON(w, http.StatusOK, resp)
}

func (app *Application) TestJwt(w http.ResponseWriter, r *http.Request) {

	log.Println("here")
}

func (app *Application) RefreshJwtauth(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("userID")

	authHeader := r.Header.Get("Authorization")

	//slpit the header
	headerParts := strings.Split(authHeader, " ")

	refreshtokenStr := headerParts[1]

	secret := app.JwtAuth.TokenRefreshCache[userID].Secret

	//parse token
	jwtRefreshToken, err := jwt.Parse(refreshtokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(secret), nil
	})

	if err != nil {
		app.errorJSON(w, err, http.StatusExpectationFailed)
		return
	}

	//
	jwtCache := app.JwtAuth.TokenRefreshCache[userID]

	refcnt := jwtCache.Count

	if err != nil {
		app.errorJSON(w, errors.New("refresh token expiried"), http.StatusExpectationFailed)
		return
	}

	if refcnt > app.MaxRefreshToken {
		//remove the cache
		delete(app.JwtAuth.TokenRefreshCache, userID)
		app.errorJSON(w, errors.New("refresh token expiried"), http.StatusExpectationFailed)
		return
	}

	origToken := app.JwtAuth.TokenRefreshCache[userID].RefreshToken

	origJwtToken, err := jwt.Parse(origToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(secret), nil
	})

	if err != nil {
		app.errorJSON(w, err, http.StatusExpectationFailed)
		return
	}

	origJwtClaims := origJwtToken.Claims.(jwt.MapClaims)

	origJwtClaims["iat"] = time.Now().UTC().Unix()

	//set expriry for JWT
	origJwtClaims["exp"] = time.Now().UTC().Add(app.JwtAuth.TokenExpiry).Unix()
	//create singed token
	signedAccessToken, err := origJwtToken.SignedString([]byte(secret))

	if err != nil {
		app.errorJSON(w, err, http.StatusExpectationFailed)
		return
	}

	jwtCache.RefreshToken = signedAccessToken

	jwtCache.Count += 1
	app.JwtAuth.TokenRefreshCache[userID] = jwtCache

	signedRefreshAccessToken, err := jwtRefreshToken.SignedString([]byte(secret))
	if err != nil {
		app.errorJSON(w, err, http.StatusExpectationFailed)
		return
	}

	//create toke pairs with signed tokens
	var tokenPairs = models.TokenPairs{
		Token:        models.Token{PlainText: signedAccessToken, Expiry: app.JwtAuth.TokenExpiry / time.Minute},
		RefreshToken: models.Token{PlainText: signedRefreshAccessToken, Expiry: app.JwtAuth.RefreshExpiry / time.Hour},
	}

	resp := JSONResponse{

		Error:   false,
		Message: "jwt token",
		Data:    tokenPairs,
	}
	app.writeJSON(w, http.StatusOK, resp)
}
