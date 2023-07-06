package api

import (
	"auth/models"
	"log"
	"net/http"

	"github.com/pkg/errors"
)

func (app *Application) Signin(w http.ResponseWriter, r *http.Request) {
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

	ok, err := app.DB.IsUserLoninIdUnique(&user.UserAuth)

	if err != nil {
		log.Println(err.Error())
		app.errorJSON(w, err, http.StatusBadRequest)
		return
	}

	if !ok {
		err := errors.New("user id is not unique.")
		app.errorJSON(w, err, http.StatusBadRequest)
		return
	}

	user.ThirdPartySecrets = []models.ThirdPartySecret{}

	result, err := app.DB.CreateUser(&user)

	if err != nil {
		log.Println(err.Error())
		app.errorJSON(w, err, http.StatusBadRequest)
	}

	resp := JSONResponse{
		Error:   false,
		Message: "user created",
		Data:    result,
	}

	app.writeJSON(w, http.StatusOK, resp)
}

func (app *Application) Login(w http.ResponseWriter, r *http.Request) {
	var userAuth models.UserAuth
	err := app.readJSON(w, r, &userAuth)

	if err != nil {
		log.Println(err.Error())
		app.errorJSON(w, err, http.StatusBadRequest)
		return
	}

	err = app.Validator.Struct(userAuth)

	if err != nil {
		log.Println(err.Error())
		app.errorJSON(w, err, http.StatusBadRequest)
		return
	}

	dbuser, _, err := app.DB.ValidUserByLonginUser(&userAuth)

	if err != nil {
		log.Println(err.Error())
		app.errorJSON(w, err, http.StatusBadRequest)
		return
	}

	resp := JSONResponse{
		Error:   false,
		Message: "login succeed",
		Data:    dbuser,
	}

	app.writeJSON(w, http.StatusOK, resp)
}

func (app *Application) Health(w http.ResponseWriter, r *http.Request) {
	resp := JSONResponse{
		Error:   false,
		Message: "OK",
		Data:    nil,
	}

	app.writeJSON(w, http.StatusOK, resp)
}
