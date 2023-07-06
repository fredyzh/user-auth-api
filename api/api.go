package api

import (
	"auth/repositores"
	"auth/repositores/mongoRepo"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/mongo"
)

type Application struct {
	Domain          string
	AppID           string
	DB              repositores.DatabaseRepo
	DbOperations    *mongoRepo.Operations
	Validator       *validator.Validate
	JwtAuth         JwtAuth
	MaxRefreshToken int
}

type JSONResponse struct {
	Error   bool        `json:"error"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func (app *Application) StartApp() {

	port := os.Getenv("WEB_PORT")

	//init db
	Mongodb := mongoRepo.MongoDB{
		Host:      os.Getenv("MONGODB_HOST"),
		Port:      os.Getenv("MONGODB_PORT"),
		DefualtDb: os.Getenv("MONGODB_DEFAULT_DB"),
		Admin:     os.Getenv("MONGODB_ADMIN"),
		Password:  os.Getenv("MONGODB_PASSWORD"),
	}
	Mongodb.DBClint = Mongodb.ConnectDB().(*mongo.Client)
	dbOperatoins := &mongoRepo.Operations{
		Create: "C",
		Read:   "R",
		Update: "U",
		Delete: "D",
	}
	Mongodb.Operations = dbOperatoins

	//init app
	app.DbOperations = dbOperatoins
	app.DB = &Mongodb
	app.Validator = validator.New()
	app.Domain = os.Getenv("DOMAIN")

	// check if env init
	if app.Domain == "" {
		log.Fatal(errors.New("env dose not set"))
	}

	app.AppID = os.Getenv("APP_ID")
	maxInt, err := strconv.Atoi(os.Getenv("MAX_REFRESH_TOKEN_CNT"))

	if err != nil {
		log.Fatal(err)
	}

	app.MaxRefreshToken = maxInt

	//init jwt
	jwtAuth := JwtAuth{
		Issuer:            app.Domain + "_" + app.AppID,
		TokenRefreshCache: map[string]JwtAuthCache{},
	}
	app.JwtAuth = jwtAuth

	//start clean worker
	app.JwtAuth.CleanCacheWorker()

	log.Println("Starting application on port", port)

	//start a web server
	err = http.ListenAndServe(fmt.Sprintf("0.0.0.0:%s", port), app.routes())
	if err != nil {
		log.Fatal(err)
	}
}
