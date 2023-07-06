package repositores

import (
	"auth/models"
)

type DatabaseRepo interface {
	ConnectDB() interface{}
	CreateUser(usr *models.User) (interface{}, error)
	ValidUserByLonginUser(userAuth *models.UserAuth) (*models.User, string, error)
	IsUserLoninIdUnique(userAuth *models.UserAuth) (bool, error)
	GetUserByID(id interface{}, params ...interface{}) (interface{}, error)
	UpdateThirdPartySecretsByID(objID interface{}, secrets []models.ThirdPartySecret, operation string) (interface{}, error)
	GetJwtSecret(objID string, key string) (string, error)
}
