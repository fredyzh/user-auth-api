package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID                primitive.ObjectID `bson:"_id"`
	UserAuth          UserAuth           `json:"user_auth" validate:"required" bson:"user_auth"`
	Profile           UserPorfile        `json:"profile" bson:"profile"`
	ThirdPartySecrets []ThirdPartySecret `json:"third_party_secrets" bson:"third_party_secrets"`
	CreatedAt         primitive.DateTime `bson:"created_at"`
	UpdatedAt         primitive.DateTime `bson:"updated_at"`
}

type UserAuth struct {
	LoginID    string     `json:"login_id" validate:"required,min=2,max=100" bson:"login_id"`
	Password   string     `json:"password" validate:"required,min=4" bson:"password"`
	Scope      UserScope  `json:"scope" validate:"required" bson:"scope"`
	TokenPairs TokenPairs `json:"tokenPairs" bson:"-"`
}

type UserPorfile struct {
	FisrtName string  `json:"first_name" bson:"first_name"`
	LastNmae  string  `json:"last_name" bson:"last_name"`
	Email     string  `json:"email" bson:"email"`
	Phone     string  `json:"phone" bson:"phone"`
	Address   Address `json:"address" bson:"address"`
}

type Address struct {
	Street  string `json:"street" bson:"street"`
	City    string `json:"city" bson:"city"`
	State   string `json:"state" bson:"state"`
	Zipcode string `json:"zip_code" bson:"zip_code"`
}

type Token struct {
	PlainText string        `json:"access_token" bson:"-"`
	Hash      []byte        `json:"-" bson:"-"`
	Expiry    time.Duration `json:"expiry_time" bson:"-"`
}

type TokenPairs struct {
	Token        Token `json:"token" bson:"-"`
	RefreshToken Token `json:"refresh_token" bson:"-"`
}

type UserRole struct {
	RoleID      primitive.ObjectID
	RoleNmae    string `json:"role_name" validate:"required" bson:"role_name"`
	Description string `json:"description" bson:"description"`
}

type ThirdPartySecret struct {
	KeyName     string `json:"key_name" bson:"key_name"`
	KeyValue    string `json:"key_value" bson:"key_value"`
	Description string `json:"description" bson:"description"`
}

type UserScope struct {
	Domain string   `json:"user_domain" validate:"required" bson:"user_domain"`
	AppID  string   `json:"user_app_id" validate:"required" bson:"user_app_id"`
	Role   UserRole `json:"user_role" validate:"required" bson:"user_role"`
}
