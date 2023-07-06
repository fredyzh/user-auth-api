package mongoRepo

import (
	"auth/models"
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

const userDB = "user"

type Operations struct {
	Create string
	Read   string
	Update string
	Delete string
}

type MongoDB struct {
	Host       string
	Port       string
	DefualtDb  string
	Admin      string
	Password   string
	DBClint    *mongo.Client
	Operations *Operations
}

func (m *MongoDB) ConnectDB() interface{} {
	// `mongodb://${process.env.MONGO_USER}:${process.env.MONGO_PASSWORD}@${process.env.MONGO_IP}:${process.env.MONGO_PORT}/?authSource=admin`

	// mongoDbUri := fmt.Sprintf("mongodb://%s:%s", m.Host, m.Port)

	//mongodb+srv://mongo_admin:<password>@cluster0.abh3pnp.mongodb.net/

	mongoDbUri := fmt.Sprintf("mongodb+srv://%s:%s@%s/", m.Admin, m.Password, m.Host)
	// log.Println(mongoDbUri)

	c, err := mongo.NewClient(options.Client().ApplyURI(mongoDbUri))
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = c.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("connected to MongoDB")
	return c
}

func (m *MongoDB) CreateUser(usr *models.User) (interface{}, error) {
	client := m.DBClint
	coll := client.Database(m.DefualtDb).Collection(userDB)

	usr.ID = primitive.NewObjectID()
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(usr.UserAuth.Password), 8)

	if err != nil {
		log.Println(err)
		return nil, err
	}

	usr.UserAuth.Password = string(hashPassword)
	usr.CreatedAt = primitive.NewDateTimeFromTime(time.Now().AddDate(-1, 0, 0))
	usr.UpdatedAt = primitive.NewDateTimeFromTime(time.Now().AddDate(-1, 0, 0))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := coll.InsertOne(ctx, usr)

	if err != nil {
		log.Println(err)
		return nil, err
	}

	return result, nil
}

func (m *MongoDB) ValidUserByLonginUser(userAuth *models.UserAuth) (*models.User, string, error) {
	client := m.DBClint
	coll := client.Database(m.DefualtDb).Collection(userDB)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var result models.User
	filter := bson.D{{Key: "user_auth.login_id", Value: userAuth.LoginID}}
	opts := options.FindOne().SetProjection(bson.D{{Key: "_id", Value: 1}, {Key: "user_auth", Value: 1}, {Key: "profile", Value: 1}})
	err := coll.FindOne(ctx, filter, opts).Decode(&result)

	if err != nil {
		if strings.Contains(err.Error(), "no documents") {
			return nil, "", errors.New("invalid user id")
		}

		return nil, "", err
	}

	if ok, err := passwordMatches(result.UserAuth.Password, userAuth.Password); !ok {
		return nil, "", err
	}

	if result.UserAuth.Scope.Domain != userAuth.Scope.Domain || result.UserAuth.Scope.AppID != userAuth.Scope.AppID {
		return nil, "", errors.New("invalid user id")
	}

	result.UserAuth.Password = ""

	return &result, result.ID.Hex(), nil
}

func (m *MongoDB) IsUserLoninIdUnique(userAuth *models.UserAuth) (bool, error) {
	client := m.DBClint
	coll := client.Database(m.DefualtDb).Collection(userDB)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var result models.User
	filter := bson.D{{Key: "user_auth.login_id", Value: userAuth.LoginID}}
	opts := options.FindOne().SetProjection(bson.D{{Key: "user_auth", Value: 1}})
	err := coll.FindOne(ctx, filter, opts).Decode(&result)

	if err != nil {
		log.Println(err)

		if strings.Contains(err.Error(), "no documents") {
			return true, nil
		}
		return false, err
	}

	if result.UserAuth.Scope.Domain != userAuth.Scope.Domain || result.UserAuth.Scope.AppID != userAuth.Scope.AppID {
		return true, nil
	}

	return false, nil
}

func (m *MongoDB) GetUserByID(objID interface{}, params ...interface{}) (interface{}, error) {
	objID = objID.(*primitive.ObjectID)
	filterD := params[0].(primitive.D)
	optsD := params[1].(primitive.D)

	client := m.DBClint
	coll := client.Database(m.DefualtDb).Collection(userDB)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var result models.User
	opts := options.FindOne().SetProjection(optsD)
	err := coll.FindOne(ctx, filterD, opts).Decode(&result)

	if err != nil {
		log.Println(err)
		return nil, err
	}

	return &result, nil
}

func (m *MongoDB) UpdateThirdPartySecretsByID(objID interface{}, secrets []models.ThirdPartySecret, operation string) (interface{}, error) {
	var filter bson.M

	objID, err := primitive.ObjectIDFromHex(objID.(string))
	if err != nil {
		return nil, err
	}

	newSecrets := models.ThirdPartySecret{
		KeyName:     secrets[0].KeyName,
		KeyValue:    secrets[0].KeyValue,
		Description: secrets[0].Description}

	client := m.DBClint
	coll := client.Database(m.DefualtDb).Collection(userDB)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var res interface{}
	if operation == m.Operations.Create {
		filter = bson.M{
			"$and": []bson.M{
				{"_id": objID},
				{"third_party_secrets": bson.M{"$elemMatch": bson.M{"key_anme:": bson.M{"$ne": secrets[0].KeyName}}}}},
		}

		filter = bson.M{"_id": objID}

		update := bson.M{"$push": bson.M{"third_party_secrets": newSecrets}}
		res, err := coll.UpdateOne(ctx, filter, update)

		if err != nil {
			log.Println(err)
			return nil, err
		}

		return res, nil
	}

	if operation == m.Operations.Update {
		filter = bson.M{
			"$and": []bson.M{
				{"_id": objID},
				{"third_party_secrets.key_name": newSecrets.KeyName},
			},
		}
		update := bson.M{"$set": bson.M{"third_party_secrets.$": newSecrets}}

		res, err = coll.UpdateOne(ctx, filter, update)
		if err != nil {
			log.Println(err)
			return nil, err
		}
	}

	return res, nil
}

func (m *MongoDB) GetJwtSecret(id string, key string) (string, error) {
	objID, err := primitive.ObjectIDFromHex(id)

	if err != nil {
		log.Println(err)
		return "", err
	}

	client := m.DBClint
	coll := client.Database(m.DefualtDb).Collection(userDB)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var result models.User
	filter := bson.M{
		"$and": []bson.M{
			{"_id": objID},
			{"third_party_secrets.key_name": key}},
	}

	opts := options.FindOne().SetProjection(bson.D{{Key: "third_party_secrets.$", Value: 1}})
	err = coll.FindOne(ctx, filter, opts).Decode(&result)

	if err != nil {

		if strings.Contains(err.Error(), "no documents") {
			return "", err
		}
		return "", err
	}

	return result.ThirdPartySecrets[0].KeyValue, nil
}

// func updateUserByID(objID *primitive.ObjectID, filter primitive.M, update primitive.D, m *MongoDB) (*mongo.UpdateResult, error) {
// 	client := m.DBClint
// 	coll := client.Database(m.DefualtDb).Collection(userDB)
// 	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
// 	defer cancel()

// 	res, err := coll.UpdateOne(ctx, filter, update)

// 	if err != nil {
// 		log.Println(err)
// 		return nil, err
// 	}

// 	return res, nil
// }

func passwordMatches(password string, plainText string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(password), []byte(plainText))

	// bcrypt.

	if err != nil {
		switch {
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			err = errors.New("invalid user")
			return false, err
		default:
			return false, err
		}
	}

	return true, nil
}
