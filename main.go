package main

import (
	"context"
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	//"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	//"go.mongodb.org/mongo-driver/mongo/readpref"
	"net/http"
	"os"
	"time"
)

const uri = "mongodb+srv://CalcData:r5p3Gwuhn7ELIm3z@cluster0.vif5nkw.mongodb.net/?retryWrites=true&w=majority"

//const uri = "mongodb+srv://root:1234@cluster0.ik76ncs.mongodb.net/?retryWrites=true&w=majority"

type User struct {
	Email      string   `json:"email"`
	Password   string   `json:"password"`
	Verefy     string   `json:"verefy"`
	Times      []string `json:"times"`
	Comments   []string `json:"comments"`
	TimesWorks []string `json:"timesWorks"`
	Companets  []string `json:"companets"`
	Token      string   `json:"token"`
}

type Token struct {
	Token string `json:"token"`
}

func main() {
	r := gin.Default()
	r.POST("register", register)
	r.GET("login", login)
	r.Run(":8080")
}
func passwordHash(password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		fmt.Println(err)
	}
	return string(hash)
}

func register(c *gin.Context) {
	//chesk email data base if exist return error if not create new user and return token to client
	var user User
	c.BindJSON(&user)
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	client.Connect(ctx)
	defer client.Disconnect(ctx)
	collection := client.Database("CalcData").Collection("users")
	filter := bson.D{{Key: "email", Value: user.Email}}
	var result User
	collection.FindOne(context.Background(), filter).Decode(&result)

	if result.Email == user.Email {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email already exist"})
		return
	}
	user = User{
		Email:      user.Email,
		Password:   passwordHash(user.Password),
		Verefy:     "false",
		Times:      []string{},
		Comments:   []string{},
		TimesWorks: []string{},
		Companets:  []string{},
		Token:      createToken(user.Email),
	}
	user.Token = createToken(user.Email)
	collection.InsertOne(context.Background(), user)
	c.JSON(http.StatusOK, user)
}

func login(c *gin.Context) {
	var user User
	c.BindJSON(&user)
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	client.Connect(ctx)
	defer client.Disconnect(ctx)
	collection := client.Database("CalcData").Collection("users")
	filter := bson.D{{Key: "email", Value: user.Email}}
	var result User
	collection.FindOne(context.Background(), filter).Decode(&result)
	if result.Email == user.Email {
		if err := bcrypt.CompareHashAndPassword([]byte(result.Password), []byte(user.Password)); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "password is incorrect"})
			return
		}
		c.JSON(http.StatusOK, []string{result.Token, result.Verefy})

		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": "email is incorrect"})
}

func createToken(username string) string {
	claims := jwt.MapClaims{}
	claims["authorized"] = true
	claims["email"] = username
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(os.Getenv("SECRET")))
	return tokenString
}
