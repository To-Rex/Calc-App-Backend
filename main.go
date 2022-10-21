package main

import (
	"context"
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"

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
	Email   string `json:"email"`
	Password string `json:"password"`
	Verefy string `json:"verefy"`
	Times []string `json:"times"`
	Comments []string `json:"comments"`
	TimesWorks []string `json:"timesWorks"`
	Companets []string `json:"companets"`
	Token string `json:"token"`
}

type Token struct {
	Token string `json:"token"`
}

func main() {
	r := gin.Default()
	r.POST("register", register)
	r.Run(":8080")
}

func verifyToken(tokenString string) bool {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("SECRET")), nil
	})
	if err != nil {
		return false
	}
	if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return true
	} else {
		return false
	}
}

func connectToDB() *mongo.Client {
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		fmt.Println(err)
	}
	defer client.Disconnect(ctx)
	return client
}

func checkToken(c *gin.Context) {
	token := c.Request.Header.Get("Authorization")
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Token is required"})
		c.Abort()
		return
	}
	if !verifyToken(token) {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Token is not valid"})
		c.Abort()
		return
	}
	c.Next()
}

func register(c *gin.Context) {
	//save to db and return token
	var user User
	err := c.BindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
		return
	}
	client := connectToDB()
	collection := client.Database("CalcData").Collection("users")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	filter := bson.M{"email": user.Email}
	var result User
	err = collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
		return
	}
	if result.Email != "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
		return
	}
	user.Token = createToken(user.Email)
	_, err = collection.InsertOne(ctx, user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad request"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "OK"})
}

// func register1(c *gin.Context) {
// 	var user User
// 	c.BindJSON(&user)
// 	user.Token = createToken(user.Email)
// 	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// 	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
// 	err = client.Connect(ctx)
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// 	defer client.Disconnect(ctx)
// 	collection := client.Database("test").Collection("users")
// 	ctx, _ = context.WithTimeout(context.Background(), 5*time.Second)

// 	_, err = collection.InsertOne(ctx, user)
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// 	c.JSON(http.StatusOK, gin.H{"Token": user.Token})
// }



func createToken(username string) string {
	claims := jwt.MapClaims{}
	claims["authorized"] = true
	claims["email"] = username
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(os.Getenv("SECRET")))
	return tokenString
}