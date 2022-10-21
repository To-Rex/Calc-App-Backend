package main

import (
		"context"
		"fmt"
		"github.com/dgrijalva/jwt-go"
		"github.com/gin-gonic/gin"
		"go.mongodb.org/mongo-driver/bson"
		"go.mongodb.org/mongo-driver/mongo"
		"go.mongodb.org/mongo-driver/mongo/options"
		"go.mongodb.org/mongo-driver/mongo/readpref"
		"net/http"
		"os"
		"time"
	)

const uri = "mongodb+srv://CalcData:r5p3Gwuhn7ELIm3z@cluster0.vif5nkw.mongodb.net/?retryWrites=true&w=majority"

//const uri = "mongodb+srv://root:1234@cluster0.ik76ncs.mongodb.net/?retryWrites=true&w=majority"

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Name     string `json:"name"`
	Age      int    `json:"age"`
	Email    string `json:"email"`
	Token    string `json:"token"`
}

type Token struct {
	Token string `json:"token"`
}

func main() {
	r := gin.Default()
	r.POST("login", login)
	r.POST("register", register)
	r.GET("getuser", user)
	r.GET("getusers", users)
	r.DELETE("deleteuser", deleteUser)
	r.Run(":8080")
}

func register(c *gin.Context) {
	var user User
	c.BindJSON(&user)
	user.Token = createToken(user.Username)
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
	collection := client.Database("test").Collection("users")
	ctx, _ = context.WithTimeout(context.Background(), 5*time.Second)

	_, err = collection.InsertOne(ctx, user)
	if err != nil {
		fmt.Println(err)
	}
	c.JSON(http.StatusOK, gin.H{"Token": user.Token})
}

func user(c *gin.Context) {
	token := c.Request.Header.Get("Authorization")
	token = token[7:len(token)]
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}
	var user User
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		fmt.Println(err)
	}

	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		fmt.Println(err)
	}

	collection := client.Database("test").Collection("users")

	filter := bson.M{"username": claims["username"]}
	err = collection.FindOne(context.Background(), filter).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}
	user = User{
		Username: user.Username,
		Password: user.Password,
		Name:     user.Name,
		Age:      user.Age,
		Email:    user.Email,
	}
	c.JSON(http.StatusOK, user)

}


func users(c *gin.Context) {
	token := c.Request.Header.Get("Authorization")
	token = token[7:len(token)]
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}
	var users []User
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		fmt.Println(err)
	}

	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		fmt.Println(err)
	}

	collection := client.Database("test").Collection("users")

	cursor, err := collection.Find(context.Background(), bson.M{})
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	for cursor.Next(context.Background()) {
		var user User
		cursor.Decode(&user)
		user = User{
			Username: user.Username,
			Password: user.Password,
			Name:     user.Name,
			Age:      user.Age,
			Email:    user.Email,
		}
		
		users = append(users, user)

	}
	c.JSON(http.StatusOK, users)
}

func deleteUser(c *gin.Context) {
	token := c.Request.Header.Get("Authorization")
	token = token[7:len(token)]
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}

	ctx, _:= context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		fmt.Println(err)
	}

	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		fmt.Println(err)
	}

	collection := client.Database("test").Collection("users")

	filter := bson.M{"username": claims["username"]}
	_, err = collection.DeleteOne(context.Background(), filter)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "User deleted"})
}

func login(c *gin.Context) {
	var user User
	c.BindJSON(&user)
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		fmt.Println(err)
	}

	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		fmt.Println(err)
	}

	collection := client.Database("test").Collection("users")

	filter := bson.M{"email": user.Email}
	err = collection.FindOne(context.Background(), filter).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}
	if user.Password != user.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"password": user.Password,
		"name":     user.Name,
		"age":      user.Age,
		"email":    user.Email,
	})
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		fmt.Println(err)
	}
	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func createToken(username string) string {
	claims := jwt.MapClaims{}
	claims["authorized"] = true
	claims["email"] = username
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(os.Getenv("SECRET")))
	return tokenString
}