package main

import (
	"context"
	"net/http"
	"time"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

const uri = "mongodb+srv://CalcData:r5p3Gwuhn7ELIm3z@cluster0.vif5nkw.mongodb.net/?retryWrites=true&w=majority"
//const uri = "mongodb+srv://root:1234@cluster0.ik76ncs.mongodb.net/?retryWrites=true&w=majority"

type User struct{
	email string `json:"email"`
	password string `json:"password"`
	verify string `json:"verify"`
	times []string `json:"times"`
	coments []string `json:"coments"`
	timesWorks []string `json:"timesWorks"`
	companets []string `json:"companets"`
	token string `json:"token"`
	
}

func main() {
	r := gin.Default()
	r.POST("/register", register)

	r.Run(":8080")
}

func createToken(email string) (string, error) {
	claims := jwt.MapClaims{}
	claims["authorized"] = true
	claims["email"] = email
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte("secret"))
}
func checkTokenMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return []byte("secret"), nil
		})
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Set("email", claims["email"])
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}
	}
}

func connectDB() *mongo.Client {
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
	fmt.Println("Connected to MongoDB!")
	return client
}

func checkUser(client *mongo.Client, email string, password string) bool {
	collection := client.Database("CalcData").Collection("users")
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	var user User
	err := collection.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		fmt.Println(err)
	}
	if user.password == password {
		return true
	}
	return false
}

func register(c *gin.Context) {
	
}




