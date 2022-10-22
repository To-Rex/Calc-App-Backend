package main

import (
	"context"
	"fmt"
	"log"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"os"
	"time"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const uri = "mongodb+srv://CalcData:r5p3Gwuhn7ELIm3z@cluster0.vif5nkw.mongodb.net/?retryWrites=true&w=majority"

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
	r.POST("cheskverefy", cheskverefy)
	r.POST("verefyuser", verefyUser)
	r.GET("getuser", getUser)
	r.GET("getusers", getAllUsers)
	r.POST("addtime", addTime)
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
	//if verfy is false return error if true return token
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
	//all users in data base
	cur, err := collection.Find(context.Background(), bson.D{})
	if err != nil {
		log.Fatal(err)
	}
	defer cur.Close(ctx)
	for cur.Next(ctx) {
		var result User
		err := cur.Decode(&result)
		if err != nil {
			log.Fatal(err)
		}
		if result.Email == user.Email {
			if result.Verefy == "false" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "email is not verifed"})
				return
			}
			err := bcrypt.CompareHashAndPassword([]byte(result.Password), []byte(user.Password))
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "password is incorrect"})
				return
			}
			c.JSON(http.StatusOK, Token{Token: createToken(user.Email)})
			return
		}
	}
}

func cheskverefy(c *gin.Context) {
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
		c.JSON(http.StatusOK, gin.H{"verefy": result.Verefy})
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": "email is incorrect"})
}

func verefyUser(c *gin.Context) {
	//post authorization bearer token user db update verefy to true and return token to client 
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
		update := bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "verefy", Value: "true"},
			}},
		}
		collection.UpdateOne(context.Background(), filter, update)
		c.JSON(http.StatusOK, Token{Token: createToken(user.Email)})
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": "email is incorrect"})
}

func getUser(c *gin.Context) {
	token := c.Request.Header.Get("Authorization")
	token = token[7:len(token)]
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token is incorrect"})
		return
	}
	email := claims["email"].(string)
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	client.Connect(ctx)
	defer client.Disconnect(ctx)
	collection := client.Database("CalcData").Collection("users")
	filter := bson.D{{Key: "email", Value: email}}
	var result User
	collection.FindOne(context.Background(), filter).Decode(&result)
	if result.Email == email {
		c.JSON(http.StatusOK, result)
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": "email is incorrect"})
}

func getAllUsers(c *gin.Context) {
	//get authorization bearer token user db return all users all data
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
	c.BindJSON(&user)
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	client.Connect(ctx)
	defer client.Disconnect(ctx)
	collection := client.Database("CalcData").Collection("users")
	filter := bson.D{{Key: "email", Value: claims["email"]}}
	var result User
	collection.FindOne(context.Background(), filter).Decode(&result)
	if result.Email == claims["email"] {
		var results []*User
		cur, err := collection.Find(context.Background(), bson.D{})
		if err != nil {
			log.Fatal(err)
		}
		for cur.Next(context.Background()) {
			var elem User
			err := cur.Decode(&elem)
			if err != nil {
				log.Fatal(err)
			}
			results = append(results, &elem)
		}
		if err := cur.Err(); err != nil {
			log.Fatal(err)
		}
		cur.Close(context.Background())
		//results = results[1:]

		c.JSON(http.StatusOK, results)
		return
	}
}

func addTime(c *gin.Context) {
	//post authorization bearer token user db update time
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
	//add time in [{"time": "2020-12-12 12:12:12","coment","true"}] format to user db time array 
	if result.Email == user.Email {
		update := bson.D{
			{Key: "$push", Value: bson.D{
				{Key: "time", Value: bson.D{
					{Key: "times", Value: user.Times},
					{Key: "coment", Value: "user.Times[0].Coment"},
					{Key: "verefy", Value: "user.Times[0].Verefy"},
				}},
			}},
		}
		collection.UpdateOne(context.Background(), filter, update)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
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
