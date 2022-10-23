package main

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

const uri = "mongodb+srv://CalcData:r5p3Gwuhn7ELIm3z@cluster0.vif5nkw.mongodb.net/?retryWrites=true&w=majority"

type User struct {
	Email     string   `json:"email"`
	Password  string   `json:"password"`
	Verefy    bool     `json:"verefy"`
	Times     []string `json:"times"`
	Coments   []string `json:"coments"`
	Switch    []string `json:"switch"`
	Companets []string `json:"companets"`
	Token     string   `json:"token"`
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
	r.POST("updatetime", updateTime)
	r.POST("updatecompanets", updateCompanets)
	r.GET("gettimes", getTimes)
	r.POST("resendverefy", resendVerefyCode)
	r.POST("updatePassword", updatePassword)
	r.POST("logout", logout)
	r.DELETE("deleteuser", deleteUser)
	r.Run(":8080")
}

func createToken(username string) string {
	claims := jwt.MapClaims{}
	claims["authorized"] = true
	claims["email"] = username
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(os.Getenv("SECRET")))
	return tokenString
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
	verefy := rand.Intn(999999)
	if verefy < 100000 {
		verefy += 100000
	}
	user = User{
		Email:     user.Email,
		Password:  passwordHash(user.Password),
		Verefy:    false,
		Times:     []string{},
		Coments:   []string{},
		Switch:    []string{},
		Companets: []string{},
		Token:     createToken(user.Email),
	}
	user.Token = createToken(user.Email)
	collection.InsertOne(context.Background(), user)
	sendMailSimple(user.Email, strconv.Itoa(verefy))

	c.JSON(http.StatusOK, gin.H{"token": user.Token, "verefy": verefy})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "error"})
	}
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
		fmt.Println(err)
	}
	defer cur.Close(ctx)
	for cur.Next(ctx) {
		var result User
		err := cur.Decode(&result)
		if err != nil {
			fmt.Println(err)
		}
		if result.Email == user.Email {
			if result.Verefy == false {
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

func addTime(c *gin.Context) {
	//db get user email from token add time to user time add new time to user time array
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
	//get user times array and add new times array in times array
	if result.Email == claims["email"] {
		//get user times array and add new times array in times array
		update := bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "times", Value: append(result.Times, user.Times...)},
			}},
			{Key: "$set", Value: bson.D{
				{Key: "coments", Value: append(result.Coments, user.Coments...)},
			}},
			{Key: "$set", Value: bson.D{
				{Key: "switch", Value: append(result.Switch, user.Switch...)},
			}},
		}

		collection.UpdateOne(context.Background(), filter, update)
		collection.FindOne(context.Background(), filter).Decode(&result)
		result = User{Times: result.Times, Coments: result.Coments, Switch: result.Switch}
		c.JSON(http.StatusOK, result)
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": "email is incorrect"})
}

func updateTime(c *gin.Context) {
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
		//get user times array and add new times array in times array
		update := bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "times", Value: user.Times},
			}},
			{Key: "$set", Value: bson.D{
				{Key: "coments", Value: user.Coments},
			}},
			{Key: "$set", Value: bson.D{
				{Key: "switch", Value: user.Switch},
			}},
		}

		collection.UpdateOne(context.Background(), filter, update)
		collection.FindOne(context.Background(), filter).Decode(&result)
		result = User{Times: result.Times, Coments: result.Coments, Switch: result.Switch}
		c.JSON(http.StatusOK, result)
		return
	}
}

func updateCompanets(c *gin.Context) {
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
		//get user times array and add new times array in times array
		update := bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "companets", Value: user.Companets},
			}},
		}
		collection.UpdateOne(context.Background(), filter, update)
		collection.FindOne(context.Background(), filter).Decode(&result)
		c.JSON(http.StatusBadRequest, gin.H{"companets": result.Companets})
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": "email is incorrect"})
}

func getTimes(c *gin.Context) {
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
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	client.Connect(ctx)
	defer client.Disconnect(ctx)
	collection := client.Database("CalcData").Collection("users")
	filter := bson.D{{Key: "email", Value: claims["email"]}}
	var result User
	collection.FindOne(context.Background(), filter).Decode(&result)
	if result.Email == claims["email"] {
		result = User{Times: result.Times, Coments: result.Coments, Switch: result.Switch, Companets: result.Companets}
		c.JSON(http.StatusOK, result)
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": "email is incorrect"})
}

func sendMailSimple(email string, code string) {
	auth := smtp.PlainAuth(
		"",
		"uz.yorvoration@gmail.com",
		"cpjiovhtsffdpmys",
		"smtp.gmail.com",
	)

	headers := "MiME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	subject := "Verify your email"
	html := "<h1>Verification code</h1><p>" + code + "</p>"
	msg := "Subject: " + subject + " \n" + headers + html

	err := smtp.SendMail(
		"smtp.gmail.com:587",
		auth,
		email,
		[]string{email},
		[]byte(msg),
	)
	if err != nil {
		fmt.Println(err)
	}
}

func resendVerefyCode(c *gin.Context) {
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
		if result.Verefy == false {
			verefy := rand.Intn(999999)
			if verefy < 100000 {
				verefy += 100000
			}
			verefy += 1
			verefyCode := strconv.Itoa(verefy)
			c.JSON(http.StatusOK, gin.H{"verefyCode": verefyCode})
			sendMailSimple(user.Email, verefyCode)
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "email is already verified"})
			return
		}
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": "email is incorrect"})
}

func updatePassword(c *gin.Context) {
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
		hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
		if err != nil {
			fmt.Println(err)
		}
		update := bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "password", Value: string(hash)},
			}},
		}
		collection.UpdateOne(context.Background(), filter, update)
		collection.FindOne(context.Background(), filter).Decode(&result)
		result = User{Email: result.Email}
		c.JSON(http.StatusOK, result)
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": "email is incorrect"})
}

func getUser(c *gin.Context) {
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
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	client.Connect(ctx)
	defer client.Disconnect(ctx)
	collection := client.Database("CalcData").Collection("users")
	filter := bson.D{{Key: "email", Value: claims["email"]}}
	var result User
	collection.FindOne(context.Background(), filter).Decode(&result)
	if result.Email == claims["email"] {
		if result.Verefy == true {
			c.JSON(http.StatusOK, gin.H{"email": result.Email,"verify": result.Verefy, "times": result.Times, "coments": result.Coments, "switch": result.Switch, "companets": result.Companets})
			c.JSON(http.StatusOK, result)
			return
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "email is not verified"})
			return
		}
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": "email is incorrect"})
}

func getAllUsers(c *gin.Context) {
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		fmt.Println(err)
	}
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	client.Connect(ctx)
	defer client.Disconnect(ctx)
	collection := client.Database("CalcData").Collection("users")
	var result []User
	cur, err := collection.Find(context.Background(), bson.D{})
	if err != nil {
		fmt.Println(err)
	}
	for cur.Next(context.Background()) {
		var elem User
		err := cur.Decode(&elem)
		if err != nil {
			fmt.Println(err)
		}
		result = append(result, elem)
	}
	if err := cur.Err(); err != nil {
		fmt.Println(err)
	}
	cur.Close(context.Background())
	c.JSON(http.StatusOK, result)
}

func logout(c *gin.Context) {
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
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	client.Connect(ctx)
	defer client.Disconnect(ctx)
	collection := client.Database("CalcData").Collection("users")
	filter := bson.D{{Key: "email", Value: claims["email"]}}
	//user verefy update false
	update := bson.D{
		{Key: "$set", Value: bson.D{
			{Key: "verefy", Value: false},
		}},
	}
	collection.UpdateOne(context.Background(), filter, update)
	c.JSON(http.StatusOK, gin.H{"message": "logout"})
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
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	client.Connect(ctx)
	defer client.Disconnect(ctx)
	collection := client.Database("CalcData").Collection("users")
	filter := bson.D{{Key: "email", Value: claims["email"]}}
	collection.DeleteOne(context.Background(), filter)
	c.JSON(http.StatusOK, gin.H{"message": "delete user"})
}