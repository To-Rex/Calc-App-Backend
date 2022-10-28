// bismillaxir roxmanir roxim
package main

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"

	//"net/smtp"
	"os"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/trycourier/courier-go/v2"
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
	Blocked   bool     `json:"blocked"`
	Times     []string `json:"times"`
	Coments   []string `json:"coments"`
	Switch    []string `json:"switch"`
	Companets []string `json:"companets"`
	Token     string   `json:"token"`
}

type Timess struct {
	Times string `json:"times"`
	Coments string `json:"coments"`
	Switch string `json:"switch"`
}

type Token struct {
	Token string `json:"token"`
}

func main() {
	r := gin.Default()
	r.POST("register", register)
	r.POST("login", login)
	r.POST("cheskverefy", cheskverefy)
	r.POST("verefyuser", verefyUser)
	r.GET("getuser", getUser)
	r.GET("getusers", getAllUsers)
	r.POST("addtime", addTime)
	r.POST("updatetime", updateTime)
	r.POST("deletetime", deleteTime)
	r.POST("updatecompanets", updateCompanets)
	r.GET("gettimes", getTimes)
	r.POST("resendverefy", resendVerefyCode)
	r.POST("updatePassword", updatePassword)
	r.POST("logout", logout)
	r.DELETE("deleteuser", deleteUser)
	r.Run()
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
	fmt.Println(string(hash))
	return string(hash)
}

// bcrypt.GenerateFromPassword([]byte(password), 10) //hashing the password with the default cost of 10
func passwordCheck(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		fmt.Println(err)
		return false
	}
	return true
}

func sendMailSimple(email string, code string) {
	client := courier.CreateClient("pk_prod_K10S0E6XF2MSA5MFK6E33ECTFJ9M", nil)
	requestID, err := client.SendMessage(
		context.Background(),
		courier.SendMessageRequestBody{
			Message: map[string]interface{}{
				"to": map[string]string{
					"email": email,
				},
				"template": "K4PMX20GEM4121GAFQJBH30JSSGD",
				"data": map[string]string{
					"recipientName": code,
				},
			},
		},
	)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(requestID)
	}
}

func register(c *gin.Context) {
	//chesk email data base if exist return error if not create new user and return token to client
	var user User
	c.BindJSON(&user)
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "error"})
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
		Blocked:   false,
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

func cheskverefy(c *gin.Context) {
	var user User
	c.BindJSON(&user)
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "error"})
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
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email is not exist"})
		return
	}
}

func verefyUser(c *gin.Context) {
	//post authorization bearer token user db update verefy to true and return token to client
	var user User
	c.BindJSON(&user)
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "error"})
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
				{Key: "verefy", Value: true},
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
	var timess Timess
	c.BindJSON(&timess)
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "error"})
	}
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	client.Connect(ctx)
	defer client.Disconnect(ctx)
	collection := client.Database("CalcData").Collection("users")
	filter := bson.D{{Key: "email", Value: claims["email"]}}
	var result User
	collection.FindOne(context.Background(), filter).Decode(&result)
	if result.Email == claims["email"] {
		if result.Verefy == false {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user is not verefy"})
			return
		}
		if result.Blocked == true {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user is blocked"})
			return
		}
		update := bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "times", Value: append(result.Times, timess.Times)},
			}},
			{Key: "$set", Value: bson.D{
				{Key: "coments", Value: append(result.Coments, timess.Coments)},
			}},
			{Key: "$set", Value: bson.D{
				{Key: "switch", Value: append(result.Switch, timess.Switch)},
			}},
		}
		collection.UpdateOne(context.Background(), filter, update)
		c.JSON(http.StatusOK, gin.H{"message": "time added"})
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": "email is incorrect"})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "error"})
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
		if result.Blocked == true {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user is blocked"})
			return
		}
		update := bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "companets", Value: user.Companets},
			}},
		}
		collection.UpdateOne(context.Background(), filter, update)
		collection.FindOne(context.Background(), filter).Decode(&result)
		c.JSON(http.StatusOK, gin.H{"companets": result.Companets})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "error"})
	}
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	client.Connect(ctx)
	defer client.Disconnect(ctx)
	collection := client.Database("CalcData").Collection("users")
	filter := bson.D{{Key: "email", Value: claims["email"]}}
	var result User
	collection.FindOne(context.Background(), filter).Decode(&result)
	if result.Email == claims["email"] {
		if result.Blocked == true {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user is blocked"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"times": result.Times, "coments": result.Coments, "switch": result.Switch, "companets": result.Companets})
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": "email is incorrect"})
}

func resendVerefyCode(c *gin.Context) {
	var user User
	c.BindJSON(&user)
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "error"})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "error"})
	}
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	client.Connect(ctx)
	defer client.Disconnect(ctx)
	collection := client.Database("CalcData").Collection("users")
	filter := bson.D{{Key: "email", Value: user.Email}}
	var result User
	collection.FindOne(context.Background(), filter).Decode(&result)
	if result.Email == user.Email {
		if result.Blocked == true {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user is blocked"})
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "error"})
		}
		update := bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "password", Value: string(hash)},
			}},
		}
		collection.UpdateOne(context.Background(), filter, update)
		collection.FindOne(context.Background(), filter).Decode(&result)
		c.JSON(http.StatusOK, gin.H{"message": "password updated"})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "error"})
	}
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	client.Connect(ctx)
	defer client.Disconnect(ctx)
	collection := client.Database("CalcData").Collection("users")
	filter := bson.D{{Key: "email", Value: claims["email"]}}
	var result User
	collection.FindOne(context.Background(), filter).Decode(&result)
	if result.Email == claims["email"] {
		if result.Blocked == true {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user is blocked"})
			return
		} else {
			if result.Verefy == true {
				c.JSON(http.StatusOK, gin.H{"email": result.Email, "verify": result.Verefy, "blocked": result.Blocked, "times": result.Times, "coments": result.Coments, "switch": result.Switch, "companets": result.Companets})
				return
			} else {
				c.JSON(http.StatusBadRequest, gin.H{"error": "email is not verified"})
				return
			}
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "error"})
	}
	for cur.Next(context.Background()) {
		var elem User
		err := cur.Decode(&elem)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "error"})
		}
		result = append(result, elem)
	}
	if err := cur.Err(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "error"})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "error"})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "error"})
	}
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	client.Connect(ctx)
	defer client.Disconnect(ctx)
	collection := client.Database("CalcData").Collection("users")
	filter := bson.D{{Key: "email", Value: claims["email"]}}
	collection.DeleteOne(context.Background(), filter)
	c.JSON(http.StatusOK, gin.H{"message": "delete user"})
}
func login(c *gin.Context) {
	//if user verify true treturn token else return error message
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "error"})
	}
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	client.Connect(ctx)
	defer client.Disconnect(ctx)
	collection := client.Database("CalcData").Collection("users")
	filter := bson.D{{Key: "email", Value: user.Email}}
	var result User
	collection.FindOne(context.Background(), filter).Decode(&result)
	if result.Email == user.Email {
		if result.Blocked == true {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user is blocked"})
			return
		}
		if result.Verefy == true {
			//check password
			if err := bcrypt.CompareHashAndPassword([]byte(result.Password), []byte(user.Password)); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "password is incorrect"})
				return
			} else {
				if result.Blocked == true {
					c.JSON(http.StatusBadRequest, gin.H{"error": "user is blocked"})
					return
				} else {
					token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
						"email": result.Email,
					})
					tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))
					if err != nil {
						fmt.Println(err)
					}
					c.JSON(http.StatusOK, gin.H{"token": tokenString})
					return
				}
			}
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "email is not verified"})
			return
		}
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": "email is incorrect"})
}

func deleteTime(c *gin.Context) {
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "error"})
	}
	indexs := c.Query("index")
	index, err := strconv.Atoi(indexs)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "index is not int"})
		return
	}
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	client.Connect(ctx)
	defer client.Disconnect(ctx)
	collection := client.Database("CalcData").Collection("users")
	filter := bson.D{{Key: "email", Value: claims["email"]}}
	var result User
	collection.FindOne(context.Background(), filter).Decode(&result)
	lenth := len(result.Times)
	if result.Blocked == true {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user is blocked"})
		return
	}

	if result.Verefy == false {
		c.JSON(http.StatusOK, gin.H{"message": "delete time"})
		return
	}
	if index > lenth {
		c.JSON(http.StatusBadRequest, gin.H{"error": "index is not correct"})
		return
	}

	if err := collection.FindOne(context.Background(), filter).Decode(&result); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user not found"})
		return
	}
	 var times []string
	 var coments []string
	 var switchs []string
	 for i := 0; i < len(result.Times); i++ {
		if i != index {
			times = append(times, result.Times[i])
			coments = append(coments, result.Coments[i])
			switchs = append(switchs, result.Switch[i])
		}
	}
	
	update := bson.D{
		{Key: "$set", Value: bson.D{
			{Key: "times", Value: times},
			{Key: "coments", Value: coments},
			{Key: "switch", Value: switchs},
		}},
	}
	collection.UpdateOne(context.Background(), filter, update)
	c.JSON(http.StatusOK, gin.H{"message": "delete time"})
}

func updateTime(c *gin.Context){
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "error"})
	}
	indexs := c.Query("index")
	index, err := strconv.Atoi(indexs)
	//if index is not int return error
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "index is not int"})
		return
	}
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	client.Connect(ctx)
	defer client.Disconnect(ctx)
	collection := client.Database("CalcData").Collection("users")
	filter := bson.D{{Key: "email", Value: claims["email"]}}
	var result User
	collection.FindOne(context.Background(), filter).Decode(&result)
	if result.Blocked == true {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user is blocked"})
		return
	}

	if result.Verefy == false {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email is not verified"})
		return
	}

	lenth := len(result.Times)
	if index > lenth {
		c.JSON(http.StatusBadRequest, gin.H{"error": "index is not correct"})
		return
	}
	//get data add index to time and coments and switch and update user
	var times Timess
	if err := c.ShouldBindJSON(&times); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := collection.FindOne(context.Background(), filter).Decode(&result); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user not found"})
		return
	}
	 for i := 0; i < len(result.Times); i++ {
		if i == index {
			result.Times[i] = times.Times
			result.Coments[i] = times.Coments
			result.Switch[i] = times.Switch
		}
	}

	update := bson.D{
		{Key: "$set", Value: bson.D{
			{Key: "times", Value: result.Times},
			{Key: "coments", Value: result.Coments},
			{Key: "switch", Value: result.Switch},
		}},
	}
	collection.UpdateOne(context.Background(), filter, update)
	c.JSON(http.StatusOK, gin.H{"message": "update time"})
}

// func updateTime(c *gin.Context) {
// 	token := c.Request.Header.Get("Authorization")
// 	token = token[7:len(token)]
// 	claims := jwt.MapClaims{}
// 	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
// 		return []byte(os.Getenv("SECRET")), nil
// 	})
// 	if err != nil {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
// 		return
// 	}
// 	var user User
// 	c.BindJSON(&user)
// 	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// 	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
// 	client.Connect(ctx)
// 	defer client.Disconnect(ctx)
// 	collection := client.Database("CalcData").Collection("users")
// 	filter := bson.D{{Key: "email", Value: claims["email"]}}
// 	var result User
// 	collection.FindOne(context.Background(), filter).Decode(&result)

// 	if result.Email == claims["email"] {
// 		//get user times array and add new times array in times array
		
// 		if result.Blocked == true {
// 			c.JSON(http.StatusBadRequest, gin.H{"error": "user is blocked"})
// 			return
// 		}
// 		update := bson.D{
// 			{Key: "$set", Value: bson.D{
// 				{Key: "times", Value: user.Times},
// 			}},
// 			{Key: "$set", Value: bson.D{
// 				{Key: "coments", Value: user.Coments},
// 			}},
// 			{Key: "$set", Value: bson.D{
// 				{Key: "switch", Value: user.Switch},
// 			}},
// 		}

// 		collection.UpdateOne(context.Background(), filter, update)
// 		collection.FindOne(context.Background(), filter).Decode(&result)
// 		c.JSON(http.StatusOK, gin.H{"times": result.Times, "coments": result.Coments, "switch": result.Switch, "companets": result.Companets})
// 		return
// 	}
// }
