package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"net/http"

)

const uri = "mongodb+srv://root:1234@cluster0.ik76ncs.mongodb.net/?retryWrites=true&w=majority"

type User struct{
	email string `json:"email"`
	password string `json:"password"`
}

func main() {
	r := gin.Default()
	r.POST("/login", login)
	r.POST("/register", register)
	r.GET("/profile", profile)
	r.Run(":8080")
}

//register user ansync


