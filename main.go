package main

import (
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
)

var router *mux.Router

// Definitions of Structs
// User store User details
type User struct {
	gorm.Model
	Name     string `json:"name"`
	Email    string `gorm:"unique" json:"email"`
	Password string `json:"password`
	Role     string `json:"role"`
}

// Authentication is for login data
type Authentication struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Token 
type Token struct {
	Role        string `json:"role"`
	Email       string `json:"email"`
	TokenString string `json:"token"`
}

// CreateRouter generates a new instance of Mux Router
func CreateRouter() {
	router = mux.NewRouter()
}

// InitializeRoute creates handlers for the mux Router to handle
func InitializeRoute() {
	router.HandleFunc("/signup", SignUp).Methods("POST")
	router.HandleFunc("/signin", SignIn).Methods("POST")
}

// Main entry point function
func main() {
	CreateRouter()
	InitializeRoute()
}
