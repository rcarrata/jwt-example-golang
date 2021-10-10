package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/lib/pq"
)

var router *mux.Router

// Definitions of Structs
// User store User details
type User struct {
	gorm.Model
	Name     string `json:"name"`
	Email    string `gorm:"unique" json:"email"`
	Password string `json:"password"`
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

func SignUp(w http.ResponseWriter, r *http.Request) {

}

func SignIn(w http.ResponseWriter, r *http.Request) {

}

// Connect to the Postgresql Database
// TODO: Use Viper and .Env to handle the psql parameters
func GetDatabase() *gorm.DB {
	databasename := "userdb"
	database := "postgres"
	databasepassword := "1312"
	databaseurl := "postgres://postgres:" + databasepassword + "@localhost/" + databasename + "?sslmode=disable"

	connection, err := gorm.Open(database, databaseurl)
	if err != nil {
		log.Fatalln("wrong database url")
	}
	if err != nil {
		log.Fatalf("Error in connect the DB %v", err)
		return nil
	}
	if err := connection.DB().Ping(); err != nil {
		log.Fatalln("Error in make ping the DB " + err.Error())
		return nil
	}
	if connection.Error != nil {
		log.Fatalln("Any Error in connect the DB " + err.Error())
		return nil
	}
	log.Println("DB connected")
	return connection

}

func InitialMigration() {
	connection := GetDatabase()
	defer Closedatabase(connection)
	connection.AutoMigrate(User{})
	CreateRecord(connection)
}

func Closedatabase(connection *gorm.DB) {
	log.Println("Closing DB connection")
	sqldb := connection.DB()
	sqldb.Close()
}

// Function to test the generation of records in the DB
func CreateRecord(db *gorm.DB) {
	user := User{Name: "Rober", Email: "rober@test.com", Password: "test", Role: "Admin"}
	result := db.Create(&user)

	if result.Error != nil {
		log.Fatalln("Not able to generate the record")
	}
}

// Main entry point function
func main() {
	CreateRouter()
	InitializeRoute()
	InitialMigration()
}
