package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/lib/pq"
)

// -- GLOBAL VARS --

var router *mux.Router

// -- STRUCTS --
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

type Error struct {
	IsError bool   `json:"isError"`
	Message string `json:"message"`
}

// -- DATABASE FUNCTIONS --
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

// Add the InitialMigration for the DB
func InitialMigration() {
	connection := GetDatabase()
	defer Closedatabase(connection)
	connection.AutoMigrate(User{})
	// CreateRecord(connection, User)
}

// Close the database connection opened
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

// Query records in example function
func QueryRecord(db *gorm.DB, user User) {
	result := db.First(&user)

	if result.Error != nil {
		log.Println("Not record present")
	}
}

// -- ROUTES --
// CreateRouter generates a new instance of Mux Router
func CreateRouter() {
	router = mux.NewRouter()
}

// InitializeRoute creates handlers for the mux Router to handle
func InitializeRoute() {
	router.HandleFunc("/", homeHandler).Methods("GET")
	router.HandleFunc("/signup", SignUp).Methods("POST")
	router.HandleFunc("/signin", SignIn).Methods("POST")
}

func StartServer() {
	port := ":" + os.Getenv("PORT")
	fmt.Printf("Server running in port %s", port)
	//err := http.ListenAndServe(port, handlers.CORS(handlers.AllowCredentials))

	err := http.ListenAndServe(port, handlers.CORS(handlers.AllowedHeaders([]string{"X-Requested-With", "Access-Control-Allow-Origin", "Content-Type", "Authorization"}), handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"}), handlers.AllowedOrigins([]string{"*"}))(router))
	if err != nil {
		log.Fatal(err)
	}
}

// -- ROUTES HANDLERS --

// SignIn function that checks if the user is present in the system, and check the key:values
// stored in the database. After compares the values from input and output and if its ok,
// generates a Golang JWT authentication
func SignIn(w http.ResponseWriter, r *http.Request) {
	connection := GetDatabase()
	defer Closedatabase(connection)

	// Read from Request Body the auth input email and pass and store it in a Struct Authentication
	var authdetails Authentication
	err := json.NewDecoder(r.Body).Decode(&authdetails)
	// TODO: Add logrus to handle the logs output
	if err != nil {
		var err Error
		err = SetError(err, "Error in reading body")
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		json.NewEncoder(w).Encode(err)
		return
	}

}

func SignUp(w http.ResponseWriter, r *http.Request) {

}

// Home Page Handler
func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome to the Home Page [No Auth Required]"))
}

// -- HELPER FUNCTIONS --

func SetError(err Error, message string) Error {
	err.IsError = true
	err.Message = message
	return err
}

// Main entry point function
func main() {
	InitialMigration()
	CreateRouter()
	InitializeRoute()
	StartServer()
}
