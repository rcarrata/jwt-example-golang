package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"

	logrus "github.com/sirupsen/logrus"
)

// -- GLOBAL VARS --

var (
	router    *mux.Router
	secretkey string = "secretkeyjwt"
)

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
	database := "postgres"
	databasepassword := "1312"
	databaseurl := "postgres://postgres:" + databasepassword + "@localhost/" + database + "?sslmode=disable"

	connection, err := gorm.Open(database, databaseurl)
	sqldb := connection.DB()

	// Check the Database URL
	if err != nil {
		logrus.Fatalln("Wrong database url")
	}

	// Check the connection towards the Postgresql
	if err := sqldb.Ping(); err != nil {
		logrus.Fatalln("Error in make ping the DB " + err.Error())
		return nil
	}

	logrus.Info("DB connected")
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
	// Only for debug
	// log.Println("Closing DB connection")
	sqldb := connection.DB()
	sqldb.Close()
}

// Function to test the generation of records in the DB
func CreateRecord(db *gorm.DB) {
	user := User{Name: "Rober", Email: "rober@test.com", Password: "test", Role: "Admin"}
	result := db.Create(&user)

	if result.Error != nil {
		logrus.Fatalln("Not able to generate the record")
	}
}

// Query records in example function
func QueryRecord(db *gorm.DB, user User) {
	result := db.First(&user)

	if result.Error != nil {
		logrus.Println("Not record present")
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
	logrus.Info("Server running in port ", port)
	//err := http.ListenAndServe(port, handlers.CORS(handlers.AllowCredentials))

	err := http.ListenAndServe(port, handlers.CORS(handlers.AllowedHeaders([]string{"X-Requested-With", "Access-Control-Allow-Origin", "Content-Type", "Authorization"}), handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"}), handlers.AllowedOrigins([]string{"*"}))(router))
	if err != nil {
		log.Fatal(err)
	}
}

// -- ROUTES HANDLERS --

func SignUp(w http.ResponseWriter, r *http.Request) {
	connection := GetDatabase()
	defer Closedatabase(connection)

	user := User{}
	// Extract from the Body the Email/Password struct inputs and store into new memory address of new struct
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		var err Error
		err = SetError(err, "Error in reading body")
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		// Returns to the http response the Err struct in json format encoded
		json.NewEncoder(w).Encode(err)
		return
	}

	// Define a empty struct for the User
	loginuser := User{}

	// Retrieve the first matched record of a User (struct) in the database and compare it
	// with the user.Email that was sent in the POST request Body.
	// Use the Where GORM sentence for
	// Gorm Conditionals: https://gorm.io/docs/query.html#String-Conditions

	// Select first matched record email == user.Email() and store the result into the User{} struct
	// If the select is empty, the user/email is not present and you can create it
	connection.Where("email = ?", user.Email).First(&loginuser)

	// Check if the Email is already registered or not
	// If the output of the struct loginuser have NOT the Email empty after the Where clause
	// the email is already repeated
	if loginuser.Email != "" {
		// For debugging purposes
		logrus.Println("The User:", loginuser.Email, "with Password:", loginuser.Password)

		err := Error{}
		err = SetError(err, "Email already in use")
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		json.NewEncoder(w).Encode(err)
		return
	}

	logrus.Println("Generating the Password for user", user.Email)

	// Update to the user.Password param in struct the generated password
	user.Password, err = GeneratePass(user.Password)
	if err != nil {
		logrus.Fatalln("Error in password generation hash")
	}
	logrus.Println("Password: ", user.Password)

	// Create a new user with the struct of the User updated
	connection.Create(&user)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	// Return the request with the User struct
	json.NewEncoder(w).Encode(user)

}

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
		// Create a decoder with the request body and call the decode method with the pointer of the struct
		json.NewEncoder(w).Encode(err)
		return
	}

	authuser := User{}
	connection.Where("email = ?", authdetails.Email).First(&authuser)

}

// Home Page Handler
func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome to the Home Page [No Auth Required]\n"))
}

// -- HELPER FUNCTIONS --

func SetError(err Error, message string) Error {
	err.IsError = true
	err.Message = message
	return err
}

// Generate Password from a Hash
func GeneratePass(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	// fmt.Println(string(bytes))
	return string(bytes), err
}

func CheckPass(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		fmt.Println("Error during the Check Hash Password")
	}
	return err == nil
}

// Generate JWT Token based in the email and in the role
func GenerateJWT(email string, role string) (string, error) {

	// Add the signingkey and convert it to an array of bytes
	signingKey := []byte(secretkey)

	// Generate a token by HS256
	token := jwt.New(jwt.SigningMethodHS256)
	logrus.Info("JWT Token:", token)

	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true
	claims["email"] = email
	claims["role"] = role
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	tokenStr, err := token.SignedString(signingKey)
	if err != nil {
		logrus.Fatalln("Error during the Signing Token:", err.Error())
		return "", err
	}
	return tokenStr, err
}

// Main entry point function
func main() {
	InitialMigration()
	CreateRouter()
	InitializeRoute()
	StartServer()
}
