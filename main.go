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

// ------- GLOBAL VARS -------

var (
	router    *mux.Router
	secretkey string = "secretkeyjwt"
)

// ------- STRUCTS -------
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

// ------- DATABASE FUNCTIONS -------
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

// ------- MIDDLEWARE FUNCTIONS -------

// isAuthOk returns a handler that executes some logic,
// and then calls the next handler.

func isAuthOk(handler http.HandlerFunc) http.HandlerFunc {

	// this middleware function uses an anonymous function to simplify
	return func(w http.ResponseWriter, r *http.Request) {

		if r.Header["Token"] == nil {
			var err Error
			err = SetError(err, "No Token Found")
			// Returns to the http response the Err struct in json format encoded
			json.NewEncoder(w).Encode(err)
		}

		// Define the SigningKey var and convert this secretkey into byte
		var newSigningKey = []byte(secretkey)

		// Received Token from the Header when the request is performed
		receivedToken := r.Header["Token"][0]
		logrus.Println(receivedToken)

		// Parsing and Validating the token received in the request using the HMAC signing method
		// https://pkg.go.dev/github.com/golang-jwt/jwt@v3.2.2+incompatible#Parse
		token, err := jwt.Parse(receivedToken, func(token *jwt.Token) (interface{}, error) {

			// Parse takes the token string and a function for looking up the key. The latter is especially
			// useful if you use multiple keys for your application.
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				// Validate the Token and return an error if the signing token is not the proper one
				// TODO: change fmt -> logrus
				return nil, fmt.Errorf("unexpected signing method: %v in token of type: %v", token.Header["alg"], token.Header["typ"])
			}

			// logrus.Println(token.Header["alg"])
			// logrus.Println(token.Header["typ"])
			return newSigningKey, nil
		})

		// If the token Parser have an error the Token is considered as Expired
		// TODO: Improve with the jwt.ValidationErrorMalformed
		if err != nil {
			var err Error
			err = SetError(err, "Your Token has been expired")
			// Returns to the http response the Err struct in json format encoded
			json.NewEncoder(w).Encode(err)
			return
		}

		// claims are actually a map[string]interface{}
		// Check if the token provided is Valid
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			logrus.Println("Token is Valid")
			logrus.Println(claims["role"])
			if claims["role"] == "admin" {
				logrus.Println("Assigned Token role to Admin")
				r.Header.Set("Role", "admin")
				handler.ServeHTTP(w, r)
				return
			} else if claims["role"] == "user" {
				logrus.Println("Assigned Token role to User")
				r.Header.Set("Role", "user")
				handler.ServeHTTP(w, r)
				return
			} else {
				var err Error
				err = SetError(err, "Role Not Authorized.")
				// Returns to the http response the Err struct in json format encoded
				json.NewEncoder(w).Encode(err)
			}
		}
	}
}

func AdminIndex(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Role") != "admin" {
		w.Write([]byte("You are not authorized. Admin Only!"))
		return
	}
	w.Write([]byte("Welcome, Admin."))
}

func UserIndex(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Role") != "user" {
		w.Write([]byte("Not authorized. User Only!!"))
		return
	}
	w.Write([]byte("Welcome, User."))
}

// ------- ROUTES -------
// CreateRouter generates a new instance of Mux Router
func CreateRouter() {
	router = mux.NewRouter()
}

// Home Page Handler (No Auth Required)
func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome to the Home Page [No Auth Required]\n"))
}

// Time Page Handler (No Auth Required)
func timeHandler(w http.ResponseWriter, r *http.Request) {
	tm := time.Now().Format(time.RFC1123)
	w.Write([]byte("The time is: " + tm))
}

// InitializeRoute creates handlers for the mux Router to handle
func InitializeRoute() {
	router.HandleFunc("/", homeHandler).Methods("GET")
	router.HandleFunc("/time", timeHandler).Methods("GET")
	router.HandleFunc("/signup", SignUp).Methods("POST")
	router.HandleFunc("/signin", SignIn).Methods("POST")
	router.HandleFunc("/admin", isAuthOk(AdminIndex)).Methods("GET")

	// Option Methods
	router.Methods("OPTIONS").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, Access-Control-Request-Headers, Access-Control-Request-Method, Connection, Host, Origin, User-Agent, Referer, Cache-Control, X-header")
	})
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

// ------- ROUTES HANDLERS -------

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
	// Connect to the Database
	connection := GetDatabase()

	// Defer the close of the Database to the end of the
	defer Closedatabase(connection)

	// Read from Request Body the auth input email and pass and store it in a Struct Authentication
	var authdetails Authentication
	err := json.NewDecoder(r.Body).Decode(&authdetails)

	// Raise an error if the Body is not well formatted or if have not the proper structure
	if err != nil {
		var err Error
		err = SetError(err, "Error in reading body")
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		// Create a decoder with the request body and call the decode method with the pointer of the struct
		json.NewEncoder(w).Encode(err)
		return
	}

	// Authuser struct defined to store values from the DB
	authuser := User{}
	// Check the email that the User sends when sends the request, and it's stored in the Authentication struct defined before
	connection.Where("email = ?", authdetails.Email).First(&authuser)

	// If the User/Email is empty represents that the email introduced are not present into the database.
	if authuser.Email == "" {
		var err Error
		err = SetError(err, "Your email is not registered. Please first do the signup!")
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		json.NewEncoder(w).Encode(err)
		return
	}

	logrus.Info("Authdetails - User Request: ", authdetails.Password)
	logrus.Info("AuthUser - DB Stored: ", authuser.Password)
	// authdetails struct storing values from the User request to the API
	check := CheckPass(authdetails.Password, authuser.Password)

	// Check if the bool of the return err from the CheckPass is nil
	if !check {
		var err Error
		err = SetError(err, "Username or Password is incorrect. Please review them!")
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		json.NewEncoder(w).Encode(err)
		return
	}

	// Generate the JWT Token using the Email from the authuser Email and Roles stored into the DB
	validToken, err := GenerateJWT(authuser.Email, authuser.Role)
	if err != nil {
		var err Error
		err = SetError(err, "Failed to generate the token")
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		json.NewEncoder(w).Encode(err)
		return
	}

	// Initialize a empty Token struct in a variable token
	token := Token{}
	// Define the email and role that is stored in the DB
	token.Email = authuser.Email
	token.Role = authuser.Role
	// Define the TokenString with the value of the Token generated
	token.TokenString = validToken
	logrus.Info("Generated JWT Token: ", token.TokenString)

	// Send the TokenString generated back to the user as response of the signin
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	json.NewEncoder(w).Encode(token.TokenString)

}

// ------- HELPER FUNCTIONS -------

func SetError(err Error, message string) Error {
	err.IsError = true
	err.Message = message
	return err
}

// Generate Password from a Hash
func GeneratePass(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	// logrus.Println(string(bytes))
	return string(bytes), err
}

func CheckPass(password string, hash string) bool {
	// CompareHashAndPassword compares a bcrypt hashed password with its possible plaintext equivalent.
	// Returns nil on success, or an error on failure.
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	// If it's OK, set the error to bool nil / empty
	return err == nil
}

// JWT are divided in three separated elements:
// - Header: consists in two parts (JWT + Signign Algorithm) in json format, encoded in base64url
// - Payload: contains the Claims (usually the user) and other additional data
// - Signature: result of Header + Payload encoded, a secret, the signing algorithm and signing the Header + Payload

// Generate JWT Token based in the email and in the role as input. Creates a token by the algorithm signing method (HS256) and adds authorized email,
// role, and exp into claims.
// Claims are pieces of info added into the tokens.
func GenerateJWT(email string, role string) (string, error) {

	// Add the signingkey and convert it to an array of bytes
	signingKey := []byte(secretkey)

	// Generate a token with the HS256 as the Signign Method
	token := jwt.New(jwt.SigningMethodHS256)
	// logrus.Info("JWT Token: ", token) // Debug purposes

	// jwt library defines a struct with the MapClaims for define the different claims
	// to include in our token payload content in key-value format
	claims := token.Claims.(jwt.MapClaims)

	// TODO: Explore the token.jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims("key": "value")}
	// https://pkg.go.dev/github.com/golang-jwt/jwt@v3.2.2+incompatible#example-New-Hmac

	// Adding to the claims Map, authorized, the email, role and exp
	claims["authorized"] = true
	claims["email"] = email
	claims["role"] = role
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	// To Debug Claims
	// logrus.Println("claims auth", claims["authorized"])
	// logrus.Println("claims email", claims["email"])
	// logrus.Println("claims role", claims["role"])
	// logrus.Println("claims time", claims["exp"])

	// Sign the token with the signingkey defined in the step before
	tokenStr, err := token.SignedString(signingKey)
	if err != nil {
		logrus.Fatalln("Error during the Signing Token:", err.Error())
		return "", err
	}
	// For debugging purposes
	logrus.Println("Token Signed: ", tokenStr)

	return tokenStr, err

	// TODO: add Parser Token to increase the security purposes
}

// Main entry point function
func main() {
	InitialMigration()
	CreateRouter()
	InitializeRoute()
	StartServer()
}
