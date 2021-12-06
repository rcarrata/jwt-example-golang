# JWT Example Golang

JWT example written in Golang 

## Install & Usage

* Run a Postgresql exposing the port to 5432 and defining a Postgres Password:

```
docker run --name postgres -p 5432:5432 -e POSTGRES_PASSWORD=1312 -d postgres
```

* Define an local user for the app:
```
psql -h localhost -p 5432 -U postgres
create user userdb;
ALTER USER userdb WITH PASSWORD '1312';
\du
```

* Export the PORT to run the server and run the app:
```
export PORT=8081
go run main.go
```

* Define a signup with the Name, Email, Password and Role in the /signup path of the API:
```
curl -X POST -H "Content-Type: application/json" -d '{"Name":"Rober", "Email":"rober16@test.com", "Password": "rober", "Role":"admin"}' http://localhost:8081/signup | jq -r .
```

* Check into the DB if it's the user is generated and stored properly:
```
psql -h localhost -p 5432 -U postgres -W
SELECT * from users;
# (Only for clean!) 
DELETE from users; 
```

* Perform a Select of the user generated in step before:
```
SELECT * FROM USERS WHERE email = 'rober16@test.com' ORDER BY id LIMIT 1;
```

* Signing with the Email / Password, and receive a Token JWT:

```
curl -X POST -H "Content-Type: application/json" -d '{"Email":"rober16@test.com","Password":"rober"}' http://localhost:8081/signin | jq -r .

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdXRob3JpemVkIjp0cnVlLCJlbWFpbCI6InJvYmVyMTVAdGVzdC5jb20iLCJleHAiOjE2Mzg3MjkxODgsInJvbGUiOiJBZG1pbiJ9.OPl3zntUt8CNj2jq7iNsJfJIlgGKQDWf7pyFdrRfjWs
```

```
TOKEN=$(curl -X POST -H "Content-Type: application/json" -d '{"Name":"Rober", "Email":"rober16@test.com", "Role":"admin", "Password":"rober"}' http://localhost:8081/signin | jq -r .)

```
curl -H "Content-Type: application/json" -H ""Token": $TOKEN" http://localhost:8082/admin
Welcome, Admin.
```