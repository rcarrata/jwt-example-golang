# JWT Example Golang

JWT example written in Golang 

## Install

* Run a Postgresql exposing the port to 5432 and defining a Postgres Password:

```
podman run --name postgres -p 5432:5432 -e POSTGRES_PASSWORD=1312 -d postgres
```

* Define an local user for the app:
```
psql -h localhost -p 5432 -U postgres
create user userdb;
ALTER USER userdb WITH PASSWORD '1312';
\du
```

* (OPTIONAL) - Export the PORT to run the server and run the app:
```
export PORT=8081
go run main.go
```

* Build the container with the Dockerfile:

```
podman build -t localhost/rck-auth:ubi8 -f Dockerfile.ubi8
```

* Run the container, defining the DB_HOST (in my case cni_podman IP) running the PSQL:

```
podman run -dt -p 8080:8080 -e PORT=8082 -e DB_HOST=10.88.0.1 localhost/rck-auth:ubi8
```

* Check that everything is working ok:

```
podman ps -a

72d802cc3b54  docker.io/library/postgres:latest                             postgres              4 hours ago    Up 4 hours ago    0.0.0.0:5432->5432/tcp  postgres
56964a619719  localhost/rck-auth:ubi8                                       /app                  9 minutes ago  Up 9 minutes ago  0.0.0.0:8080->8080/tcp  app
```

## Usage:

* Define a signup with the Name, Email, Password and Role in the /signup path of the API:
```
curl -X POST -H "Content-Type: application/json" -d '{"Name":"Rober", "Email":"rober16@test.com", "Password": "rober", "Role":"admin"}' http://localhost:8082/signup | jq -r .
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
curl -X POST -H "Content-Type: application/json" -d '{"Email":"rober16@test.com","Password":"rober"}' http://localhost:8082/signin | jq -r .

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdXRob3JpemVkIjp0cnVlLCJlbWFpbCI6InJvYmVyMTVAdGVzdC5jb20iLCJleHAiOjE2Mzg3MjkxODgsInJvbGUiOiJBZG1pbiJ9.OPl3zntUt8CNj2jq7iNsJfJIlgGKQDWf7pyFdrRfjWs
```

* Retrieve the token and save it in a variable:

```
TOKEN=$(curl -X POST -H "Content-Type: application/json" -d '{"Name":"Rober", "Email":"rober16@test.com", "Role":"admin", "Password":"rober"}' http://localhost:8082/signin | jq -r .)
```

* Login with the token towards the /admin:

```
curl -H "Content-Type: application/json" -H ""Token": $TOKEN" http://localhost:8082/admin
Welcome, Admin.
```

* Try to login to the /user with the Role: Admin:

```
curl -H "Content-Type: application/json" -H ""Token": $TOKEN" http://localhost:8082/user -v
*   Trying ::1:8082...
* Connected to localhost (::1) port 8082 (#0)
> GET /user HTTP/1.1
> Host: localhost:8082
> User-Agent: curl/7.71.1
> Accept: */*
> Content-Type: application/json
> Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdXRob3JpemVkIjp0cnVlLCJlbWFpbCI6InJvYmVyMTZAdGVzdC5jb20iLCJleHAiOjE2MzkwNzgyMTEsInJvbGUiOiJhZG1pbiJ9.ZeCTW1GoA8WLEcQW6WiZo6F9FUsHCkthIGPfmnQDar8
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 403 Forbidden
< Date: Thu, 09 Dec 2021 19:04:11 GMT
< Content-Length: 27
< Content-Type: text/plain; charset=utf-8
<
* Connection #0 to host localhost left intact
Not authorized. User Only!
```

as you can see the Role used is not authorized, and a 403 Forbidden error is raised.