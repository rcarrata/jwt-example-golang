# JWT Example Golang

JWT example written in Golang 

## Initialize App

```
docker run --name postgres -p 5432:5432 -e POSTGRES_PASSWORD=1312 -d postgres
```

```
psql -h localhost -p 5432 -U postgres
create user userdb;
ALTER USER userdb WITH PASSWORD '1312';
\du
```

```
export PORT=8081
go run main.go
```

```
curl -X POST -H "Content-Type: application/json" -d '{"Name":"Rober", "Email":"rober15@test.com", "Password": "rober", "Role":"Admin"}' http://localhost:8081/signup | jq -r .
```

```
psql -h localhost -p 5432 -U postgres -W
SELECT * from users;
DELETE from users;
```

```
SELECT * FROM USERS WHERE email = 'rober1@test.com' ORDER BY id LIMIT 1;
```

```
curl -X POST -H "Content-Type: application/json" -d '{"Name":"Rober", "Email":"rober15@test.com", "Role":"Admin", "Password":"rober"}' http://localhost:8081/signin | jq -r .
