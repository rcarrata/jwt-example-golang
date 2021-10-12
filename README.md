# JWT Example Golang

JWT example written in Golang 

## Initialize App

```
docker run --name postgres -p 5432:5432 -e POSTGRES_PASSWORD=1312 -d postgres
```

```
docker exec -ti postgres create user userdb;
```

```
curl -X POST -H "Content-Type: application/json" -d '{"Email":"rober@test.com"}' http://localhost:8081/signup | jq -r .
```

