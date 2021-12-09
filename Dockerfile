FROM golang:1.17 as build
WORKDIR /rck-auth
COPY main.go .
COPY go.mod .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

FROM scratch
COPY --from=0 /rck-auth/app .
EXPOSE 8080
CMD ["/app"]