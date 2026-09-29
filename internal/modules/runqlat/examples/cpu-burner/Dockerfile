FROM golang:1.24

WORKDIR /app

COPY main.go .

RUN go build -o cpu-burner main.go

ENTRYPOINT ["./cpu-burner"]
