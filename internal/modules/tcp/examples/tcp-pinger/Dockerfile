FROM golang:1.24

WORKDIR /app

COPY main.go .

RUN go build -o tcp-pinger main.go

CMD ["./tcp-pinger"]
