FROM golang:1.24

WORKDIR /app

COPY main.go .

RUN go build -o writer main.go

CMD ["./writer"]