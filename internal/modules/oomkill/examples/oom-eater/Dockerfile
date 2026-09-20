FROM golang:1.24

WORKDIR /app

COPY main.go .

RUN go build -o oom-eater main.go

CMD ["./oom-eater"]
