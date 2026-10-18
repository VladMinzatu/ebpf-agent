FROM golang:1.24

WORKDIR /app

COPY main.go .

# A plain go build keeps the DWARF that watch resolves -sym with: don't add
# -ldflags="-s -w".
RUN go build -o go-counter main.go

CMD ["./go-counter"]
