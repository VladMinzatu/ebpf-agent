FROM golang:1.24

# exe (go build's default on Linux) or pie, to try watch on both.
ARG BUILDMODE=exe

WORKDIR /app

COPY main.go .

# A plain go build keeps the DWARF that watch resolves -sym with: don't add
# -ldflags="-s -w".
RUN go build -buildmode=$BUILDMODE -o go-counter main.go

CMD ["./go-counter"]
