FROM golang:latest AS builder

ARG SERVICE=server
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN wget https://github.com/vultisig/go-wrappers/archive/refs/heads/master.tar.gz
RUN tar -xzf master.tar.gz
RUN mkdir -p /usr/local/lib/includes/linux
RUN cp -a go-wrappers-master/includes/linux/. /usr/local/lib/includes/linux/.

ENV CGO_ENABLED=0
RUN go build -o main cmd/${SERVICE}/main.go

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/main .
