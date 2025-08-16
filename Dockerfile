FROM --platform=linux/amd64 golang:latest AS builder

RUN apt-get update && apt-get install -y clang lld

ARG SERVICE=server
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ENV CGO_ENABLED=1
ENV CC=clang
ENV CGO_LDFLAGS=-fuse-ld=lld
RUN go build -o main cmd/${SERVICE}/main.go

FROM --platform=linux/amd64 alpine:latest

RUN apk add --no-cache libc6-compat

WORKDIR /app
COPY --from=builder /app/main .
