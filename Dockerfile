FROM --platform=linux/amd64 golang:1.24.2 AS builder

RUN apt-get update && apt-get install -y clang lld wget

RUN wget https://github.com/vultisig/go-wrappers/archive/refs/heads/master.tar.gz && \
    tar -xzf master.tar.gz && \
    cd go-wrappers-master && \
    mkdir -p /usr/local/lib/dkls && \
    cp -r includes /usr/local/lib/dkls

ARG SERVICE
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ENV CGO_ENABLED=1
ENV CC=clang
ENV CGO_LDFLAGS=-fuse-ld=lld
ENV LD_LIBRARY_PATH=/usr/local/lib/dkls/includes/linux:$LD_LIBRARY_PATH
RUN go build -o main cmd/${SERVICE}/main.go

FROM --platform=linux/amd64 ubuntu:22.04

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/main .
COPY --from=builder /usr/local/lib/dkls /usr/local/lib/dkls
ENV LD_LIBRARY_PATH=/usr/local/lib/dkls/includes/linux:$LD_LIBRARY_PATH
