FROM golang:latest AS builder

ARG SERVICE
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN wget https://github.com/vultisig/go-wrappers/archive/refs/heads/master.tar.gz
RUN tar -xzf master.tar.gz && \
    cd go-wrappers-master && \
    mkdir -p /usr/local/lib/dkls && \
    cp --recursive includes /usr/local/lib/dkls
ENV LD_LIBRARY_PATH=/usr/local/lib/dkls/includes/linux/:${LD_LIBRARY_PATH:-}

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o main cmd/${SERVICE}/main.go

FROM alpine:latest

WORKDIR /app

COPY --from=builder /usr/local/lib/dkls /usr/local/lib/dkls
ENV LD_LIBRARY_PATH=/usr/local/lib/dkls/includes/linux/:${LD_LIBRARY_PATH:-}

COPY --from=builder /app/main .
