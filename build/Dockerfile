FROM registry.apk-group.net/mirror/golang:1.23 AS builder
ENV GOPROXY="https://swap-repository.apk-group.net/go, direct"
WORKDIR /app
COPY go.mod ./
COPY go.sum ./
RUN go mod tidy
COPY . .
RUN GOPROXY=https://goproxy.cn CGO_ENABLED=0 go build -ldflags="-s -w" -o asset_discovery_backend cmd/asset_discovery/main.go

# Runner stage
FROM registry.apk-group.net/mirror/alpine:3.21.3 AS deploy
RUN apk add --no-cache tzdata
RUN apk add --no-cache iputils
ENV TZ=Asia/Tehran
RUN mkdir -p /etc/siem/certs/
RUN apk add --no-cache openssl && \
        openssl req -x509 -nodes -days 365 -subj "/CN=localhost" \
        -newkey rsa:2048 -keyout /etc/siem/certs/key.pem -out /etc/siem/certs/cert.pem \
        -addext "subjectAltName=DNS:localhost,DNS:asset_discovery_backend"
RUN apk update && apk add --no-cache nmap
WORKDIR /usr/share/siem/asset_discovery
COPY --from=builder /app/asset_discovery_backend .
EXPOSE 2030
CMD ["./asset_discovery_backend", "--config" , "/etc/siem/asset_discovery/config.yml"]
