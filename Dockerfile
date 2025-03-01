FROM golang:1.24 AS builder

WORKDIR /app

COPY go.mod go.sum /app/
COPY cmd/ /app/cmd/
COPY main.go /app/main.go
RUN go mod download
RUN go mod tidy

RUN CGO_ENABLED=0 GOOS=linux go build -o ldap-proxy *.go

FROM ubuntu:22.04
USER root

COPY --from=builder /app/ldap-proxy /app/ldap-proxy

WORKDIR /app

ENTRYPOINT ["/app/ldap-proxy"]
