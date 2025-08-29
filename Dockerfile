# Dockerfile
# --- build stage ---
FROM golang:1.24 AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/api ./cmd/api

# --- runtime stage (alpine с curl для healthcheck) ---
FROM alpine:3.20
RUN adduser -D -u 10001 appuser && apk add --no-cache curl
WORKDIR /app
ENV HTTP_ADDR=:8080
COPY --from=build /bin/api /bin/api
EXPOSE 8080
USER appuser
ENTRYPOINT ["/bin/api"]
