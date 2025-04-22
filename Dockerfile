# Build stage
FROM golang:1.23-alpine AS builder

RUN apk --no-cache add git build-base

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o mcp-recon ./mcp-recon.go

# Final image
FROM alpine:3.18

RUN apk --no-cache add ca-certificates
RUN addgroup -S app && adduser -S app -G app

WORKDIR /app
RUN mkdir -p /tmp/mcp-recon && chown -R app:app /tmp/mcp-recon

COPY --from=builder /app/mcp-recon .

RUN chmod +x /app/mcp-recon
USER app
CMD ["./mcp-recon"]

