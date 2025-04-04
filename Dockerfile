# Build stage
FROM golang:1.23-alpine AS builder

RUN apk --no-cache add git build-base

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o tellix ./tellix.go

# Final image
FROM alpine:3.18

RUN apk --no-cache add ca-certificates
RUN addgroup -S app && adduser -S app -G app

WORKDIR /app
RUN mkdir -p /tmp/tellix && chown -R app:app /tmp/tellix

COPY --from=builder /app/tellix .

RUN chmod +x /app/tellix
USER app
CMD ["./tellix"]

