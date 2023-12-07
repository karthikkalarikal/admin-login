# Use the official Golang Alpine image as the builder stage
# build stage
FROM golang:1.21.3-alpine3.18 AS builder


WORKDIR /app
COPY . .

RUN go build -o main -v web/*.go

# Final stage
FROM alpine:3.18

WORKDIR /app
COPY --from=builder /app/main .

CMD ["./main"]
