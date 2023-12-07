# Use the official Golang Alpine image as the builder stage
# build stage
FROM golang:1.21.3-alpine3.18 AS builder


WORKDIR /app
COPY . /app
COPY templates /app/templates

RUN go mod download

# Set env variable to indicate its running in a container
ENV CONTAINERIZED=true


RUN go build -o main -v web/*.go

# Final stage
FROM alpine:3.18

WORKDIR /app
COPY --from=builder /app/main .
COPY --from=builder /app/templates /app/templates

EXPOSE 8081

COPY .env /app/.env

CMD ["./main"]
