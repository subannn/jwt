FROM golang:alpine AS builder

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 go build -o main main.go

FROM alpine:latest

WORKDIR /app

# Копируем исполняемый файл и .env из этапа сборки
COPY --from=builder /app/main /app
COPY --from=builder /app/.env /app

CMD ["/app/main"]
