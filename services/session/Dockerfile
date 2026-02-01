FROM golang:1.21-alpine AS build

WORKDIR /app

COPY go.mod ./
COPY internal ./internal
COPY services/session ./services/session

RUN go build -o /session ./services/session

FROM alpine:3.19

RUN adduser -D -g '' appuser
USER appuser

COPY --from=build /session /session

EXPOSE 8080

ENTRYPOINT ["/session"]
