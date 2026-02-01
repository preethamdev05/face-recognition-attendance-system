FROM golang:1.21-alpine AS build

WORKDIR /app

COPY go.mod ./
COPY internal ./internal
COPY services/verification ./services/verification

RUN go build -o /verification ./services/verification

FROM alpine:3.19

RUN adduser -D -g '' appuser
USER appuser

COPY --from=build /verification /verification

EXPOSE 8080

ENTRYPOINT ["/verification"]
