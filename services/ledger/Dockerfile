FROM golang:1.21-alpine AS build

WORKDIR /app

COPY go.mod ./
COPY internal ./internal
COPY services/ledger ./services/ledger

RUN go build -o /ledger ./services/ledger

FROM alpine:3.19

RUN adduser -D -g '' appuser
USER appuser

COPY --from=build /ledger /ledger

EXPOSE 8080

ENTRYPOINT ["/ledger"]
