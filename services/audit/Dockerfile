FROM golang:1.21-alpine AS build

WORKDIR /app

COPY go.mod ./
COPY internal ./internal
COPY services/audit ./services/audit

RUN go build -o /audit ./services/audit

FROM alpine:3.19

RUN adduser -D -g '' appuser
USER appuser

COPY --from=build /audit /audit

EXPOSE 8080

ENTRYPOINT ["/audit"]
