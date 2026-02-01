FROM golang:1.21-alpine AS build

WORKDIR /app

COPY go.mod ./
COPY internal ./internal
COPY services/capture ./services/capture

RUN go build -o /capture ./services/capture

FROM alpine:3.19

RUN adduser -D -g '' appuser
USER appuser

COPY --from=build /capture /capture

EXPOSE 8080

ENTRYPOINT ["/capture"]
