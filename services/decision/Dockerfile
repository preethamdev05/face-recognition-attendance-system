FROM golang:1.21-alpine AS build

WORKDIR /app

COPY go.mod ./
COPY internal ./internal
COPY services/decision ./services/decision

RUN go build -o /decision ./services/decision

FROM alpine:3.19

RUN adduser -D -g '' appuser
USER appuser

COPY --from=build /decision /decision

EXPOSE 8080

ENTRYPOINT ["/decision"]
