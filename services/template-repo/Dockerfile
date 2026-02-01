FROM golang:1.21-alpine AS build

WORKDIR /app

COPY go.mod ./
COPY internal ./internal
COPY services/template-repo ./services/template-repo

RUN go build -o /template-repo ./services/template-repo

FROM alpine:3.19

RUN adduser -D -g '' appuser
USER appuser

COPY --from=build /template-repo /template-repo

EXPOSE 8080

ENTRYPOINT ["/template-repo"]
