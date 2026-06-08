FROM golang:1.21-alpine AS builder

RUN apk --no-cache add git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /k8s-policy-enforcer ./cmd/k8s-policy-enforcer

FROM alpine:3.19

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /k8s-policy-enforcer .

ENTRYPOINT ["/app/k8s-policy-enforcer"]
CMD ["--help"]
