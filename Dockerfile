FROM golang:1.17 AS builder

WORKDIR /go/src/app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN GCO_ENABLED=0 -o /go/bin/app

FROM gcr.io/distroless/static

COPY --from=builder /go/bin/app /

CMD ["/app"]
