FROM golang:alpine AS builder

WORKDIR /go/src/github.com/superfly/tokenizer
COPY go.mod go.sum ./
RUN go mod download

# prebuild big deps so they're cached...
RUN go build github.com/hashicorp/vault/api
RUN go build github.com/elazarl/goproxy

COPY *.go ./
COPY ./cmd ./cmd
COPY ./processors ./processors
RUN go build -o ./bin/server ./cmd/server

FROM alpine:latest AS runner
WORKDIR /root
COPY --from=builder /go/src/github.com/superfly/tokenizer/bin/server ./server
CMD ["./server"]
