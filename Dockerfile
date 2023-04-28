FROM golang:alpine AS builder

WORKDIR /go/src/github.com/superfly/tokenizer
COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
COPY ./cmd/server ./cmd/server
RUN go build -o ./bin/server ./cmd/server

FROM alpine:latest AS runner
WORKDIR /root
COPY --from=builder /go/src/github.com/superfly/tokenizer/bin/server ./server
CMD ["./server"]
