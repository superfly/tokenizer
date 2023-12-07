FROM golang:1.21-alpine AS builder

WORKDIR /go/src/github.com/superfly/tokenizer
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build \
	--mount=type=cache,target=/go/pkg \
    go mod download

COPY VERSION ./
COPY *.go ./
COPY ./macaroon ./macaroon
COPY ./cmd/tokenizer ./cmd/tokenizer
RUN --mount=type=cache,target=/root/.cache/go-build \
	--mount=type=cache,target=/go/pkg \
    go build -ldflags "-X 'main.Version=$(cat VERSION)' -X 'main.FilteredHeaders=Fly-Client-Ip,Fly-Forwarded-Port,Fly-Forwarded-Proto,Fly-Forwarded-Ssl,Fly-Region,Fly-Request-Id,Fly-Traceparent,Fly-Tracestate'" -buildvcs=false -o ./bin/tokenizer ./cmd/tokenizer

FROM alpine:latest AS runner
WORKDIR /root
COPY --from=builder /go/src/github.com/superfly/tokenizer/bin/tokenizer /usr/local/bin/tokenizer
CMD ["tokenizer"]
