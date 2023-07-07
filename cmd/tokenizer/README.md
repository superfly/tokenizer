# github.com/superfly/tokenizer/cmd/tokenizer

Package for running a tokenizer HTTP proxy.

## Production deployment

See the README in the top-level `github.com/superfly/tokenizer` package.

## Testing

To run a test server locally:

```shell
# load example LISTEN_ADDRESS and OPEN_KEY environment variables
source ./.envrc

# run server
go run .
```

The `github.com/superfly/tokenizer/cmd/curl` package has instructions for sending requests via this server with a test client.