# github.com/superfly/tokenizer/cmd/curl

This is an example client for making requests against a tokenizer server.

Assuming you've followed the instructions for starting a test server in `github.com/superfly/tokenizer/cmd/tokenizer`, you can send a test request like so:

```shell
# load example PROXY_URL and SEAL_KEY environment variables
source ./.envrc

# use $SEAL_KEY to encrypt the secret "trustno1".
# Stores the sealed secret in $SEALED_SECRET and auth token in $AUTH_TOKEN
eval $(go run . gen trustno1)

# send the secret in a request to https://httpbin.org/get
go run . http://httpbin.org/get

# output:
#    {
#    "args": {},
#    "headers": {
#        "Accept-Encoding": "gzip",
#        "Authorization": "Bearer trustno1",
#        "Host": "httpbin.org",
#        "User-Agent": "Go-http-client/1.1",
#        "X-Amzn-Trace-Id": "Root=1-64a81969-74f0804e26d8ebca31735213"
#    },
#    "origin": "97.118.205.196",
#    "url": "https://httpbin.org/get"
#    }
```