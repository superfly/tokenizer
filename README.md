# Tokenizer

This is an HTTP proxy that injects third party authentication credentials into requests. Authentication secrets are stored in Vault along with metadata about how they may be used. The client includes a `Proxy-Tokenizer` header in requests, instructing the proxy where to inject API credentials. The proxy ensures the client is authorized to use the secret by validating the `Proxy-Authorization` header.

Here's an example secret that could be stored in Vault under the path `/tokenizer/stripe`

```json
{
    // The actual secret value
    "secret": "my-stripe-api-key",

    // How the proxy should authenticate the client.
    "authorizer": "secret",

    // Which "processor" the proxy should use for getting the secret into
    // requests.
    "processor": "inject"
}
```

The client configures their HTTP library to use the tokenizer service as it's HTTP proxy:

```ruby
conn = Faraday.new(
    proxy: "http://tokenizer.flycast", 
    headers: {
        proxy_tokenizer: "foo", 
        proxy_authorization: "Bearer myproxysecret"
    }
)

conn.get("http://api.stripe.com")
```

The request will get rewritten to look like this:

```http
GET / HTTP/1.1
Host: api.stripe.com
Authorization: my-stripe-api-key
```

The `Proxy-Tokenizer` header instructs the proxy to lookup and use the secret named `foo`. The `Proxy-Authorization` header satisfies the includes the token that authenticates the client to the proxy.

Notice that our eventual request is to _http_://api.stripe.com. In order for the proxy to be able to inject credentials into requests we need to speak plain HTTP to the proxy server, not HTTPS. The proxy transparently switches to HTTPS for connections to upstream services. We could use HTTPS for communication between the client and the proxy server, but flycast is already going over WireGuard and it's simpler to use HTTP.

## Processors

Processors dictate how the secret in vault get's turned into valid credentials for a request and are added to the request. The example above uses the `inject` processor (configured in the Vault secret), which simply injects the verbatim secret into a request header. By default, this injects the secret into the `Authorization` header without further processing.

The client can include parameters to change this behavior though:

```ruby
conn.headers[:proxy_tokenizer] = 'foo; {"dst": "My-Custom-Header", "fmt": "Bearer %s"}'
conn.get("http://api.stripe.com")
```

The request will get rewritten to look like this:

```http
GET / HTTP/1.1
Host: api.stripe.com
My-Custom-Header: Bearer my-stripe-api-key
```

The parameters are supplied as JSON in the `Proxy-Tokenizer` header after the secret name. The `dst` parameter instructs the processor to put the secret in the `My-Custom-Header` header and the `fmt` parameter is a printf-style format string that is applied to the secret.

Aside from the `inject` processor, we have the `inject-hmac` processor. This uses the secret from Vault as the key for creating an HMAC signature which is then injected into a request header. The hash algorithm can be specified in the Vault secret under the key `hash` and defaults to SHA256. This processor signs the verbatim request body by default, but can sign custom messages specified in the `msg` parameter in the `Proxy-Tokenizer` header. It also respects the `dst` and `fmt` parameters.