# Tokenizer

This is an HTTP proxy that injects third party authentication credentials into requests. Clients encrypt third party secrets using the proxy's public key. When the client wants to send a request to the third party service, it does so via the proxy, sending along the encrypted secret in the `Proxy-Tokenizer` header. The proxy decrypts the secret and injects it into the client's request. To ensure that encrypted secrets can only be used by authorized clients, the encrypted data also includes instructions on authenticating the client. 

Here's an example secret that the client encrypts using the proxy's public key:

```ruby
secret = {
    inject_processor: {
        token: "my-stripe-api-token"
    },
    bearer_auth: {
        digest: Digest::SHA256.base64digest('trustno1')
    }
}

seal_key = ENV["TOKENIZER_PUBLIC_KEY"]
sealed_secret = RbNaCl::Boxes::Sealed.new(seal_key).box(secret.to_json)
```

The client configures their HTTP library to use the tokenizer service as it's HTTP proxy:

```ruby
conn = Faraday.new(
    proxy: "http://tokenizer.flycast", 
    headers: {
        proxy_tokenizer: Base64.encode64(sealed_secret),
        proxy_authorization: "Bearer trustno1"
    }
)

conn.get("http://api.stripe.com")
```

The request will get rewritten to look like this:

```http
GET / HTTP/1.1
Host: api.stripe.com
Authorization: Bearer my-stripe-api-token
```

Notice that the client's request is to _http_://api.stripe.com. In order for the proxy to be able to inject credentials into requests we need to speak plain HTTP to the proxy server, not HTTPS. The proxy transparently switches to HTTPS for connections to upstream services. We could use HTTPS for communication between the client and the proxy server, but flycast already uses WireGuard and the redundant encryption would only complicate things.

## Processors

The processor dictates how the encrypted secret gets turned into a credential and added to the request. The example above uses `inject_processor`, which simply injects the verbatim secret into a request header. By default, this injects the secret into the `Authorization` header without further processing.

The client can include parameters to change this behavior though:

```ruby
processor_params = {
    dst: "My-Custom-Header", 
    fmt: "FooBar %s"
}

conn.headers[:proxy_tokenizer] = "#{Base64.encode64(sealed_secret)}; #{processor_params.to_json}"

conn.get("http://api.stripe.com")
```

The request will get rewritten to look like this:

```http
GET / HTTP/1.1
Host: api.stripe.com
My-Custom-Header: FooBar my-stripe-api-key
```

The parameters are supplied as JSON in the `Proxy-Tokenizer` header after the encrypted secret. The `dst` parameter instructs the processor to put the secret in the `My-Custom-Header` header and the `fmt` parameter is a printf-style format string that is applied to the secret.

Aside from `inject_processor`, we also have `inject_hmac_processor`. This creates an HMAC signatures using the key stored in the encrypted secret and injects that into a request header. The hash algorithm can be specified in the secret under the key `hash` and defaults to SHA256. This processor signs the verbatim request body by default, but can sign custom messages specified in the `msg` parameter in the `Proxy-Tokenizer` header. It also respects the `dst` and `fmt` parameters.

```ruby
secret = {
    inject_hmac_processor: {
        key: "my signing key",
        hash: "sha256"
    },
    bearer_auth: {
        digest: Digest::SHA256.base64digest('trustno1')
    }
}
```

## Host allowlist

If a client is fully compromised, the attacker could send encrypted secrets via tokenizer to a service that simply echoes back the request. This way, the attacker could learn the plaintext value of the secret. To mitigate against this, secrets can specify which hosts they may be used against. 

```ruby
secret = {
    inject_processor: {
        token: "my-stripe-api-token"
    },
    bearer_auth: {
        digest: Digest::SHA256.base64digest('trustno1')
    },
    allowed_hosts: ["api.stripe.com"],
    # or
    # allowed_host_pattern: ".*\.stripe\.com$"
}
```
