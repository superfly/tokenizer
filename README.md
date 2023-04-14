We integrate with third parties, which necessitates talking to third party APIs, which necessitates having third party API tokens. API tokens are scary because bad things happen when they're leaked/stolen.

To make this less scary, we could build an HTTP proxy that injects API tokens into requests for us, much akin to credit card tokenization. Web can store API tokens in Vault and connect to third party APIs via this tokenizer proxy. The proxy would inject API tokens into the right parts of requests while forwarding them to the third party API.

There are a few tricky bits we'd need to figure out:

### Injecting tokens

The proxy needs to know where in client requests to inject tokens and which tokens to inject. I propose we specify ax HTTP header like this

```
X-Tokenizer-Replace: <nonce>=<vault secret name>
```

Here, `nonce` is a random string that's generated per-request. Tokenizer receives this header in the `CONNECT` request and replaces all occurrences of `nonce` with the token stored in vault under `vault secret name` for the duration of the proxy connection.

### Authenticating/authorizing proxy clients

We need to know who the HTTP client is and that they're authorized to use the API token.

For tokens that we only envision being used while we're talking to the user, we can use macaroons for authentication. Alongside the token in vault, we can store a macaroon "fact" (see [this doc](https://flyio.slab.com/posts/macaroon-concepts-facts-and-caveats-fewldfsy) if that terminology is new to you). Our HTTP `CONNECT` request to the proxy would then include a user macaroon in the `Proxy-Authorization` header. The tokenizer would validate any facts found alongside the API token in vault using the provided macaroon.

For example, if we only want to use this token when interacting with users that have read access to org 123, we would store `{"orgId": 123, "action": "r"}` alongside the API token. Authorized users' macaroons would satisfy this fact.

If we envision making calls to the third party API when we're _not_ talking to a user, we could authenticate the HTTP client with a static secret that is shared between the tokenizer and the proxy client (web). Instead of storing a fact alongside the token in Vault, we could store some indication that this token can be used with the shared secret.

### Not leaking tokens

To be extra sure that we don't leak tokens, we should store the 3rd party API hostname alongside the token in vault. The tokenizer should ensure that this matches before injecting tokens into requests.