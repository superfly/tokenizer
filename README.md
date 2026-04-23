# Tokenizer

Tokenizer is an HTTP proxy that injects third party authentication credentials into requests. Clients encrypt third party secrets using the proxy's public key. When the client wants to send a request to the third party service, it does so via the proxy, sending along the encrypted secret in the `Proxy-Tokenizer` header. The proxy decrypts the secret and injects it into the client's request. To ensure that encrypted secrets can only be used by authorized clients, the encrypted data also includes instructions on authenticating the client.

# Docs

More docs can be found under [docs/](docs/):

* [The Fly tokenizer](docs/FlyTokenizer.md) describes the tokenizer that Fly runs.
* [Quick start](docs/QuickStart.md) describes how to quickly setup, run, and use your own tokenizer.
* [User guide](docs/UserGuide.md) describes how to seal tokens and make requests through the tokenizer with them.

# Example

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

Notice that the client's request is to _http_://api.stripe.com. In order for the proxy to be able to inject credentials into requests we need to speak plain HTTP to the proxy server, not HTTPS. The proxy transparently switches to HTTPS for connections to upstream services. This assumes communication between the client and tokenizer happens over a secure transport (a VPN).

## Processors

The processor dictates how the encrypted secret gets turned into a credential and added to the request. The example above uses `inject_processor`, which simply injects the verbatim secret into a request header. By default, this injects the secret into the `Authorization: Bearer` header without further processing. The `inject_processor` can optionally specify a destination and/or printf-style format string to be applied to the injection of the credential:

```ruby
secret = {
    inject_processor: {
        token: "my-stripe-api-token",
        dst:   "X-Stripe-Token",
        fmt:   "token=%s",
    },
    bearer_auth: {
        digest: Digest::SHA256.base64digest('trustno1')
    }
}
```

This will result in the header getting injected like this:

```http
X-Stripe-Token: token=my-stripe-api-key
```

Aside from `inject_processor`, we also have `inject_hmac_processor`. This creates an HMAC signatures using the key stored in the encrypted secret and injects that into a request header. The hash algorithm can be specified in the secret under the key `hash` and defaults to SHA256. This processor signs the verbatim request body by default, but can sign custom messages specified in the `msg` parameter in the `Proxy-Tokenizer` header (see about parameters bellow). This processor also respects the `dst` and `fmt` options.

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

### SigV4 processor

The `sigv4_processor` re-signs AWS requests with SigV4 credentials. It parses the existing `Authorization` header to extract the service, region, and date, then re-signs the request with the sealed AWS credentials.

```ruby
secret = {
    sigv4_processor: {
        access_key: "AKIAIOSFODNN7EXAMPLE",
        secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        no_swap: true
    },
    bearer_auth: {
        digest: Digest::SHA256.base64digest('trustno1')
    }
}
```

Note: the `no_swap` field controls a bug-compatibility mode. When `false` (the default for backward compatibility), the region and service values extracted from the credential scope are swapped before re-signing. Set `no_swap: true` for correct behavior with new secrets.

### JWT processor

The `jwt_processor` handles Google Cloud service account authentication (and other OAuth2 JWT-bearer flows per [RFC 7523](https://tools.ietf.org/html/rfc7523)). It signs a JWT with the sealed private key and exchanges it for a short-lived access token at the token endpoint. RSA (RS256), ECDSA (ES256/ES384/ES512), and Ed25519 (EdDSA) keys are supported - the signing algorithm is chosen automatically based on the key type.

This processor is unique in two ways:
1. **It transforms both the request and the response.** On the request side, it builds the JWT and constructs the token exchange POST body. On the response side, it intercepts the token endpoint's response, extracts the access token, seals it into a new `inject_processor` secret, and replaces the response body.
2. **The caller never sees any plaintext credential.** The private key, the signed JWT, and the access token are all plaintext only inside tokenizer's process memory. The caller receives an opaque sealed blob.

```ruby
secret = {
    jwt_processor: {
        private_key: File.read("service-account-key.pem"),
        email: "my-sa@my-project.iam.gserviceaccount.com",
        scopes: "https://www.googleapis.com/auth/admin.directory.user",
        token_url: "https://oauth2.googleapis.com/token",  # optional, this is the default
        sub: "admin@example.com"                            # optional, for domain-wide delegation
    },
    bearer_auth: {
        digest: Digest::SHA256.base64digest('trustno1')
    },
    allowed_hosts: ["oauth2.googleapis.com", "admin.googleapis.com"]
}
```

**Usage is a two-step flow:**

Step 1 - Exchange the sealed SA key for a sealed access token:

```ruby
# Send to the token endpoint through tokenizer
resp = conn.post("http://oauth2.googleapis.com/token")
sealed_access_token = JSON.parse(resp.body)["sealed_token"]
expires_in = JSON.parse(resp.body)["expires_in"]
```

The response body is replaced with:
```json
{"sealed_token": "<base64 sealed InjectProcessor>", "expires_in": 3540, "token_type": "sealed"}
```

Step 2 - Use the sealed access token for API calls:

```ruby
conn2 = Faraday.new(
    proxy: "http://tokenizer.flycast",
    headers: {
        proxy_tokenizer: "#{sealed_access_token}",
        proxy_authorization: "Bearer trustno1"
    }
)

conn2.get("http://admin.googleapis.com/admin/directory/v1/users")
```

The sealed access token is a normal `inject_processor` secret - tokenizer unseals it and injects the `Authorization: Bearer` header. When the token expires (typically after ~1 hour), repeat Step 1.

The `sub` and `scopes` fields can be overridden at request time via parameters, allowing different requests through the same sealed credential to impersonate different users or request different scopes:

```ruby
processor_params = { sub: "other-admin@example.com", scopes: "https://www.googleapis.com/auth/gmail.readonly" }
conn.headers[:proxy_tokenizer] = "#{Base64.encode64(sealed_secret)}; #{processor_params.to_json}"
```

**Fly.io deployment note:** For internal use on Fly.io, consider using `fly-src` auth instead of `bearer_auth`. This ties the sealed secret to a specific Fly machine, so the token is not useful if exfiltrated outside the originating instance.

## Request-time parameters

If the destination/formatting might vary between requests, `inject_processor` and `inject_hmac_processor` can specify an allowlist of `dst`/`fmt` parameters that the client can specify at request time. These parameters are supplied as JSON in the `Proxy-Tokenizer` header after the encrypted secret.

```ruby
secret = {
    inject_processor: {
        token: "my-stripe-api-token"
        allowed_dst: ["X-Stripe-Token", "Authorization"],
        allowed_fmt: ["Bearer %s", "token=%s"],
    },
    bearer_auth: {
        digest: Digest::SHA256.base64digest('trustno1')
    }
}

seal_key = ENV["TOKENIZER_PUBLIC_KEY"]
sealed_secret = RbNaCl::Boxes::Sealed.new(seal_key).box(secret.to_json)

processor_params = {
    dst: "X-Stripe-Token",
    fmt: "token=%s"
}

conn.headers[:proxy_tokenizer] = "#{Base64.encode64(sealed_secret)}; #{processor_params.to_json}"

conn.get("http://api.stripe.com")
```

### Client credentials processor

The `client_credentials_processor` implements the OAuth2 `client_credentials` grant ([RFC 6749 section 4.4](https://tools.ietf.org/html/rfc6749#section-4.4)) for machine-to-machine auth (HelpScout, and similar API platforms). It follows the same two-step sealed pattern as `jwt_processor` - see that section for the full flow description.

```ruby
secret = {
    client_credentials_processor: {
        client_id: "my-client-id",
        client_secret: "my-client-secret",
        token_url: "https://api.helpscout.net/v2/oauth2/token",
        scopes: "mailbox.read mailbox.write"  # optional
    },
    bearer_auth: {
        digest: Digest::SHA256.base64digest('trustno1')
    },
    allowed_hosts: ["api.helpscout.net"]
}
```

Step 1 - Exchange the sealed client credentials for a sealed access token (send to the token endpoint through tokenizer):

```ruby
resp = conn.post("http://api.helpscout.net/v2/oauth2/token")
sealed_access_token = JSON.parse(resp.body)["sealed_token"]
```

Step 2 - Use the sealed access token for API calls (same as `jwt_processor`):

```ruby
conn2 = Faraday.new(
    proxy: "http://tokenizer.flycast",
    headers: {
        proxy_tokenizer: "#{sealed_access_token}",
        proxy_authorization: "Bearer trustno1"
    }
)
conn2.get("http://api.helpscout.net/v2/conversations")
```

| Field | Required | Description |
|---|---|---|
| `client_id` | yes | OAuth2 client ID |
| `client_secret` | yes | OAuth2 client secret (sealed, never exposed) |
| `token_url` | yes | Token endpoint URL |
| `scopes` | no | Space-separated OAuth2 scopes |

### GitHub App processor

The `github_app_processor` authenticates as a [GitHub App](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation). It follows the same two-step sealed pattern as `jwt_processor`, but with GitHub's non-standard flow: the JWT goes in the `Authorization` header (not a form body), the request body is empty, and the installation ID lives in the URL path. GitHub requires RSA keys signed with RS256; other key types are rejected.

```ruby
secret = {
    github_app_processor: {
        private_key: File.read("github-app-key.pem"),
        app_id: "123456",
        installation_id: "78901234",
        # token_url: "https://api.github.com/app/installations/{installation_id}/access_tokens"  # default
    },
    bearer_auth: {
        digest: Digest::SHA256.base64digest('trustno1')
    },
    allowed_hosts: ["api.github.com"]
}
```

Step 1 - Exchange the sealed App key for a sealed installation token. POST to any path on `api.github.com` through tokenizer - the processor rewrites the path using the sealed `installation_id`:

```ruby
resp = conn.post("http://api.github.com/")
sealed_installation_token = JSON.parse(resp.body)["sealed_token"]
```

The response body is replaced with:
```json
{"sealed_token": "<base64 sealed InjectProcessor>", "expires_in": 3540, "token_type": "sealed"}
```

Installation tokens expire after one hour. Repeat step 1 before expiry.

Step 2 - Use the sealed installation token for API calls. Tokenizer injects `Authorization: token <installation_token>` and enforces that the token is only usable against `api.github.com`:

```ruby
conn2 = Faraday.new(
    proxy: "http://tokenizer.flycast",
    headers: {
        proxy_tokenizer: "#{sealed_installation_token}",
        proxy_authorization: "Bearer trustno1"
    }
)
conn2.get("http://api.github.com/installation/repositories")
```

| Field | Required | Description |
|---|---|---|
| `private_key` | yes | PEM-encoded RSA private key (sealed, never exposed) |
| `app_id` | yes | GitHub App ID, used as the JWT `iss` claim |
| `installation_id` | yes | Installation ID, substituted into `token_url` |
| `token_url` | no | Token URL template; `{installation_id}` is substituted. Override for GitHub Enterprise. |

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

## Production deployment — fly.io

Assuming you have [flyctl](https://fly.io/docs/hands-on/install-flyctl/) installed, start by cloning this repository

```shell
git clone https://github.com/superfly/tokenizer
cd ./tokenizer
```

create a fly.io app:

```shell
fly app create
export FLY_APP="<name of app>"
```

generate a private (open) key:

```shell
OPEN_KEY=$(openssl rand -hex 32)
fly secrets set --stage OPEN_KEY=$OPEN_KEY
```

Deploy the app without making it available on the internet<sup>1</sup>:

```shell
fly deploy --no-public-ips
```

Tokenizer is now deployed and accessible to other apps in your org at `<name of app>.flycast`. The deploy logs will contain the public (seal) key, which can be used for encrypting secrets.

<sup>1</sup>*Assigning a public IP address to the app is not recommended, since it will happily proxy traffic to private IP addresses. If you require a public deployment, consider running tokenizer in a separate, dedicated organization or using it in conjuction with [smokescreen](https://github.com/stripe/smokescreen).*

## Production deployment — custom

Tokenizer is totally stateless, so it's simple to deploy anywhere.

Assuming you have Golang installed, you can build and install tokenizer in `/usr/local/bin` by running

```shell
GOBIN=/usr/local/bin go install github.com/superfly/tokenizer/cmd/tokenizer@latest
```

Generate a private (open) key:

```shell
export OPEN_KEY=$(openssl rand -hex 32)
```

Run the tokenizer server:

```shell
tokenizer serve -use-flysrc=true
```

The output will contain the public (seal) key, which can be used for encrypting secrets.

## Test deployment

See the READMEs in `github.com/superfly/tokenizer/cmd/tokenizer` and `github.com/superfly/tokenizer/cmd/curl` for instructions on running/testing tokenizer locally.

## Configuration

Tokenizer is configured with the following environment variables:

- `OPEN_KEY` - The hex encoded 32 byte private key is used for decrypting secrets.
- `LISTEN_ADDRESS` - The address (`ip:port`) to listen on.
- `FILTERED_HEADERS` - A comma separated list of request headers to strip from client requests.
- `OPEN_PROXY` - Setting `1` or `true` will allow requests that don't contain sealed secrets to be proxied. Such requests are blocked by default.
