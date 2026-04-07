# Tokenizer User's Guide

This document describes how to seal tokens and how to make requests with them.

# Sealing tokens

To seal a token you need the sealing key of your tokenizer. 
* If you have the `OPEN_KEY` set in your environment you can get the seal by running `go run ./cmd/tokenizer sealkey`.
* The seal key is written by the server when the server is started on a line like `listening address="localhost:8080" seal_key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`.

## Command line

To seal a token with the command line
* Place the sealing key in your environment as `SEAL_KEY`. Alternately place the unsealing key in your environment as `OPEN_KEY`.
* Construct the sealing information as json, perhaps putting it into a file such as `token.json`.
* Run `go run ./cmd/tokenizer -json-file token.json` or `go run ./cmd/tokenizer -json $JSONOBJ`.

Example:

```bash
export SEAL_KEY=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

# Using a json file
cat > token.json <<_EOF_
{
  "inject_processor": { "token": "MY_SECRET_TOKEN" },
  "allowed_hosts": ["timflyio-go-example.fly.dev"],
  "fly_src_auth": {
    "allowed_orgs": ["tim-newsham"],
    "allowed_apps": ["thenewsh"]
  }
}
_EOF_
go run ./cmd/tokenizer seal -json-file token.json

# Using the json directly
go run ./cmd/tokenizer seal -json '{"inject_processor":{"token":"MY_SECRET_TOKEN"},"allowed_hosts":["timflyio-go-example.fly.dev"],"fly_src_auth":{"allowed_orgs":["tim-newsham"],"allowed_apps":["thenewsh"]}}'
```

On a deployed tokenizer where `OPEN_KEY` is already set, you can seal and unseal keys without making any additional settings:

```bash
TOKEN=$(tokenizer seal -json '{"inject_processor":{"token":"MY_SECRET_TOKEN"},"allowed_hosts":["timflyio-go-example.fly.dev"],"fly_src_auth":{"allowed_orgs":["tim-newsham"],"allowed_apps":["thenewsh"]}}')
echo $TOKEN
tokenizer unseal -token "$TOKEN"
```

## Go

To seal a token with go, import `github.com/superfly/tokenizer` library, build up a `tokenizer.Secret` and call the `Seal` method with the sealing key.

Example:

```go
package main

import (
    "fmt"
    "os"

    "github.com/superfly/tokenizer"
)

func main() {
    sealKey := os.Getenv("SEAL_KEY")
    if len(sealKey) == 0 {
        fmt.Printf("SEAL_KEY not set\n")
        os.Exit(1)
    }

    secret := tokenizer.Secret{
        ProcessorConfig: &tokenizer.InjectProcessorConfig{Token: "MY TOKEN"},
        RequestValidators: []tokenizer.RequestValidator{
            tokenizer.AllowHosts("timflyio-go-example.fly.dev"),
        },
        AuthConfig: tokenizer.NewFlySrcAuthConfig(
            tokenizer.AllowlistFlySrcOrgs("tim-newsham"),
            tokenizer.AllowlistFlySrcApps("thenewsh"),
        ),
    }
    sealed, err := secret.Seal(sealKey)
    if err != nil {
        fmt.Printf("sealing error: %v\n", err)
        os.Exit(1)
    }
    fmt.Printf("sealed: %v\n", sealed)
}
```

## Ruby

To seal a token with ruby, build up the sealing information into a variable and use the tokenizer seal key to seal it with `RbNaCl::Boxes::Sealed`.

Example:

```ruby
secret = {
    inject_processor: {
        token: "my-stripe-api-token"
    },
    bearer_auth: {
        digest: Digest::SHA256.base64digest('trustno1')
    }
}

seal_key = ENV["SEAL_KEY"]
sealed_secret = RbNaCl::Boxes::Sealed.new(seal_key).box(secret.to_json)
```

# Sealing options

Sealed tokens are encodings of `tokenizer.Secret`, and are often represented as JSON.
The `Secret` contains
authentication settings which describe how requests must be authenticated,
validation settings which describe how an auathenticated request must be validated,
and processors that describe how authenticated and validated requests will be processed.

## Auth config

The sealed token contains exactly one auth configuration, which specifies how to authenticate
requests with the sealed token before processing them.

### No Auth

The simplest auth configuration is `tokenizer.NoAuthConfig` which says that no additional authentication
is required. Its json representation is

```json
  "no_auth": {}
```

Example:

```bash
SEAL='{
  "inject_processor": { "token": "MY_SECRET_TOKEN" },
  "allowed_hosts": ["timflyio-go-example.fly.dev"],
  "no_auth": {}
}'
SEALED=$(go run ./cmd/tokenizer seal -json "$SEAL")

curl -s -x https://tokenizer.fly.dev \
  -H "Proxy-Tokenizer: $SEALED" \
  http://timflyio-go-example.fly.dev
```

### Bearer Auth

The `tokenizer.BearerAuthConfig` specifies that requests must contain a `Proxy-Authorization` header containing
`Bearer secret`, `FlyV1 secret` or `Basic base64`. In the case of `Basic base64`, the base64 component must
be a base64 encoding of `user:secret`. The message is authenticated if any such header exists and contains
a secret matching the configured sha256 digest.

The json encoding requiring a bearer auth containing "secret" is below. Note that the sha256 digest must be encoded as base64.

```json
  "bearer_auth": {
    "digest": "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols="
  }
```

Example:

```bash
SEAL='{
  "inject_processor": { "token": "MY_SECRET_TOKEN" },
  "allowed_hosts": ["timflyio-go-example.fly.dev"],
  "bearer_auth": {"digest": "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols="}
}'
SEALED=$(go run ./cmd/tokenizer seal -json "$SEAL")

curl -s -x https://tokenizer.fly.dev \
  -H "Proxy-Tokenizer: $SEALED" \
  -H "Proxy-Authorization: Bearer secret" \
  http://timflyio-go-example.fly.dev
```

### Macaroon Auth

TBD

### Flyio Macaroon Auth

TBD

### Flysrc Auth

The `tokenizer.FlysrcAuthConfig` specifies that the request must have a signed `Fly-src` header which specifies
where the request came from. This header is automatically added by the Fly proxy in certain requests between
Fly Apps, such as those going over Flycast. In other requests between Fly Apps, the requester can opt-in to
having `Fly-src` headers added with the `Fly-src-optin: *` header. The `FlysrcAuthConfig` has a list of allowed
Fly orgs, apps, and instances (machine IDs) that are allowed. The authentication passes if the `Fly-src` header
has a valid signature and specifies a Fly Org, App, and Machine in the allowed list. If an empty list is given
for any of these items, then it will act as a wildcard.

The json representation for an auth config that requires a fly-src for any Machine in the tim-newsham/thenewsh Fly Org and App is:

```json
  "fly_src_auth": {
    "allowed_orgs": [
      "tim-newsham"
    ],
    "allowed_apps": [
      "thenewsh"
    ]
  }
```

Here is an example. Note that the resulting command is printed out and must be run by the `thenewsh` Fly App.
Note that the Fly tokenizer is accessed on port `:8443` because the tokenizer access through
port 443 never receives `Fly-src` headers.

```bash
SEAL='{
  "inject_processor": { "token": "MY_SECRET_TOKEN" },
  "allowed_hosts": ["timflyio-go-example.fly.dev"],
  "fly_src_auth": {
    "allowed_orgs": [
      "tim-newsham"
    ],
    "allowed_apps": [
      "thenewsh"
    ]
  }
}'
SEALED=$(go run ./cmd/tokenizer seal -json "$SEAL")

# This will only work from Machines in the thenewsh App.
echo curl -s -x https://tokenizer.fly.dev:8443 \
  -H "\"Proxy-Tokenizer: $SEALED\"" \
  -H "\"Fly-src-optin: *\"" \
  http://timflyio-go-example.fly.dev
```

## Request Validation

After a request is authenticated, it is validated with a list of `tokenizer.RequestValidator` items. There are
request validators for lists of hosts, and for regular expressions matching hosts. These are built with
`tokenizer.AllowHosts` and `tokenizer.AllowHostPattern`.  A request is considered valid if it is being made
to an URL with a host that is in the allow list, or matches one of the allowed host patterns.

In JSON these are:

```json
  "allowed_hosts": ["www.google.com", "www.yahoo.com"],
  "allowed_host_pattern": "*.fly.dev"
```

Here's an example. Note the regular expression here matches hosts that end with ".fly.dev", and the escaping is
for the shell (double backslashes become one backslash) and for the regular expression (backslash-dot matches a single dot).

```bash
SEAL='{
  "inject_processor": { "token": "MY_SECRET_TOKEN" },
  "allowed_host_pattern": ".*\\.fly\\.dev$",
  "no_auth": {}
}'
SEALED=$(go run ./cmd/tokenizer seal -json "$SEAL")

curl -s -x https://tokenizer.fly.dev \
  -H "Proxy-Tokenizer: $SEALED" \
  http://timflyio-go-example.fly.dev
```

## Request Processing

Request processors specify how requests are modified. They usually inject secret material into requests flowing through the proxy.
A sealed token specifies a single processor that is applied to requests that have been authenticated and validated.
See documentation below on `tokenizer.MultiProcessorConfig` if multiple processors are needed.

### FmtProcessor
Several processors include an optional `tokenizer.FmtProcessor` or `tokenizer.DstProcessor` to provide
flexibility in how secrets are injected into requests.

The `FmtProcessor` specifies how a secret is injected. It optionaly includes an included format, and an include
format allow list. When the format is left empty, it can be specified in each request by including a "fmt" parameter
in the `Proxy-Tokenizer` header. If the format allow list is non-empty, the format for each request (whether
from the included format, or from the "fmt" parameter in the request header) must match one of the formats in the list.
Each format must contain one `%x`, `%X`, or `%s` format specifier, which is used to expand the secret.

If the format is not specified, it is taken from the first item in the allow list, if there is one,
otherwise it defaults to `Bearer %s` or `Bearer %x` depending on the context.

The json for a FmtProcessor contains zero or more of the following optional fields:

```json
  "fmt": "test %x",
  "allowed_fmt": ["test %x"]
```

This example allows one of three formats to be specified with each request:

```bash
SEAL='{
  "inject_processor": {
    "token": "MY_SECRET_TOKEN",
    "allowed_fmt": [
      "Bearer %s",
      "Cower %s",
      "Doger %s"
    ]
  },
  "allowed_hosts": ["timflyio-go-example.fly.dev"],
  "no_auth": {}
}'
SEALED=$(go run ./cmd/tokenizer seal -json "$SEAL")

PARAMS='{"fmt": "Cower %s"}'
curl -s -x https://tokenizer.fly.dev \
  -H "Proxy-Tokenizer: $SEALED; $PARAMS" \
  http://timflyio-go-example.fly.dev
```

### DstProcessor
The `DstProcessor` provides flexibility in which request header a secret is injected into.
The Dst processor includes an optional destination header name, and an optional list of allowed
destination headers. If the destination is not included, it can be specified in the "dst" field
include the parameters specified in the `Proxy-Tokenizer` header.
If not specified, it is taken from the first element in the allow list, or defaults to the `Authorization` header.
If the allowed list of destination headers is provided, the destination header must be on this list.

The json for a DstProcessor contains zero or more of the following optional fields:

```json
  "dst": "Y-Auth",
  "allowed_dst": ["X-Auth", "Y-Auth", "Z-Auth"]
```

This example allows one of three destination headers to be specified with each request:

```bash
SEAL='{
  "inject_processor": {
    "token": "MY_SECRET_TOKEN",
    "allowed_dst": [
      "X-Auth",
      "Y-Auth",
      "Z-Auth"
    ]
  },
  "allowed_hosts": ["timflyio-go-example.fly.dev"],
  "no_auth": {}
}'
SEALED=$(go run ./cmd/tokenizer seal -json "$SEAL")

PARAMS='{"dst": "Z-Auth"}'
curl -s -x https://tokenizer.fly.dev \
  -H "Proxy-Tokenizer: $SEALED; $PARAMS" \
  http://timflyio-go-example.fly.dev
```

### InjectProcessorConfig
The `tokenizer.InjectProcessorConfig` specifies a token to inject, and can include an optional format and destination.
By default the token is injected as an `Authoriation` header as `Bearer %s`.

Note that if the format and destination are left unspecified, the requester is free to choose any format and destination.
This may pose a security risk, and it is a best practice to limit the allowed formats and destinations.

Params: "fmt", "dst".

The json for the injection processor is:

```json
  "inject_processor": {
    "token": "MY_SECRET_TOKEN",
    "allowed_fmt": ["%s"],
    "allowed_dst": ["X-Auth"]
  }
```

This example will inject "secret" into the `X-Auth` header:

```bash
SEAL='{
  "inject_processor": {
    "token": "secret",
    "allowed_fmt": ["%s"],
    "allowed_dst": ["X-Auth"]
  },
  "allowed_hosts": ["timflyio-go-example.fly.dev"],
  "no_auth": {}
}'
SEALED=$(go run ./cmd/tokenizer seal -json "$SEAL")

curl -s -x https://tokenizer.fly.dev \
  -H "Proxy-Tokenizer: $SEALED" \
  http://timflyio-go-example.fly.dev
```

### InjectHMACProcessorConfig

The `tokenizer.InjectHMACProcessorConfig` injects computes the HMAC of the request body and injects it as a secret.
It includes an optional format and destination.
By default the token is injected as an `Authoriation` header as `Bearer %x`.
The processor includes the name of a hash algorithm to use, and an HMAC key. "sha256" is the only supported
algorithm.

If the request includes the "msg" parameter in the `Proxy-Tokenizer` header, the HMAC is computed from that message instead of the request body.

Note that if the format and destination are left unspecified, the requester is free to choose any format and destination.
This may pose a security risk, and it is a best practice to limit the allowed formats and destinations.

Params: "msg", "fmt", "dst"

The json for an HMAC injection processor that uses the key "secret" is as follows. Note that the json value for key must be given in Base64.

```json
  "inject_hmac_processor": {
    "key": "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=",
    "hash": "sha256",
    "fmt": "hmac is %x",
    "dst": "X-Auth"
  }
```

This example injects the SHA256 HMAC of the body using the key "secret" into the `X-Auth` header.

```bash
SEAL='{
  "inject_hmac_processor": {
    "key": "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=",
    "hash": "sha256",
    "fmt": "hmac is %x",
    "dst": "X-Auth"
  },
  "allowed_hosts": ["timflyio-go-example.fly.dev"],
  "no_auth": {}
}'
SEALED=$(go run ./cmd/tokenizer seal -json "$SEAL")

curl -s -x https://tokenizer.fly.dev \
  -H "Proxy-Tokenizer: $SEALED" \
  -X GET http://timflyio-go-example.fly.dev -d "body"
```

### InjectBodyProcessorConfig

The `tokenizer.InjectBodyProcessorConfig` processor rewrites a pattern in the request body with a token.
The configuration includes the placeholder string that will be replaced. The requester can choose
a different placeholder using the "placeholder" parameter in the `Proxy-Tokenizer` header.
If no placeholder is specified, it uses `{{ACCESS_TOKEN}}` as the placeholder.

Params: "placeholder"

```json
  "inject_body_processor": {
    "token": "secret",
    "placeholder": "TokenHere"
  }
```

Example:

```bash
SEAL='{
  "inject_body_processor": {
    "token": "secret",
    "placeholder": "TokenHere"
  },
  "allowed_hosts": ["timflyio-go-example.fly.dev"],
  "no_auth": {}
}'
SEALED=$(go run ./cmd/tokenizer seal -json "$SEAL")

curl -s -x https://tokenizer.fly.dev \
  -H "Proxy-Tokenizer: $SEALED" \
  http://timflyio-go-example.fly.dev/test -d "hello TokenHere there."
```

### OAuthProcessorConfig

The `tokenizer.OAuthProcessorConfig` processor holds an OAuth access token and refresh token and can
inject either one. It normally expands the access token in the same way that the injection processor does.
The requester can specify which of the two tokens to expand by providing an "st" parameter alongside the
sealed token. When "st" is given as "refresh", the refresh token will be injected. When "st" is given as "access"
the access token will be injected.

If the requester specifies the "placeholder" parameter in the `Proxy-Tokenizer` header, the selected token replaces
the specified placeholder string in the request body. Otherwise the selected token is injected into the
`Authorization` header as a bearer token.

Params: "placeholder", "st"

```json
  "oauth2_processor": {
    "token": {
      "access_token": "MY ACCESS TOKEN",
      "refresh_token": "MY REFRESH TOKEN"
    }
  }
```

This example injects the refresh token into the request's authorization header. If the parameter in the `Proxy-Tokenizer` header was
omitted, it would have injected the access token.

```bash
SEAL='{
  "oauth2_processor": {
    "token": {
      "access_token": "MY ACCESS TOKEN",
      "refresh_token": "MY REFRESH TOKEN"
    }
  },
  "allowed_hosts": ["timflyio-go-example.fly.dev"],
  "no_auth": {}
}'
SEALED=$(go run ./cmd/tokenizer seal -json "$SEAL")

PARAM='{"st":"refresh"}'
curl -s -x https://tokenizer.fly.dev \
  -H "Proxy-Tokenizer: $SEALED; $PARAM" \
  http://timflyio-go-example.fly.dev
```


### OAuthBodyProcessorConfig

The `tokenizer.OAuthBodyProcessorConfig` processor seals an access token and a refresh token
and rewrites a pattern in the request body with one of the two tokens.
The configuration includes the placeholder string that will be replaced. The requester can choose
a different placeholder using the "placeholder" parameter in the `Proxy-Tokenizer` header.
If no placeholder is specified, it uses `{{ACCESS_TOKEN}}` as the placeholder.

The requester can specify which of the two tokens to expand by providing an "st" parameter alongside the
sealed token. When "st" is given as "refresh", the refresh token will be injected. When "st" is given as "access"
the access token will be injected.

Params: "placeholder", "st"

```json
  "oauth2_body_processor": {
    "token": {
      "access_token": "MY ACCESS TOKEN",
      "refresh_token": "MY REFRESH TOKEN"
    },
    "placeholder": "TokenHere"
  }
```

This example injects the refresh token into the request's body in place of the "TokenHere" placeholder.
If the parameter in the `Proxy-Tokenizer` header was omitted, it would have injected the access token.

```bash
SEAL='{
  "oauth2_body_processor": {
    "token": {
      "access_token": "MY ACCESS TOKEN",
      "refresh_token": "MY REFRESH TOKEN"
    },
    "placeholder": "TokenHere"
  },
  "allowed_hosts": ["timflyio-go-example.fly.dev"],
  "no_auth": {}
}'
SEALED=$(go run ./cmd/tokenizer seal -json "$SEAL")

PARAM='{"st":"refresh"}'
curl -s -x https://tokenizer.fly.dev \
  -H "Proxy-Tokenizer: $SEALED; $PARAM" \
  http://timflyio-go-example.fly.dev/test -d "hello TokenHere there."
```

### Sigv4ProcessorConfig

The `tokenizer.Sigv4ProcessorConfig` seals an AWS access key and secret key and re-signs AWS v4 requests
with them. It does this by using the request's `Authorization` header, extracting the date, region, and
service components from the `Credential` attribute, and generating a new authorization header using
the credentials and this information. If the request has an `X-Amz-Date` header, it uses the date
from this header instead of the one in the `Credentials` attribute.

The original implementation accidentally swapped the region and service that was extracted from
the `Credentials` attribute. To address this without breaking compatibility with existing sealed
credentials, the optional `no_swap` field was added, which should be set to `true` in all newly
sealed credentials.

It strips the following headers from the request prior to signing:

* `Proxy-Tokenizer`
* `Proxy-Authorization`
* `Accept-Encoding`
* `Proxy-Connection`
* `Proxy-Authenticate`
* `Proxy-Authorization`
* `Via`
* `X-Forwarded-For`
* `X-Forwarded-Port`
* `X-Forwarded-Proto`
* `X-Forwarded-Ssl`
* `X-Request-Start`

```json
  "sigv4_processor": {
    "access_key": "AKIAIOSFODNN7EXAMPLE",
    "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "no_swap": true
  }
```

Example

```bash
SEAL='{
  "sigv4_processor": {
    "access_key": "AKIAIOSFODNN7EXAMPLE",
    "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "no_swap": true
  },
  "allowed_hosts": ["timflyio-go-example.fly.dev"],
  "no_auth": {}
}'
SEALED=$(go run ./cmd/tokenizer seal -json "$SEAL")

curl -s -x https://tokenizer.fly.dev \
  -H "Proxy-Tokenizer: $SEALED" \
  -H "Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260406/us-east-1/iam/aws4_request, Signature=xxx" \
  http://timflyio-go-example.fly.dev
```

### JWTProcessorConfig

The `tokenizer.JWTProcessorConfig` processor is used to support JWT code exchanges.
It seals parameters needed to make a JWT code exchange request, and replaces the
request body with a code exchange request. The original body is not processed.
It processes the response by extracting
the access token, sealing it using a `tokenizer.InjectProcessorConfig`, and replacing
the response body with JSON carrying the newly sealed token. This token can be used
to make inject the resulting JWT into future requests using the tokenizer.

TODO: this section could be made clearer and could use a working example.
See the documentation for `JWTProcessorConfig` in `processor.go` for more details.

Params: "sub", "scopes"

The sealed parameters include the private key and URL needed to make the code exchange request,
and the "email", "sub", and "scopes" that will be used when constructing a sealed JWT.
Scopes are specified as a space-separated list.
If the token URL is not specified, it defaults to `https://oauth2.googleapis.com/token`.
The private key must be base64 encoded and must be an RSA256 key in PKCS1 format, or
a PKCS8 key in RSA256, ECDSA, or Ed25519 format. ECDSA keys must use the P256, P384, or P521 curve.
If the "sub" or "scopes" parameters are provided in the `Proxy-Tokenizer` header, they override
the sealed "sub" and "scopes" parameters.

```json
  "jwt_processor": {
    "private_key": "xxxbase64xxx",
    "email": "jwtsRus@service.com",
    "sub": "user@host.com",
    "scopes": "read:user read:project",
    "token_url": "https://github.com/login/oauth/access_token"
  }
```

When processing requests, the original request body is ignored and replaced with a token request in the following form:

```json
  {
    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
    "assertion": "signed-jwt-here"
  }
```

The JWT in the request body is formed using the sealed parameters and is signed with the sealed private key.

```json
  {
    "iss":   "from-sealed-email",
    "scope": "from-sealed-scopes",
    "aud":   "from-sealed-token-url",
    "iat":   from-current-time,
    "exp":   from-current-time-plus-one-hour,
  }
```

The response from the target is expected to be in the following format:

```json
  {
    "access_token": "access-token-here",
    "expires_in": access-token-expiration,
    "token_type": "access-token-type"
  }
```

This response is processed by sealing the access token as a `tokenizer.InjectProcessorConfig`.
The sealed token carries the same request authentication and request validator requirements
as the `tokenizer.JWTProcessorConfig`.
The response is replaced with a response body in the following format.
Note: the expiration of the original access token is adjusted down by 60 seconds.

```json
  {
    "sealed_token": "sealed-token-here",
    "expires_in": sealed-token-expiration,
    "token_type": "sealed"
  }
```

TBD
Include a working example.

### ClientCredentialsProcessorConfig

TBD
See the documentation for `ClientCredentialsProcessorConfig` in `processor.go` for details.

### MultiProcessorConfig
The `tokenizer.MultiProcessorConfig` processes requests with a list of request processors. It is encoded as follows:

```json
  "multi_processor": [
    {
      "inject_processor": {
        "token": "x-secret",
        "fmt": "%s",
        "dst": "X-Auth"
      }
    },
    {
      "inject_processor": {
        "token": "y-secret",
        "fmt": "%s",
        "dst": "Y-Auth"
      }
    }
  ]
```

This example injects secrets into the `X-Auth` and `Y-Auth` headers:

```bash
SEAL='{
  "multi_processor": [
    {"inject_processor": {"token": "x-secret", "fmt": "%s", "dst": "X-Auth"}},
    {"inject_processor": {"token": "y-secret", "fmt": "%s", "dst": "Y-Auth"}}
  ],
  "allowed_hosts": ["timflyio-go-example.fly.dev"],
  "no_auth": {}
}'
SEALED=$(go run ./cmd/tokenizer seal -json "$SEAL")

curl -s -x https://tokenizer.fly.dev \
  -H "Proxy-Tokenizer: $SEALED" \
  http://timflyio-go-example.fly.dev

```

# Making requests
To make requests to the tokenizer, submit requests using your tokenizer server as an HTTP proxy.
Requests should include one or more `Proxy-Tokenizer` headers containing a sealed token.
The server processes each of these in order by unsealing the token, authenticating the
request, validating the request, and then processing the request with the processor in the unsealed token.
When multiple headers are provided, they are applied in order.

Each tokenizer header can also specify a set of parameters to be used by the processors.
These are specified as `Proxy-Tokenizer: $SEALED_TOKEN; $PARAMTERS`. Parameters should
be specified as a JSON dictionary of strings. The use and interpretation of parameters vary
by request processor, and provide a way for the same processor to be used in different
ways for different requests. For example, using the "fmt" parameter allows the requester
to choose between one of several allowed formats by the injection processor.

The following example demonstrates using parameters to choose to inject the secret into
the `X-Auth` header with the `Cower %s` format. If the parameters were not specified,
the secret would have been injected to the `Authorization` header as `Bearer %s`.

```bash
SEAL='{
  "inject_processor": {
    "token": "MY_SECRET_TOKEN",
    "allowed_fmt": ["Bearer %s", "Cower %s", "Doger %s"],
    "allowed_dst": ["Authorization", "X-Auth", "Y-Auth"]
  },
  "allowed_hosts": ["timflyio-go-example.fly.dev"],
  "no_auth": {}
}'
SEALED=$(go run ./cmd/tokenizer seal -json "$SEAL")

PARAMS='{"fmt": "Cower %s", "dst": "X-Auth"}'
curl -s -x https://tokenizer.fly.dev \
  -H "Proxy-Tokenizer: $SEALED; $PARAMS" \
  http://timflyio-go-example.fly.dev
```

## Supported parameters

The following parameters are supported:

* `fmt` overrides the default format in several injection processors.
* `dst` overrides the default destination header in several injection processors.
* `msg` specifies a message to compute the HMAC over instead of the request body in the HMAC injection processor.
* `st` selects which of several subtokens to inject, and is used by the OAuth processor and the OAuth body processor to choose to inject the refresh token instead of the access token.
* `placeholder` selects a placeholder string that will be replaced with an injected token. It overrides any placeholder in the sealed token configuration. It is supported by the oauth processor, the body injection processor, and the oauth body injection processor.
* `sub` overrides the sealed subject to use when constructing signed JWTs in the JWT processor.
* `scopes` overrides the sealed scopes to use when constructing signed JWTs in the JWT processor.

