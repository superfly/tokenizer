# Quick Start

Here's a short walk through of setting up and using the tokenizer proxy.
The use case here is running the proxy from a public fly address, such that it
is accessible by any other fly app that has a valid wrapped secret.

## Config file

The config file I used is called `fly.toml.timkenizer` with the following contents:

```
app = 'timkenizer'
primary_region = 'sjc'
kill_signal = 'SIGINT'

[build]

[env]
  OPEN_PROXY = 'false'
  REQUIRE_FLY_SRC = 'true'
  TOKENIZER_HOSTNAMES = 'timkenizer.fly.dev'

[http_service]
  internal_port = 8080
  auto_stop_machines = 'off'
  auto_start_machines = false
  min_machines_running = 1
  processes = ['app']

[[vm]]
  memory = '2gb'
  cpu_kind = 'shared'
  cpus = 1
```

## Commands

The commands I used to create the app and use it are:

```
# create the app, it will fail to start
fly -c fly.toml.timkenizer launch

# generate and set the secret "open" and "seal" keys.
# install the OPEN_KEY on the server and keep the SEAL_KEY for later.
export OPEN_KEY=$(openssl rand -hex 32)
export SEAL_KEY=$(go run ./cmd/tokenizer -sealkey)
fly -c fly.toml.timkenizer secrets set OPEN_KEY=$OPEN_KEY

# use the SEAL_KEY to generate a proxy token that will inject a secret token into requests to the target.
# here restricted to use against https://timflyio-go-example.fly.dev from app=thenewsh
TOKEN=$(go run ./cmd/sealtoken -host timflyio-go-example.fly.dev -org tim-newsham -app thenewsh MY_SECRET_TOKEN)

# install the TOKEN in your approved app and use it to access the approved url.
# the secret token (MY_SECRET_TOKEN) will be added as a bearer token.
# note: you'll need to opt-in to get a fly-src header to allow the proxy to approve the request.
curl -H "Proxy-Tokenizer: $TOKEN" -H "fly-src-optin: *" -x https://timkenizer.fly.dev http://timflyio-go-example.fly.dev

# try out some bad requests to the wrong target, from the wrong app, etc..
curl -H "Proxy-Tokenizer: $TOKEN" -H "fly-src-optin: *" -x https://timkenizer.fly.dev http://thenewsh.fly.dev

# review the log files
fly -c fly.toml.timkenizer logs
```
