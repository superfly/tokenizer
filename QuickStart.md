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

# generate and set the secret key
export OPEN_KEY=$(openssl rand -hex 32)
fly -c fly.toml.timkenizer secrets set OPEN_KEY=$OPEN_KEY

# find the seal key in the logs
fly -c fly.toml.timkenizer logs -n |grep -o 'seal_key=.*'
seal_key=xxxxxx
export SEAL_KEY=$seal_key

# seal a token, here restricted to use against https://timflyio-go-example.fly.dev from app=thenewsh
TOKEN=$(go run ./cmd/sealtoken -host timflyio-go-example.fly.dev -org tim-newsham -app thenewsh MY_SECRET_TOKEN)

# and use it from the approved app to the approved url
# note: you'll need to opt-in to get a fly-src header to approve the request.
curl -H "Proxy-Tokenizer: $TOKEN" -H "fly-src-optin: *" -x https://timkenizer.fly.dev http://timflyio-go-example.fly.dev

# try out some bad requests to the wrong target, from the wrong app, etc..
curl -H "Proxy-Tokenizer: $TOKEN" -H "fly-src-optin: *" -x https://timkenizer.fly.dev http://thenewsh.fly.dev

# review the log files
fly -c fly.toml.timkenizer logs
```
