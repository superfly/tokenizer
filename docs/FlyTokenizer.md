# Fly's tokenizer service.

Fly runs a tokenizer in the [tokenizer](http://admin.vpn.flyio.net/apps/1000491) App of the `tokenizer` Org.
It is available from the Internet at

* https://tokenizer.fly.dev - terminated by fly-proxy, but using TCP pass-thru. This endpoint will not add `Fly-src` headers.
* https://tokenizer.fly.dev:8443 - terminated by fly-proxy using an http hander.
* http://tokenizer.fly.dev - using TCP pass-thru. This endpoint will not add `Fly-src` headers.
* http://tokenizer.fly.dev:8080 - using an http handler.

It can also be reached via http://tokenizer.flycast from select services.

Requestors should include the `Fly-src-optin: *` header when making requests on https://tokenizer.fly.dev:8443 or http://tokenizer.fly.dev:8080 if their sealed token requires a `Fly-src` header. Requests made over flycast will automatically be given the `Fly-src` header.

## Sealing key

The tokenizer's seal key is need to seal tokens. It is logged by the server during startup. If you need access to the seal key you can find it by going to the admin panel for tokenizer at http://admin.vpn.flyio.net/apps/1000491, clicking on the log file icon, and searching for `seal_key`. 
