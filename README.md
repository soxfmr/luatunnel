# luatunnel
A reverse proxy implements in Lua that working on OpenResty

# Usage

## Server side

Deploy the Lua script on the server side, you should specify a pre-share key for variable `id` which is used to encrypt the communication traffic:

```lua
http = require("resty.http")
aes = require("resty.aes")
str = require("resty.string")
rand = require("resty.random")

id = "secret_key"
```

## Client side

```shell
$ go run client.go
  -key string
    	Encrypt key of the traffic for remote request
  -port string
    	Proxy port (default "8888")
  -url string
    	Proxy URL on remote target
```

Starting a HTTP proxy server listen on local port 8080:
```shell
$ go run client.go -key secret_key -port 1080 -url https://target.com/proxy.luac
```

Access the internal resources by using the local proxy:
```shell
$ curl --proxy http://localhost:1080 https://ad.internal.server
```