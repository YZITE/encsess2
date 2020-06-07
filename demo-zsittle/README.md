# yzesd2

`zsittle`-alike demo program for `yz-encsess v2`.

## client usage

```
USAGE:
# first, generate a key-pair
  cargo run --bin yzesd2-genkey
# write it into a config file (see below)
# third, run (save the config as a toml file)
  cargo run --bin yzesd2-client -- CLCONFIG.toml SERVER_NAME
```

```toml
# CLCONFIG.toml
privkey = "PRIVKEY"

[server.SERVER_NAME]
# if the server addr is an ipv6 ip-addr, put the addr in [IPv6]
connect = "SERVER_ADDR:PORT"
pubkey = "PUBKEY"
```

## server usage

```
USAGE:
# first, generate a key-pair
  cargo run --bin yzesd2-genkey
# write it into a config file (see below)
# third, run (save the config as a toml file)
  cargo run --bin yzesd2-server -- SVCONFIG.toml
```

```toml
# SVCONFIG.toml
listen = "IP:PORT"
privkey = "PRIVKEY"

# if no 'Client' blocks exist at all, client whitelisting is disabled
# e.g. anyone is then hopefully able to successfully connect to the server
[[client]]
pubkey = "PUBKEY"
```
