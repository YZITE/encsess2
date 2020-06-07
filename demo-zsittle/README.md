# yzesd2

`zsittle`-alike demo program for `yz-encsess v2`.

```
USAGE:
# first run (generates private + public keys, you should save them to some file)
  cargo run --bin yzesd2-client -- --listen IP:PORT
# second run (use the same private key as the server printed in the previous run)
  cargo run --bin yzesd2-client -- --listen IP:PORT --privkey PRIVKEY

# that works similiar with the client, but the client must know which public key the server has
  cargo run --bin yzesd2-client -- --connect IP:PORT --remote-pubkey SERVER_PUBKEY [--privkey CLIENT_PRIVKEY]
```

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
