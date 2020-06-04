# yzesd2

`zsittle`-alike demo program for `yz-encsess v2`.

```
USAGE:
# first run (generates private + public keys, you should save them to some file)
  cargo run --bin yzesd2-server -- --listen IP:PORT
# second run (use the same private key as the server printed in the previous run)
  cargo run --bin yzesd2-server -- --listen IP:PORT --privkey PRIVKEY

# that works similiar with the client, but the client must know which public key the server has
  cargo run --bin yzesd2-client -- --connect IP:PORT --remote-pubkey SERVER_PUBKEY [--privkey CLIENT_PRIVKEY]
```
