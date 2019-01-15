WIP

Slightly resembles luasocket's core module, but this is a bit more low level and tries to follow the unix socket api.

To test the examples like this: 
`luajit examples/tcp_client_blocking_tls.lua`

Assuminug you have luajit and ffi installed.

The TLC client examples uses libtls (LibreSSL) which in turn depends on libssl and libcrypto. `tls.lua` has been auto generated based on the tls header.
