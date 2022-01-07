Slightly resembles luasocket's core module, but it's a bit more low level and tries to follow the unix socket api.

Assuming you have luajit installed, you can test the library by run the examples like this: 
`luajit examples/tcp_client_blocking_tls.lua`

The TLS client examples uses libtls (LibreSSL) which in turn depends on libssl and libcrypto. `tls.lua` has been auto generated based on libtls' headers.

It seems to be working, but I haven't explored paths other than TCP and UDP. TCP is the one I've used this the most with. My intention is to keep this close to how it works on the OS level. 

High level abstractions are out of scope in this library. It also aims to just be a single file that's easy to copy paste. :)
