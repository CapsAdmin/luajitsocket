local luanet = require("luanet")

for _, info in ipairs(assert(luanet.get_address_info({host = "www.google.com"}))) do
    print("================================")
    print("host: ", info.host)
    print("service: ", info.service)
    print("ip: ", info:get_ip())
    print("port: ", info:get_port())
    print("family: ", info.family)
    print("socket_type: ", info.socket_type)
    print("protocol: ", info.protocol)
    print("addrinfo: ", info.addrinfo)
    print("flags: ")
    for k,v in pairs(info.flags) do
        print("\t", k, v)
    end
    print("================================")
end