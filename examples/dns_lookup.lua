local bsocket = require("bsocket")

for _, info in ipairs(assert(bsocket.get_address_info({host = "www.google.com"}))) do
    print("================================")
    print("host: ", info.host)
    print("service: ", info.service)
    print("ip: ", info.ip)
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