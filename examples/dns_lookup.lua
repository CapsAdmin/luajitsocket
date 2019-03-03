local socket = require("ljsocket")

for _, info in ipairs(assert(socket.get_address_info({host = "www.google.com"}))) do
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

    print("ai_flags: ", info.addrinfo.ai_flags)
    print("ai_family: ", info.addrinfo.ai_family)
    print("ai_socktype: ", info.addrinfo.ai_socktype)
    print("ai_protocol: ", info.addrinfo.ai_protocol)
    print("ai_addrlen: ", info.addrinfo.ai_addrlen)
    print("ai_canonname: ", info.addrinfo.ai_canonname)
    print("ai_addr: ", info.addrinfo.ai_addr)
    print("ai_next: ", info.addrinfo.ai_next)


    print("================================")
end