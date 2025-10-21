local socket = require("ljsocket")

do -- lookup google
    results = socket.get_address_info({host = "www.google.com"})
    assert(type(results) ~= nil)
    assert(#results ~= 0)

    for i, info in ipairs(results) do
        assert(info.host == "www.google.com")
        assert(info.family)
        assert(info.protocol)
    end
end