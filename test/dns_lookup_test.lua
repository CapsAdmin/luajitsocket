local socket = require("ljsocket")
local test = require("test.gambarina")

test('DNS lookup for www.google.com', function()
    local results = socket.find_address_info("www.google.com")
    ok(type(results) ~= nil, "results should not be nil")
    ok(#results ~= 0, "results should not be empty")

    for i, info in ipairs(results) do
        ok(info.host == "www.google.com", "host should be www.google.com")
        ok(info.family ~= nil, "family should be set")
        ok(info.protocol ~= nil, "protocol should be set")
    end
end)