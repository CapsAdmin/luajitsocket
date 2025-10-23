local socket = require("ljsocket")
local test = require("test.gambarina")

test('TCP client timeout blocking test', function()
    local sock = assert(socket.create("inet", "stream", "tcp"))
    assert(sock:connect("httpbin.org", "http"))
    assert(sock:send("GET /delay/10 HTTP/1.1\r\nHost: httpbin.org\r\n\r\n"))
    assert(sock:set_option("rcvtimeo", 0.25))
    local res, err = sock:receive()
    if res then
        error("expected timeout error, got data")
    end
    eq(err, "timeout")
end)