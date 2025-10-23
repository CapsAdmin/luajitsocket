local socket = require("ljsocket")
local test = require("test.gambarina")

test('TCP client rcvtimeo timeout blocking test', function()
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

test('TCP client sndtimeo blocking test', function()
    -- Create a server that accepts but never reads
    local server = assert(socket.create("inet", "stream", "tcp"))
    assert(server:set_option("reuseaddr", 1))
    assert(server:bind("127.0.0.1", "0"))  -- bind to any available port
    assert(server:listen(1))

    local _, port = assert(server:get_name())

    -- Connect a client
    local client = assert(socket.create("inet", "stream", "tcp"))
    assert(client:connect("127.0.0.1", tostring(port)))

    -- Accept the connection but don't read from it
    local accepted = assert(server:accept())

    -- Set a short send timeout
    assert(client:set_option("sndtimeo", 0.25))

    -- Try to send enough data to fill the send buffer
    -- This should eventually timeout when the buffer is full
    local large_data = string.rep("x", 65536)
    local timeout_occurred = false

    for i = 1, 10000 do
        local bytes, err = client:send(large_data)
        if not bytes and err == "timeout" then
            timeout_occurred = true
            break
        end
        if not bytes then
            error("unexpected error: " .. tostring(err))
        end
    end

    if not timeout_occurred then
        error("expected send timeout to occur")
    end

    client:close()
    accepted:close()
    server:close()
end)