local socket = require("ljsocket")
local test = require("test.gambarina")

test('TCP client blocking test', function()
    local host = "www.freebsd.no"
    local sock = assert(socket.create("inet", "stream", "tcp"))
    assert(sock:connect(host, "http"))

    local sent = assert(sock:send(
        "GET / HTTP/1.1\r\n"..
        "Host: " .. host .. "\r\n"..
        "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:64.0) Gecko/20100101 Firefox/64.0\r\n"..
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"..
        "Accept-Language: nb,nb-NO;q=0.9,en;q=0.8,no-NO;q=0.6,no;q=0.5,nn-NO;q=0.4,nn;q=0.3,en-US;q=0.1\r\n"..
        "DNT: 1\r\n"..
        "Connection: keep-alive\r\n"..
        "Upgrade-Insecure-Requests: 1\r\n"..
        "\r\n"
    ))

    local total_length
    local str = ""

    while true do
        str = str .. assert(sock:receive())

        if not total_length then
            total_length = tonumber(str:match("Content%-Length: (%d+)"))
        end

        local magic = "0\r\n\r\n"
        if str:sub(-#magic) == magic or (total_length and #str >= total_length) then
            break
        end
    end

    ok(total_length and total_length > 1024, "response should be larger than 1024 bytes")
    ok(string.find(str, "HTTP/1.1 200 OK", nil, true) ~= nil, "response should contain HTTP 200 OK")
    ok(string.find(str, "</html>", nil, true) ~= nil, "response should contain closing html tag")
end)

test('TCP client non-blocking test', function()
    local host = "www.freebsd.no"
    local sock = assert(socket.create("inet", "stream", "tcp"))
    assert(sock:connect(host, "http"))
    assert(sock:set_blocking(false))

    local str = ""
    local total_length

    while true do
        if sock:is_connected() then
            assert(sock:send(
                "GET / HTTP/1.1\r\n"..
                "Host: "..host.."\r\n"..
                "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:64.0) Gecko/20100101 Firefox/64.0\r\n"..
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"..
                "Accept-Language: nb,nb-NO;q=0.9,en;q=0.8,no-NO;q=0.6,no;q=0.5,nn-NO;q=0.4,nn;q=0.3,en-US;q=0.1\r\n"..
                "DNT: 1\r\n"..
                "Connection: keep-alive\r\n"..
                "Upgrade-Insecure-Requests: 1\r\n"..
                "\r\n"
            ))

            while true do
                local chunk, err = sock:receive()

                if chunk then
                    str = str .. chunk

                    if not total_length then
                        total_length = tonumber(str:match("Content%-Length: (%d+)"))
                    end

                    if total_length and #str >= total_length then
                        ok(total_length > 1024, "response should be larger than 1024 bytes")
                        ok(string.find(str, "HTTP/1.1 200 OK", nil, true) ~= nil, "response should contain HTTP 200 OK")
                        ok(string.find(str, "</html>", nil, true) ~= nil, "response should contain closing html tag")
                        return
                    end
                elseif err ~= "tryagain" then
                    error("receive error: " .. tostring(err))
                    return
                end
            end
        else
            sock:try_connect()
        end
    end
end)