local socket = require("ljsocket")
local host = "www.google.com"
local socket = assert(socket.create("inet", "stream", "tcp"))
local ssl = require("ssl")
do
    local tls = ssl.tls_client()

    function socket:on_connect(host, service)
        return tls.connect(self.fd, host)
    end

    function socket:on_send(data, flags)
        return tls.send(data)
    end

    function socket:on_receive(buffer, max_size, flags)
        return tls.receive(buffer, max_size)
    end

    function socket:on_close()
        return tls.close()
    end
end

assert(socket:connect(host, "https"))

assert(socket:send(
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

local total_length
local str = ""

while true do
    local chunk = assert(socket:receive())

    if not chunk then
        break
    end

    str = str .. chunk

    if not total_length then
        total_length = tonumber(str:match("Content%-Length: (%d+)"))
    end

    local magic = "0\r\n\r\n"
    if str:sub(-#magic) == magic or (total_length and #str >= total_length) then
        break
    end
end

print(str)