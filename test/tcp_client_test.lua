require("luacov")
local lunit = require("lunit")
local socket = require("ljsocket")

module("tcp_test", lunit.testcase, package.seeall)

function tcp_client_blocking_test()
    local host = "www.freebsd.no"
    local socket = socket.create("inet", "stream", "tcp")
    lunit.assert(socket)
    lunit.assert(socket:connect(host, "http"))
    lunit.assert(socket:send(
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
        local chunk = socket:receive()
        lunit.assert(chunk)

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

    lunit.assert_true(total_length > 1024)
    lunit.assert_true(string.find(str, "HTTP/1.1 200 OK") > 0)
    lunit.assert_true(string.find(str, "</html>") > 0)
end

function tcp_client_blocking_test()
    local host = "www.freebsd.no"
    local socket = socket.create("inet", "stream", "tcp")
    lunit.assert(socket)
    lunit.assert(socket:connect(host, "http"))
    lunit.assert(socket:set_blocking(false))

    local str = ""
    local total_length

    while true do
        if socket:is_connected() then
            lunit.assert(socket:send(
                "GET / HTTP/1.1\r\n"..
                "Host: "..host.."\r\n"..
                "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:64.0) Gecko/20100101 Firefox/64.0\r\n"..
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"..
                "Accept-Language: nb,nb-NO;q=0.9,en;q=0.8,no-NO;q=0.6,no;q=0.5,nn-NO;q=0.4,nn;q=0.3,en-US;q=0.1\r\n"..
                --"Accept-Encoding: gzip, deflate\r\n"..
                "DNT: 1\r\n"..
                "Connection: keep-alive\r\n"..
                "Upgrade-Insecure-Requests: 1\r\n"..
                "\r\n"
            ))

            while true do
                local chunk, err, num = socket:receive()

                if chunk then
                    str = str .. chunk

                    if not total_length then
                        total_length = tonumber(str:match("Content%-Length: (%d+)"))
                    end

                    if #str >= total_length then
                        return
                    end
                elseif num ~= 11 then
                    error(err)
                end
            end
        else
            socket:poll_connect()
        end
    end

    lunit.assert_true(total_length > 1024)
    lunit.assert_true(string.find(str, "HTTP/1.1 200 OK") > 0)
    lunit.assert_true(string.find(str, "</html>") > 0)
end

lunit.main(...)
