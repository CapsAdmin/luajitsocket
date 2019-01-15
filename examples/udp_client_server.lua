local socket = require("ljsocket")
local port = 8080
local address = socket.find_first_address("*", port)

do -- server
    local server = assert(socket.create("inet", "dgram", "udp"))
    assert(server:set_blocking(false))
    assert(server:bind(address))
    print("hosting at ", address:get_ip(), address:get_port())

    function update_server()
        local data, addr = server:receive_from()

        if data then
            print(data)
            assert(server:send_to(addr, "hello from server " .. os.clock()))
        elseif addr ~= "timeout" then
            error(addr)
        end
    end
end

do -- client
    local client = assert(socket.create("inet", "dgram", "udp"))
    assert(client:set_blocking(false))
    local next_send = 0

    function update_client()
        if next_send < os.clock() then
            assert(client:send_to(address, "hello from client " .. os.clock()))
            next_send = os.clock() + math.random() + 0.5
        end

        local data, addr = client:receive_from(address)

        if data then
            print(data, addr:get_ip(), addr:get_port())
        elseif addr ~= "timeout" then
            error(addr)
        end
    end
end

while true do
    update_server()
    update_client()
end