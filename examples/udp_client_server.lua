local socket = require("ljsocket")
local port = 8080

do -- server
    local bind_address = socket.find_first_address("*", port)  -- 0.0.0.0 for binding
    local server = assert(socket.create("inet", "dgram", "udp"))
    assert(server:set_blocking(false))
    assert(server:bind(bind_address))
    print("hosting at ", bind_address:get_ip(), bind_address:get_port())

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
    local send_address = socket.find_first_address("127.0.0.1", port)  -- localhost for sending
    local client = assert(socket.create("inet", "dgram", "udp"))
    assert(client:set_blocking(false))
    local next_send = 0

    function update_client()
        if next_send < os.clock() then
            assert(client:send_to(send_address, "hello from client " .. os.clock()))
            next_send = os.clock() + math.random() + 0.5
        end

        local data, addr = client:receive_from()

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