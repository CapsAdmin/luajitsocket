local socket = require("ljsocket")
local test = require("test.gambarina")

test('UDP client-server communication', function()
	local port = 8080

	-- Server setup
	local bind_address = socket.find_first_address_info("*", port)
	ok(bind_address ~= nil, "should find bind address")

	local server = socket.create("inet", "dgram", "udp")
	ok(server ~= nil, "should create server socket")

	local blocking_set = server:set_blocking(false)
	ok(blocking_set, "should set server to non-blocking")

	local bound = server:bind(bind_address)
	ok(bound, "should bind server to port")

	function update_server()
		local data, addr = server:receive_from()

		if data then
			ok(data == "hello from client", "server should receive 'hello from client'")
			ok(addr:get_port() ~= nil, "should have sender port")
			local sent = server:send_to(addr, "hello from server")
			ok(sent, "server should send response")
		elseif addr ~= "tryagain" then
			ok(false, "server receive error: " .. tostring(addr))
		end
	end

	-- Client setup
	local send_address = socket.find_first_address_info("127.0.0.1", port)
	ok(send_address ~= nil, "should find send address")

	local client = socket.create("inet", "dgram", "udp")
	ok(client ~= nil, "should create client socket")

	local blocking_set = client:set_blocking(false)
	ok(blocking_set, "should set client to non-blocking")

	local sent = false
	local times = 0

	function update_client()
		if not sent then
			local sent_result = client:send_to(send_address, "hello from client")
			ok(sent_result, "client should send initial message")
			sent = true
		end

		local data, addr = client:receive_from()

		if data then
			ok(data == "hello from server", "client should receive 'hello from server'")
			ok(addr:get_port() ~= nil, "should have server port")
			local sent_result = client:send_to(send_address, "hello from client")
			ok(sent_result, "client should send next message")
			times = times + 1
			if times > 5 then
				return true
			end
		elseif addr ~= "tryagain" then
			ok(false, "client receive error: " .. tostring(addr))
		end
	end

	-- Run the client-server loop
	while true do
		if update_client() then break end
		update_server()
	end

	ok(times > 5, "should complete multiple message exchanges")
end)
