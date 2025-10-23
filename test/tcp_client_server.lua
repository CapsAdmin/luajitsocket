local socket = require("ljsocket")
local test = require("test.gambarina")

test('TCP client-server communication', function()
	local port = 8080
	local update_server
	local update_client

	-- Server setup
	local info = socket.find_first_address_info("*", port, {"passive"}, "inet", "stream", "tcp")
	ok(info ~= nil, "should find address info for server")

	local server = socket.create(info.family, info.socket_type, info.protocol)
	ok(server ~= nil, "should create server socket")

	server:set_option("reuseaddr", 1)
	local blocking_set = server:set_blocking(false)
	ok(blocking_set, "should set server to non-blocking")

	local bound = server:bind(info)
	ok(bound, "should bind server to port")

	local listening = server:listen()
	ok(listening, "should start listening")

	local current_client = nil

	function update_server()
		local client, err = server:accept()

		if client then
			current_client = client
			local blocking_set = client:set_blocking(false)
			ok(blocking_set, "should set client socket to non-blocking")
		elseif err ~= "timeout" then
			ok(false, "server accept error: " .. tostring(err))
		end

		if current_client then
			local str, err = current_client:receive()
			if str then
				ok(str == "hello", "server should receive 'hello' message")
				local sent = current_client:send(str)
				ok(sent, "server should send echo message")
			elseif err == "closed" then
				local closed = current_client:close()
				ok(closed, "should close client connection")
				current_client = nil
				return true
			elseif err ~= "timeout" then
				ok(false, "server receive error: " .. tostring(err))
			end
		end
	end

	-- Client setup
	local client = socket.create("inet", "stream", "tcp")
	ok(client ~= nil, "should create client socket")

	local connected = client:connect("localhost", port)
	ok(connected, "client should connect to server")

	local blocking_set = client:set_blocking(false)
	ok(blocking_set, "should set client to non-blocking")

	local sent_message = false

	function update_client()
		if client:is_connected() then
			if not sent_message then
				local sent = client:send("hello")
				ok(sent, "client should send 'hello' message")
				sent_message = true
			else
				local str, err = client:receive()

				if str then
					ok(str == "hello", "client should receive echo 'hello'")
					client:close()
				elseif err ~= "timeout" then
					ok(false, "client receive error: " .. tostring(err))
				end
			end
		end
	end

	-- Run the client-server loop
	local iterations = 0
	while iterations < 1000 do
		update_client()
		if update_server() then break end
		iterations = iterations + 1
	end

	ok(iterations < 1000, "test should complete within 1000 iterations")
end)