local socket = require("ljsocket")
local test = require("test.gambarina")

test('TCP client-server communication', function()
	local port = 8080
	local update_server
	local update_client

	-- Server setup
	local info = assert(socket.find_first_address_info("*", port, {"passive"}, "inet", "stream", "tcp"))
	local server = assert(socket.create(info.family, info.socket_type, info.protocol))

	assert(server:set_option("reuseaddr", 1))
	assert(server:set_blocking(false))
	assert(server:bind(info))
	assert(server:listen())

	local current_client = nil

	function update_server()
		local client, err = server:accept()

		if client then
			current_client = client
			assert(client:set_blocking(false))
		elseif err ~= "tryagain" then
			error("server accept error: " .. tostring(err))
		end

		if current_client then
			local str, err = current_client:receive()
			if str then
				ok(str == "hello", "server should receive 'hello' message")
				assert(current_client:send(str))
			elseif err == "closed" then
				assert(current_client:close())
				current_client = nil
				return true
			elseif err ~= "tryagain" then
				error("server receive error: " .. tostring(err))
			end
		end
	end

	-- Client setup
	local client = assert(socket.create("inet", "stream", "tcp"))
	assert(client:connect("localhost", port))
	assert(client:set_blocking(false))

	local sent_message = false

	function update_client()
		if client:is_connected() then
			if not sent_message then
				assert(client:send("hello"))
				sent_message = true
			else
				local str, err = client:receive()

				if str then
					ok(str == "hello", "client should receive echo 'hello'")
					assert(client:close())
				elseif err ~= "tryagain" then
					error("client receive error: " .. tostring(err))
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