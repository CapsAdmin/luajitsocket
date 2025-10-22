local socket = require("ljsocket")
local port = 8080

do -- server
	local info = assert(
		socket.find_first_address_info("*", port, {"passive"}, "inet", "stream", "tcp")
	)
	-- Create a SOCKET for connecting to server
	local server = assert(socket.create(info.family, info.socket_type, info.protocol))
	server:set_option("reuseaddr", 1)
	assert(server:set_blocking(false))
	assert(server:bind(info))
	assert(server:listen())
	local current_client = nil

	function update_server()
		local client, err = server:accept()

		if client then
			current_client = client
			assert(client:set_blocking(false))
		elseif err ~= "timeout" then
			error(err)
		end

		if current_client then
			local str, err = current_client:receive()

			if str then
				assert(str == "hello")
				current_client:send(str)
			elseif err == "closed" then
				current_client:close()
			elseif err ~= "timeout" then
				error(err)
			end
		end
	end
end

do -- client
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
				local data, err = client:receive()

				if data then
					assert(data == "hello")
					client:close()
				elseif err ~= "timeout" then
					error(err)
				end
			end
		end
	end
end

while true do
	update_server()
	update_client()
end
