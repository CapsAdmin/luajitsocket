local socket = require("ljsocket")
local port = 8080
local update_server
local update_client

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
	print("server: listening on port", port)
	local current_client = nil

	function update_server()
		local client, err = server:accept()

		if client then
			current_client = client
			assert(client:set_blocking(false))
			print("server: client connected")
		elseif err ~= "timeout" then
			error(err)
		end

		if current_client then
			local str, err = current_client:receive()
			if str then
				print("server: received", str)
				assert(str == "hello")
				assert(current_client:send(str))
				print("server: sent", str)
			elseif err == "closed" then
				print("server: client disconnected")
				assert(current_client:close())
				current_client = nil
				return true
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
	print("client: connected to server on port", port)
	local sent_message = false

	function update_client()
		if client:is_connected() then
			if not sent_message then
				print("client: sending ", "hello")
				assert(client:send("hello"))
				sent_message = true
			else
				local str, err = client:receive()

				if str then
					print("client: received", str)
					assert(str == "hello")
					print("client: closing")
					client:close()
				elseif err ~= "timeout" then
					error(err)
				end
			end
		end
	end
end

local iterations = 0
while iterations < 1000 do
	update_client()
	if update_server() then break end
	iterations = iterations + 1
end

if iterations == 1000 then
	error("test did not complete in time")
end