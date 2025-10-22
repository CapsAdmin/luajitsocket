local socket = require("ljsocket")
local port = 8080

do -- server
	local bind_address = socket.find_first_address_info("*", port) -- 0.0.0.0 for binding
	local server = assert(socket.create("inet", "dgram", "udp"))
	assert(server:set_blocking(false))
	assert(server:bind(bind_address))
	print("hosting at ", bind_address:get_ip(), bind_address:get_port())

	function update_server()
		local data, addr = server:receive_from()

		if data then
			print(data)
			assert(data == "hello from client")
			assert(addr:get_port())
			assert(server:send_to(addr, "hello from server"))
		elseif addr ~= "timeout" then
			error(addr)
		end
	end
end

do -- client
	local send_address = socket.find_first_address_info("127.0.0.1", port) -- localhost for sending
	local client = assert(socket.create("inet", "dgram", "udp"))
	assert(client:set_blocking(false))
	local next_send = 0

	local sent = false
	local times = 0
	function update_client()

		if not sent then
			assert(client:send_to(send_address, "hello from client"))
			sent = true
		end

		local data, addr = client:receive_from()

		if data then
			print(data)
			assert(data == "hello from server")
			assert(addr:get_port())
			assert(client:send_to(send_address, "hello from client"))
			times = times + 1
			if times > 5 then
				return true
			end
		elseif addr ~= "timeout" then
			error(addr)
		end
	end
end

while true do
	if update_client() then break end
	update_server()
end
