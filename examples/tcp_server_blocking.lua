local socket = require("ljsocket")
print("goto http://127.0.0.1:5001")

do -- server
	local host = nil
	local port = 5001
	-- Create a SOCKET for connecting to server
	local server = assert(socket.create("inet", "stream", "tcp"))
	server:set_option("reuseaddr", 1)
	assert(server:bind(host, port))
	assert(server:listen())
	local body = "<html><body><h1>hello world</h1></body></html>"
	-- \z or zapp is Lua's way to concatenate multi-line strings without newlines
	local header = "[HTTP/1.1 200 OK\r\n\z
        Server: masrv/0.1.0\r\n\z
        Date: Thu, 28 Mar 2013 22:16:09 GMT\r\n\z
        Content-Type: text/html\r\n\z
        Connection: Keep-Alive\r\n\z
        Content-Length: " .. #body .. "\r\n\z
        Last-Modified: Wed, 21 Sep 2011 14:34:51 GMT\r\n\z
        Accept-Ranges: bytes\r\n\z
        \r\n"
	local content = header .. body

	while true do
		local client, err = server:accept()

		if client then
			assert(client:send(content))
			print("client connected ", client)
			local str, err = client:receive()

			if str then
				print(str)
				client:close()
			elseif err == "closed" then
				client:close()
			end
		end
	end
end
