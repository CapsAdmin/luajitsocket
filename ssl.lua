local ffi = require("ffi")
local socket = require("ljsocket")
local ssl = {}
local callbacks = {}

function ssl.tls_client()
	local ok, lib = pcall(require, "tls")

	if ok then
		if not lib.initialized then
			lib.tls_init()
			lib.initialized = true
		end

		local client = lib.tls_client()
		lib.tls_configure(client, nil)

		local function connect(fd, host)
			if lib.tls_connect_socket(client, fd, host) < 0 then
				return nil, ffi.string(lib.tls_error(client))
			end

			if lib.tls_handshake(client) < 0 then
				return nil, ffi.string(lib.tls_error(client))
			end
		end

		local function send(data)
			local len = lib.tls_write(client, data, #data)

			if len < 0 then
				return nil, ffi.string(lib.tls_error(client))
			end

			return len
		end

		local function receive(buffer, max_size)
			local len = lib.tls_read(client, buffer, max_size)

			if len < 0 then
				return nil, ffi.string(lib.tls_error(client))
			end

			return ffi.string(buffer, len)
		end

		local function close()
			lib.tls_close(client)
			lib.tls_free(client)
		end

		return {
			connect = connect,
			send = send,
			receive = receive,
			close = close,
		}
	end

	if ffi.os == "Windows" then
		error("NYI")
	elseif ffi.os == "Linux" then
		error("NYI")
	elseif ffi.os == "BSD" then
		error("NYI")
	elseif ffi.os == "POSIX" then
		error("NYI")
	elseif ffi.os == "OSX" then
		ffi.cdef([[
            typedef void* SSLContextRef;
            
            SSLContextRef SSLCreateContext(void* alloc, int protocolSide, int connectionType);
            int SSLClose(SSLContextRef context);
            void CFRelease(void* cf);
            
            int SSLSetConnection(SSLContextRef context, void* connection);
            int SSLSetPeerDomainName(SSLContextRef context, const char* peerName, size_t peerNameLen);
            
            typedef int (*SSLReadFunc)(void* connection, void* data, size_t* dataLength);
            typedef int (*SSLWriteFunc)(void* connection, const void* data, size_t* dataLength);
            
            int SSLSetIOFuncs(SSLContextRef context, SSLReadFunc readFunc, SSLWriteFunc writeFunc);
            
            int SSLHandshake(SSLContextRef context);
            int SSLWrite(SSLContextRef context, const void* data, size_t dataLength, size_t* processed);
            int SSLRead(SSLContextRef context, void* data, size_t dataLength, size_t* processed);
            
            ssize_t read(int fd, void* buf, size_t count);
            ssize_t write(int fd, const void* buf, size_t count);

            int* __error(void);
        ]])
		local lib = ffi.load("/System/Library/Frameworks/Security.framework/Security")
		local status_to_msg
		-- Status codes
		local errSecSuccess = 0
		local errSSLWouldBlock = -9803
		local errSSLClosedGraceful = -9805
		local errSSLClosedAbort = -9806
		-- Protocol side
		local kSSLClientSide = 1
		-- Connection type
		local kSSLStreamType = 0

		do
			ffi.cdef[[
                void *SecCopyErrorMessageString(int32_t status, void *reserved);
                void CFRelease(void *cf);
                const char* CFStringGetCStringPtr(void *theString, unsigned long encoding);

                signed long CFStringGetLength(void *theString);
                signed long CFStringGetMaximumSizeForEncoding(signed long length, unsigned long encoding);
                unsigned char CFStringGetCString(void *theString, char *buffer, signed long bufferSize, unsigned long encoding);
            ]]
			local cf = ffi.load("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
			local kCFStringEncodingUTF8 = 0x08000100

			function status_to_msg(code)
				local cfStr = lib.SecCopyErrorMessageString(code, nil)

				if cfStr == nil then return "Unknown error code: " .. code end

				local length = cf.CFStringGetLength(cfStr)
				local maxSize = cf.CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1
				local buffer = ffi.new("char[?]", maxSize)
				local success = cf.CFStringGetCString(cfStr, buffer, maxSize, kCFStringEncodingUTF8)
				cf.CFRelease(cfStr)

				if success then return ffi.string(buffer) end

				return nil
			end
		end

		-- Create SSL context (client side, stream type)
		local ctx = lib.SSLCreateContext(nil, kSSLClientSide, kSSLStreamType)

		if ctx == nil then error("Failed to create SSL context") end

		-- Helper to get errno
		local function get_errno()
			return ffi.C.__error()[0]
		end

		-- EAGAIN/EWOULDBLOCK on macOS
		local EAGAIN = 35
		-- Read callback
		callbacks.read = callbacks.read or
			ffi.cast("SSLReadFunc", function(connection, data, dataLength)
				local fd_ptr = ffi.cast("int*", connection)
				local fd = fd_ptr[0]
				local len = tonumber(dataLength[0])
				local result = ffi.C.read(fd, data, len)

				if result > 0 then
					dataLength[0] = result
					return errSecSuccess
				elseif result == 0 then
					dataLength[0] = 0
					return errSSLClosedGraceful
				else
					local errno = get_errno()

					if errno == EAGAIN then
						dataLength[0] = 0
						return errSSLWouldBlock
					else
						dataLength[0] = 0
						return errSSLClosedAbort
					end
				end
			end)
		-- Write callback
		callbacks.write = callbacks.write or
			ffi.cast("SSLWriteFunc", function(connection, data, dataLength)
				local fd_ptr = ffi.cast("int*", connection)
				local fd = fd_ptr[0]
				local len = tonumber(dataLength[0])
				local result = ffi.C.write(fd, data, len)

				if result > 0 then
					dataLength[0] = result
					return errSecSuccess
				elseif result == 0 then
					dataLength[0] = 0
					return errSSLClosedAbort
				else
					local errno = get_errno()

					if errno == EAGAIN then
						dataLength[0] = 0
						return errSSLWouldBlock
					else
						dataLength[0] = 0
						return errSSLClosedAbort
					end
				end
			end)

		-- Set I/O callbacks
		if lib.SSLSetIOFuncs(ctx, callbacks.read, callbacks.write) ~= 0 then
			error("Failed to set I/O functions")
		end

		local fd_ref = ffi.new("int[1]")
		local state = "connecting"

		local function connect(fd, host)
			fd_ref[0] = fd

			if state == "connecting" then
				-- Set the connection (pointer to our fd)
				local status = lib.SSLSetConnection(ctx, fd_ref)

				if status ~= 0 then
					return nil, string.format("SSLSetConnection: %s", status_to_msg(status))
				end

				-- Set peer domain name for certificate validation
				if host then
					status = lib.SSLSetPeerDomainName(ctx, host, #host)

					if status ~= 0 then
						return nil, string.format("SSLSetPeerDomainName: %s", status_to_msg(status))
					end
				end

				state = "handshaking"
			end

			if state == "handshaking" then
				local status = lib.SSLHandshake(ctx)

				-- Handle would-block separately from actual errors
				if status == errSSLWouldBlock then
					return nil, "timeout", status
				elseif status ~= 0 then
					return nil, string.format("SSLHandshake: %s", status_to_msg(status))
				end

				-- Handshake completed successfully
				state = "connected"
			end

			-- Only return true when fully connected
			if state == "connected" then return true end

			return nil, "timeout", status
		end

		local function send(data_str)
			local processed = ffi.new("size_t[1]")
			local data_len = #data_str
			-- Create a C buffer to hold the data
			-- This ensures the data pointer remains valid during the SSLWrite call
			local data_buf = ffi.new("uint8_t[?]", data_len)
			ffi.copy(data_buf, data_str, data_len)
			local status = lib.SSLWrite(ctx, data_buf, data_len, processed)

			if status == 0 then return tonumber(processed[0]) end

			if status == errSSLWouldBlock then
				return nil, "timeout", status
			end

			return nil, string.format("SSLWrite: %s", status_to_msg(status))
		end

		local function receive(buffer_ptr, buffer_size)
			local processed = ffi.new("size_t[1]")
			local status = lib.SSLRead(ctx, buffer_ptr, buffer_size, processed)

			if status == 0 then
				local len = tonumber(processed[0])

				if len == 0 then return "" end

				return ffi.string(buffer_ptr, len)
			end

			if status == errSSLWouldBlock then
				return nil, "timeout", status
			end

			return nil, string.format("SSLRead: %s", status_to_msg(status))
		end

		local function close()
			lib.SSLClose(ctx)
			lib.CFRelease(ctx)
		end

		return {
			connect = connect,
			send = send,
			receive = receive,
			close = close,
		}
	end
end

return ssl
