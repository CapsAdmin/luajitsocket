local ffi = require("ffi")
local socket = require("ljsocket")
local ssl = {}

local loaders = {
	function() 
		local lib = require("tls")

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
	end,
	function()
		-- Try to load libcrypto first (required by libssl)
		local crypto_libs = {"/opt/homebrew/opt/openssl/lib/libcrypto.dylib", "crypto", "libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so"}
		local lib_crypto = nil
		for _, name in ipairs(crypto_libs) do
			print("Trying to load Crypto library: " .. name)
			local success, loaded = pcall(ffi.load, name)
			if success then
				print("Loaded Crypto library: " .. name)
				lib_crypto = loaded
				break
			end
		end
		
		-- Try common library names for libssl
		local ssl_libs = {"/opt/homebrew/opt/openssl/lib/libssl.dylib", "ssl", "libssl.so.3", "libssl.so.1.1", "libssl.so"}
		local lib_ssl = nil
		for _, name in ipairs(ssl_libs) do
			print("Trying to load SSL library: " .. name)
			local success, loaded = pcall(ffi.load, name)
			if success then
				print("Loaded SSL library: " .. name)
				lib_ssl = loaded
				break
			end
		end
		
		if not lib_ssl then
			error("Could not load OpenSSL")
		end

		ffi.cdef([[
			typedef struct ssl_st SSL;
			typedef struct ssl_ctx_st SSL_CTX;
			typedef struct ssl_method_st SSL_METHOD;
			
			// Error handling
			unsigned long ERR_get_error(void);
			char* ERR_error_string(unsigned long e, char *buf);
			
			// SSL context
			SSL_CTX* SSL_CTX_new(const SSL_METHOD *method);
			void SSL_CTX_free(SSL_CTX *ctx);
			
			// SSL connection
			SSL* SSL_new(SSL_CTX *ctx);
			int SSL_set_fd(SSL *ssl, int fd);
			int SSL_connect(SSL *ssl);
			int SSL_write(SSL *ssl, const void *buf, int num);
			int SSL_read(SSL *ssl, void *buf, int num);
			int SSL_get_error(SSL *ssl, int ret);
			int SSL_shutdown(SSL *ssl);
			void SSL_free(SSL *ssl);
			
			// SNI support via SSL_ctrl (SSL_set_tlsext_host_name is a macro)
			long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg);
		]])

		-- Try to initialize OpenSSL - handle both old and new versions
		local initialized = false
		
		-- Try modern OpenSSL 1.1.0+ / 3.0+ initialization
		local modern_init = pcall(function()
			ffi.cdef([[
				int OPENSSL_init_ssl(uint64_t opts, void *settings);
			]])
			local ret = lib_ssl.OPENSSL_init_ssl(0, nil)
			if ret ~= 1 then
				error("OPENSSL_init_ssl failed")
			end
		end)
		
		if modern_init then
			initialized = true
		else
			-- Fallback to legacy OpenSSL 1.0.x initialization
			local legacy_init = pcall(function()
				ffi.cdef([[
					void SSL_load_error_strings(void);
					int SSL_library_init(void);
					void OpenSSL_add_all_algorithms(void);
				]])
				lib_ssl.SSL_library_init()
				lib_ssl.SSL_load_error_strings()
				if lib_crypto then
					lib_crypto.OpenSSL_add_all_algorithms()
				end
			end)
			if legacy_init then
				initialized = true
			end
		end

		if not initialized then
			error("Failed to initialize OpenSSL")
		end

		-- Get SSL method - try modern first, then legacy
		local method = nil
		
		-- Try TLS_client_method (OpenSSL 1.1.0+ / 3.0+)
		local modern_ok = pcall(function()
			ffi.cdef([[
				const SSL_METHOD* TLS_client_method(void);
			]])
			method = lib_ssl.TLS_client_method()
		end)
		
		-- Try SSLv23_client_method (OpenSSL 1.0.x)
		if not modern_ok or method == nil then
			local legacy_ok = pcall(function()
				ffi.cdef([[
					const SSL_METHOD* SSLv23_client_method(void);
				]])
				method = lib_ssl.SSLv23_client_method()
			end)
			
			if not legacy_ok then
				-- Try TLSv1_2_client_method as another fallback
				pcall(function()
					ffi.cdef([[
						const SSL_METHOD* TLSv1_2_client_method(void);
					]])
					method = lib_ssl.TLSv1_2_client_method()
				end)
			end
		end
		
		if method == nil then
			error("Failed to get SSL method - OpenSSL library may be incompatible")
		end

		local ctx = lib_ssl.SSL_CTX_new(method)
		if ctx == nil then
			error("Failed to create SSL context")
		end

		local ssl_conn = nil
		local state = "connecting"
		
		-- SSL_ctrl constants for SNI
		local SSL_CTRL_SET_TLSEXT_HOSTNAME = 55
		local TLSEXT_NAMETYPE_host_name = 0

		local function get_error_string()
			local err = lib_ssl.ERR_get_error()
			if err == 0 then
				return "Unknown SSL error"
			end
			local buf = ffi.new("char[256]")
			lib_ssl.ERR_error_string(err, buf)
			return ffi.string(buf)
		end

		local function connect(fd, host)
			if state == "connecting" then
				ssl_conn = lib_ssl.SSL_new(ctx)
				if ssl_conn == nil then
					return nil, "Failed to create SSL connection"
				end

				if lib_ssl.SSL_set_fd(ssl_conn, fd) ~= 1 then
					return nil, "Failed to set file descriptor"
				end

				-- Set SNI hostname for certificate validation
				if host then
					-- SSL_set_tlsext_host_name is a macro, use SSL_ctrl directly
					local ret = lib_ssl.SSL_ctrl(ssl_conn, SSL_CTRL_SET_TLSEXT_HOSTNAME, 
					                              TLSEXT_NAMETYPE_host_name, ffi.cast("void*", host))
					if ret == 0 then
						return nil, "Failed to set SNI hostname"
					end
				end

				state = "handshaking"
			end

			if state == "handshaking" then
				local ret = lib_ssl.SSL_connect(ssl_conn)
				if ret == 1 then
					state = "connected"
					return true
				end

				local err = lib_ssl.SSL_get_error(ssl_conn, ret)
				-- SSL_ERROR_WANT_READ = 2, SSL_ERROR_WANT_WRITE = 3
				if err == 2 or err == 3 then
					return nil, "timeout", err
				end

				return nil, get_error_string()
			end

			if state == "connected" then
				return true
			end

			return nil, "timeout"
		end

		local function send(data_str)
			if not ssl_conn then
				return nil, "Not connected"
			end

			local ret = lib_ssl.SSL_write(ssl_conn, data_str, #data_str)
			if ret > 0 then
				return ret
			end

			local err = lib_ssl.SSL_get_error(ssl_conn, ret)
			if err == 2 or err == 3 then
				return nil, "timeout", err
			end

			return nil, get_error_string()
		end

		local function receive(buffer_ptr, buffer_size)
			if not ssl_conn then
				return nil, "Not connected"
			end

			local ret = lib_ssl.SSL_read(ssl_conn, buffer_ptr, buffer_size)
			if ret > 0 then
				return ffi.string(buffer_ptr, ret)
			end

			if ret == 0 then
				return ""
			end

			local err = lib_ssl.SSL_get_error(ssl_conn, ret)
			if err == 2 or err == 3 then
				return nil, "timeout", err
			end

			return nil, get_error_string()
		end

		local function close()
			if ssl_conn then
				lib_ssl.SSL_shutdown(ssl_conn)
				lib_ssl.SSL_free(ssl_conn)
				ssl_conn = nil
			end
			lib_ssl.SSL_CTX_free(ctx)
		end

		return {
			connect = connect,
			send = send,
			receive = receive,
			close = close,
		}
	end,
	function()
		local lib = ffi.load("/System/Library/Frameworks/Security.framework/Security")
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

		local ctx = lib.SSLCreateContext(nil, kSSLClientSide, kSSLStreamType)

		if ctx == nil then error("Failed to create SSL context") end

		local function get_errno()
			return ffi.C.__error()[0]
		end

		local EAGAIN = 35

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

		if lib.SSLSetIOFuncs(ctx, callbacks.read, callbacks.write) ~= 0 then
			error("Failed to set I/O functions")
		end

		local fd_ref = ffi.new("int[1]")
		local state = "connecting"

		local function connect(fd, host)
			fd_ref[0] = fd

			if state == "connecting" then
				local status = lib.SSLSetConnection(ctx, fd_ref)

				if status ~= 0 then
					return nil, string.format("SSLSetConnection: %s", status_to_msg(status))
				end

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

				if status == errSSLWouldBlock then
					return nil, "timeout", status
				elseif status ~= 0 then
					return nil, string.format("SSLHandshake: %s", status_to_msg(status))
				end

				state = "connected"
			end

			if state == "connected" then return true end

			return nil, "timeout", status
		end

		local function send(data_str)
			local processed = ffi.new("size_t[1]")
			local data_len = #data_str
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
}


local callbacks = {}

function ssl.tls_client()
	for _, loader in ipairs(loaders) do
		local success, result = pcall(loader)

		if success then
			return result
		end
	end

	error("No SSL/TLS implementation available")
end

return ssl