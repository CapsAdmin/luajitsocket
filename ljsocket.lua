local ffi = require("ffi")
local socket = {}
local e
local errno
--
local pollfd
local sockaddr
local sockaddr_in
local sockaddr_in6
local sockaddr_ptr
local addrinfo_hints
local addrinfo_out
local SOCKET

do
	local SocketLib = ffi.os == "Windows" and assert(ffi.load("ws2_32")) or ffi.C
	local id = 0

	local function load_c_function(lib, symbol_name, ...)
		local unique_name = id .. "_cdef_anon"
		id = id + 1
		local cdef = {}
		local args = {}

		for i = 1, select("#", ...) do
			local val = select(i, ...)

			if type(val) == "string" then
				local start, stop = val:find("NAME", nil, true)

				if start then
					local before = val:sub(1, start - 1)
					local after = val:sub(stop + 1, #val)
					table.insert(cdef, before)
					table.insert(cdef, "$")
					table.insert(cdef, after)
					table.insert(args, unique_name)
				else
					table.insert(cdef, val)
				end
			elseif type(val) == "cdata" then
				table.insert(cdef, "$")
				table.insert(args, val)
			else
				error("Invalid argument type: " .. type(val), 2)
			end
		end

		local cdef = table.concat(cdef) .. "asm(\"" .. symbol_name .. "\");"
		local ok, err = pcall(ffi.cdef, cdef, unpack(args))

		if not ok then error(err, 2) end

		local ok, func = pcall(function()
			return lib[unique_name]
		end)

		if not ok then error(func, 2) end

		return func
	end

	local function ZERO_SUCCESS(ret)
		if ret == 0 then return true end

		return nil, socket.lasterror()
	end

	local function BELOW_ZERO_ERROR(ret)
		if ret < 0 then return nil, socket.lasterror() end

		return ret
	end

	local function load_socket_function(symbol_name, error_handling, ...)
		local ok, func = pcall(load_c_function, SocketLib, symbol_name, ...)

		if not ok then error(func, 2) end

		return function(...)
			local ret = func(...)

			if error_handling then return error_handling(ret, ...) end

			return ret
		end
	end

	local in_addr = ffi.typeof([[struct { 
		uint32_t s_addr; 
	}]])
	local in6_addr = ffi.typeof([[struct { 
		union {
			uint8_t u6_addr8[16];
			uint16_t u6_addr16[8];
			uint32_t u6_addr32[4];
		} u6_addr; 
	}]])

	-- https://www.cs.dartmouth.edu/~sergey/cs60/on-sockaddr-structs.txt
	if ffi.os == "OSX" then
		sockaddr = ffi.typeof([[
			struct {
				uint8_t sa_len;
				uint8_t sa_family;
				char sa_data[14];
			}
		]])
		sockaddr_in = ffi.typeof(
			[[
			struct {
				uint8_t sin_len;
				uint8_t sin_family;
				uint16_t sin_port;
				$ sin_addr;
				char sin_zero[8];
			}
		]],
			in_addr
		)
		sockaddr_in6 = ffi.typeof(
			[[
			struct {
				uint8_t sin6_len;
				uint8_t sin6_family;
				uint16_t sin6_port;
				uint32_t sin6_flowinfo;
				$ sin6_addr;
				uint32_t sin6_scope_id;
			}
		]],
			in6_addr
		)
		SOCKET = ffi.typeof("int32_t")
		addrinfo_out = ffi.typeof(
			[[
			struct {
                int ai_flags;
                int ai_family;
                int ai_socktype;
                int ai_protocol;
                uint32_t ai_addrlen;
                char *ai_canonname;
                $ *ai_addr;
                void *ai_next;
            }
		]],
			sockaddr
		)
		socket.INVALID_SOCKET = -1
	elseif ffi.os == "Windows" then
		sockaddr = ffi.typeof([[
			struct {
				uint16_t sa_family;
				char sa_data[14];
			}
		]])
		sockaddr_in = ffi.typeof(
			[[
			struct {
				int16_t sin_family;
				uint16_t sin_port;
				$ sin_addr;
				uint8_t sin_zero[8];
			}
		]],
			in_addr
		)
		sockaddr_in6 = ffi.typeof(
			[[
			struct {
				int16_t sin6_family;
				uint16_t sin6_port;
				uint32_t sin6_flowinfo;
				$ sin6_addr;
				uint32_t sin6_scope_id;
			}
		]],
			in6_addr
		)
		SOCKET = ffi.typeof("size_t")
		addrinfo_out = ffi.typeof(
			[[
			struct {
                int ai_flags;
                int ai_family;
                int ai_socktype;
                int ai_protocol;
                size_t ai_addrlen;
                char *ai_canonname;
                $ *ai_addr;
                void *ai_next;
            }
		]],
			sockaddr
		)
		socket.INVALID_SOCKET = ffi.new(SOCKET, -1)
	else -- posix
		sockaddr = ffi.typeof([[
			struct {
				uint16_t sa_family;
				char sa_data[14];
			}
		]])
		sockaddr_in = ffi.typeof(
			[[
			struct {
				uint16_t sin_family;
				uint16_t sin_port;
				$ sin_addr;
				char sin_zero[8];
			}
		]],
			in_addr
		)
		sockaddr_in6 = ffi.typeof(
			[[
			struct {
				uint16_t sin6_family;
				uint16_t sin6_port;
				uint32_t sin6_flowinfo;
				$ sin6_addr;
				uint32_t sin6_scope_id;
			}
		]],
			in6_addr
		)
		SOCKET = ffi.typeof("int32_t")
		addrinfo_out = ffi.typeof(
			[[
			struct {
                int ai_flags;
                int ai_family;
                int ai_socktype;
                int ai_protocol;
                uint32_t ai_addrlen;
                $ *ai_addr;
                char *ai_canonname;
                void *ai_next;
            }
		]],
			sockaddr
		)
		socket.INVALID_SOCKET = -1
	end

	addrinfo_hints = addrinfo_out

	assert(ffi.sizeof(sockaddr) == 16)
	assert(ffi.sizeof(sockaddr_in) == 16)
	pollfd = ffi.typeof([[
		struct {
			$ fd;
			short events;
			short revents;
		}
	]], SOCKET)

	if ffi.os == "Windows" then
		do -- last error
			local FormatMessageA = load_c_function(
				ffi.C,
				"FormatMessageA",
				[[
					uint32_t NAME(uint32_t dwFlags,
						const void* lpSource,
						uint32_t dwMessageId,
						uint32_t dwLanguageId,
						char* lpBuffer,
						uint32_t nSize,
						va_list *Arguments
					)
				]]
			)
			local GetLastError = load_c_function(ffi.C, "GetLastError", "int NAME()")
			local FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
			local FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200
			local flags = bit.bor(FORMAT_MESSAGE_IGNORE_INSERTS, FORMAT_MESSAGE_FROM_SYSTEM)
			local cache = {}

			function socket.lasterror(num)
				num = num or GetLastError()

				if not cache[num] then
					local buffer = ffi.new("char[512]")
					local len = FormatMessageA(flags, nil, num, 0, buffer, ffi.sizeof(buffer), nil)
					cache[num] = ffi.string(buffer, len - 2)
				end

				return cache[num], num
			end
		end

		do -- init
			local wsa_data

			if jit.arch == "x64" then
				wsa_data = ffi.typeof([[struct {
                    uint16_t wVersion;
                    uint16_t wHighVersion;
                    unsigned short iMax_M;
                    unsigned short iMaxUdpDg;
                    char * lpVendorInfo;
                    char szDescription[257];
                    char szSystemStatus[129];
                }]])
			else
				wsa_data = ffi.typeof([[struct {
                    uint16_t wVersion;
                    uint16_t wHighVersion;
                    char szDescription[257];
                    char szSystemStatus[129];
                    unsigned short iMax_M;
                    unsigned short iMaxUdpDg;
                    char * lpVendorInfo;
                }]])
			end

			local WSAStartup = load_c_function(SocketLib, "WSAStartup", "int NAME(uint16_t version, ", wsa_data, " *wsa_data)")

			local function WORD(low, high)
				return bit.bor(low, bit.lshift(high, 8))
			end

			function socket.initialize()
				local data = wsa_data()

				if WSAStartup(WORD(2, 2), data) == 0 then return data end

				return nil, socket.lasterror()
			end
		end

		do -- cleanup
			local WSACleanup = load_c_function(SocketLib, "WSACleanup", "int NAME()")

			function socket.shutdown()
				if WSACleanup() == 0 then return true end

				return nil, socket.lasterror()
			end
		end

		if jit.arch == "x32" then -- xp or something
			local WSAAddressToStringA = load_c_function(
				SocketLib,
				"WSAAddressToStringA",
				"int NAME(",
				sockaddr,
				" *addr, unsigned long addrlen, void *reserved, char *name, unsigned long *namelen)"
			)

			function socket.inet_ntop(family, pAddr, strptr, strlen)
				-- win XP: http://memset.wordpress.com/2010/10/09/inet_ntop-for-win32/
				local srcaddr = sockaddr_in()
				ffi.copy(srcaddr.sin_addr, pAddr, ffi.sizeof(srcaddr.sin_addr))
				srcaddr.sin_family = family
				local len = ffi.new("unsigned long[1]", strlen)
				WSAAddressToStringA(ffi.cast(sockaddr_ptr, srcaddr), ffi.sizeof(srcaddr), nil, strptr, len)
				return strptr
			end
		end

		socket.close = load_socket_function("closesocket", ZERO_SUCCESS, "int NAME(", SOCKET, ")")

		do
			local ioctlsocket = load_socket_function(
				"ioctlsocket",
				ZERO_SUCCESS,
				"int NAME(",
				SOCKET,
				", long cmd, unsigned long* argp)"
			)
			local IOCPARM_MASK = 0x7
			local IOC_IN = 0x80000000

			local function _IOW(x, y, t)
				return bit.bor(
					IOC_IN,
					bit.lshift(bit.band(ffi.sizeof(t), IOCPARM_MASK), 16),
					bit.lshift(x, 8),
					y
				)
			end

			local FIONBIO = _IOW(string.byte("f"), 126, "uint32_t") -- -2147195266 -- 2147772030ULL
			function socket.blocking(fd, b)
				local ret = ioctlsocket(fd, FIONBIO, ffi.new("int[1]", b and 0 or 1))

				if ret then return true end

				return nil, socket.lasterror()
			end
		end

		do
			local WSAPoll = load_c_function(
				SocketLib,
				"WSAPoll",
				"int NAME(",
				pollfd,
				" *fds, unsigned long int nfds, int timeout)"
			)

			function socket.poll(fds, ndfs, timeout)
				local ret = WSAPoll(fds, ndfs, timeout)

				if ret < 0 then return nil, socket.lasterror() end

				return ret
			end
		end
	else
		do
			local strerror = load_c_function(ffi.C, "strerror", "const char *NAME(int errnum)")
			local cache = {}

			function socket.lasterror(num, err_func)
				err_func = err_func or strerror
				num = num or ffi.errno()

				if not cache[num] then
					local err = ffi.string(err_func(num))
					cache[num] = err == "" and tostring(num) or err
				end

				return cache[num], num
			end
		end

		socket.close = load_socket_function("close", ZERO_SUCCESS, "int NAME(", SOCKET, ")")

		do
			local fcntl = load_c_function(ffi.C, "fcntl", "int NAME(int fd, int cmd, ...)")
			local F_GETFL = 3
			local F_SETFL = 4
			local O_NONBLOCK = 04000

			if ffi.os == "OSX" then O_NONBLOCK = 0x0004 end

			function socket.blocking(fd, b)
				local flags = fcntl(fd, F_GETFL, 0)

				if flags < 0 then -- error
				return nil, socket.lasterror() end

				if b then
					flags = bit.band(flags, bit.bnot(O_NONBLOCK))
				else
					flags = bit.bor(flags, O_NONBLOCK)
				end

				local ret = fcntl(fd, F_SETFL, ffi.new("int", flags))

				if ret < 0 then return nil, socket.lasterror() end

				return true
			end
		end

		do
			local poll = load_c_function(ffi.C, "poll", "int NAME(", pollfd, " *fds, unsigned long nfds, int timeout)")

			function socket.poll(fds, ndfs, timeout)
				local ret = poll(fds, ndfs, timeout)

				if ret < 0 then return nil, socket.lasterror() end

				return ret
			end
		end
	end

	do
		local GAI_ERROR_HANDLER

		if ffi.os == "Windows" then
			function GAI_ERROR_HANDLER(ret)
				if ret == 0 then return true end

				return nil, socket.lasterror(ret)
			end
		else
			local gai_strerror = load_c_function(ffi.C, "gai_strerror", "const char *NAME(int errcode)")

			function GAI_ERROR_HANDLER(ret)
				if ret == 0 then return true end

				return nil, socket.lasterror(ret, gai_strerror)
			end
		end

		socket.getaddrinfo = load_socket_function(
			"getaddrinfo",
			GAI_ERROR_HANDLER,
			"int NAME(const char *node, const char *service, const ",
			addrinfo_hints,
			" *hints, ",
			addrinfo_out,
			" **res)"
		)
		socket.getnameinfo = load_socket_function(
			"getnameinfo",
			GAI_ERROR_HANDLER,
			"int NAME(const ",
			sockaddr,
			"* sa, uint32_t salen, char* host, size_t hostlen, char* serv, size_t servlen, int flags)"
		)
	end

	socket.inet_ntop = load_socket_function(
		"inet_ntop",
		function(ret, f, a, strptr, strlen)
			if ret == nil then return nil, socket.lasterror() end

			return strptr
		end,
		"const char *NAME(int af, const void *cp, char *buf, unsigned int len)"
	)
	socket.create = load_socket_function(
		"socket",
		function(ret)
			if ret <= 0 then return nil, socket.lasterror() end

			return ret
		end,
		"",
		SOCKET,
		" NAME(int af, int type, int protocol)"
	)
	socket.freeaddrinfo = load_c_function(SocketLib, "freeaddrinfo", "void NAME(", addrinfo_out, " *ai)")
	socket.inet_ntoa = load_c_function(SocketLib, "inet_ntoa", "char* NAME(", in_addr, ")")
	socket.ntohs = load_c_function(SocketLib, "ntohs", "uint16_t NAME(uint16_t netshort)")
	socket.shutdown = load_socket_function("shutdown", ZERO_SUCCESS, "int NAME(", SOCKET, ", int how)")
	socket.setsockopt = load_socket_function(
		"setsockopt",
		ZERO_SUCCESS,
		"int NAME(",
		SOCKET,
		", int level, int optname, const void* optval, uint32_t optlen)"
	)
	socket.getsockopt = load_socket_function(
		"getsockopt",
		ZERO_SUCCESS,
		"int NAME(",
		SOCKET,
		", int level, int optname, void *optval, uint32_t *optlen)"
	)
	socket.accept = load_socket_function(
		"accept",
		function(ret)
			if ret == socket.INVALID_SOCKET then return nil, socket.lasterror() end

			return ret
		end,
		SOCKET,
		" NAME(",
		SOCKET,
		", ",
		sockaddr,
		" *, int *)"
	)
	socket.bind = load_socket_function(
		"bind",
		ZERO_SUCCESS,
		"int NAME(",
		SOCKET,
		", const ",
		sockaddr,
		"* name, int namelen)"
	)
	socket.connect = load_socket_function(
		"connect",
		ZERO_SUCCESS,
		"int NAME(",
		SOCKET,
		", const ",
		sockaddr,
		"* name, int namelen)"
	)
	socket.listen = load_socket_function("listen", ZERO_SUCCESS, "int NAME(", SOCKET, ", int backlog)")
	socket.recv = load_socket_function("recv", BELOW_ZERO_ERROR, "int NAME(", SOCKET, ", char* buf, int len, int flags)")
	socket.recvfrom = load_socket_function(
		"recvfrom",
		BELOW_ZERO_ERROR,
		"int NAME(",
		SOCKET,
		", char* buf, int len, int flags, ",
		sockaddr,
		" *src_addr, unsigned int *addrlen)"
	)
	socket.send = load_socket_function(
		"send",
		BELOW_ZERO_ERROR,
		"int NAME(",
		SOCKET,
		", const char* buf, int len, int flags)"
	)
	socket.sendto = load_socket_function(
		"sendto",
		BELOW_ZERO_ERROR,
		"int NAME(",
		SOCKET,
		", const char* buf, int len, int flags, const ",
		sockaddr,
		"* to, int tolen)"
	)
	socket.getpeername = load_socket_function(
		"getpeername",
		ZERO_SUCCESS,
		"int NAME(",
		SOCKET,
		", ",
		sockaddr,
		" *, unsigned int *)"
	)
	socket.getsockname = load_socket_function(
		"getsockname",
		ZERO_SUCCESS,
		"int NAME(",
		SOCKET,
		", ",
		sockaddr,
		" *, unsigned int *)"
	)
	sockaddr_ptr = ffi.typeof("$*", sockaddr)

	e = {
		TCP_NODELAY = 1,
		TCP_MAXSEG = 2,
		TCP_CORK = 3,
		TCP_KEEPIDLE = 4,
		TCP_KEEPINTVL = 5,
		TCP_KEEPCNT = 6,
		TCP_SYNCNT = 7,
		TCP_LINGER2 = 8,
		TCP_DEFER_ACCEPT = 9,
		TCP_WINDOW_CLAMP = 10,
		TCP_INFO = 11,
		TCP_QUICKACK = 12,
		TCP_CONGESTION = 13,
		TCP_MD5SIG = 14,
		TCP_THIN_LINEAR_TIMEOUTS = 16,
		TCP_THIN_DUPACK = 17,
		TCP_USER_TIMEOUT = 18,
		TCP_REPAIR = 19,
		TCP_REPAIR_QUEUE = 20,
		TCP_QUEUE_SEQ = 21,
		TCP_REPAIR_OPTIONS = 22,
		TCP_FASTOPEN = 23,
		TCP_TIMESTAMP = 24,
		TCP_NOTSENT_LOWAT = 25,
		TCP_CC_INFO = 26,
		TCP_SAVE_SYN = 27,
		TCP_SAVED_SYN = 28,
		TCP_REPAIR_WINDOW = 29,
		TCP_FASTOPEN_CONNECT = 30,
		TCP_ULP = 31,
		TCP_MD5SIG_EXT = 32,
		TCP_FASTOPEN_KEY = 33,
		TCP_FASTOPEN_NO_COOKIE = 34,
		TCP_ZEROCOPY_RECEIVE = 35,
		TCP_INQ = 36,
		AF_INET = 2,
		AF_INET6 = 10,
		AF_UNSPEC = 0,
		AF_UNIX = 1,
		AF_AX25 = 3,
		AF_IPX = 4,
		AF_APPLETALK = 5,
		AF_NETROM = 6,
		AF_BRIDGE = 7,
		AF_AAL5 = 8,
		AF_X25 = 9,
		INET6_ADDRSTRLEN = 46,
		INET_ADDRSTRLEN = 16,
		SO_DEBUG = 1,
		SO_REUSEADDR = 2,
		SO_TYPE = 3,
		SO_ERROR = 4,
		SO_DONTROUTE = 5,
		SO_BROADCAST = 6,
		SO_SNDBUF = 7,
		SO_RCVBUF = 8,
		SO_SNDBUFFORCE = 32,
		SO_RCVBUFFORCE = 33,
		SO_KEEPALIVE = 9,
		SO_OOBINLINE = 10,
		SO_NO_CHECK = 11,
		SO_PRIORITY = 12,
		SO_LINGER = 13,
		SO_BSDCOMPAT = 14,
		SO_REUSEPORT = 15,
		SO_PASSCRED = 16,
		SO_PEERCRED = 17,
		SO_RCVLOWAT = 18,
		SO_SNDLOWAT = 19,
		SO_RCVTIMEO = 20,
		SO_SNDTIMEO = 21,
		SO_SECURITY_AUTHENTICATION = 22,
		SO_SECURITY_ENCRYPTION_TRANSPORT = 23,
		SO_SECURITY_ENCRYPTION_NETWORK = 24,
		SO_BINDTODEVICE = 25,
		SO_ATTACH_FILTER = 26,
		SO_DETACH_FILTER = 27,
		SO_GET_FILTER = 26,
		SO_PEERNAME = 28,
		SO_TIMESTAMP = 29,
		SO_ACCEPTCONN = 30,
		SO_PEERSEC = 31,
		SO_PASSSEC = 34,
		SO_TIMESTAMPNS = 35,
		SO_MARK = 36,
		SO_TIMESTAMPING = 37,
		SO_PROTOCOL = 38,
		SO_DOMAIN = 39,
		SO_RXQ_OVFL = 40,
		SO_WIFI_STATUS = 41,
		SO_PEEK_OFF = 42,
		SO_NOFCS = 43,
		SO_LOCK_FILTER = 44,
		SO_SELECT_ERR_QUEUE = 45,
		SO_BUSY_POLL = 46,
		SO_MAX_PACING_RATE = 47,
		SO_BPF_EXTENSIONS = 48,
		SO_INCOMING_CPU = 49,
		SO_ATTACH_BPF = 50,
		SO_DETACH_BPF = 27,
		SO_ATTACH_REUSEPORT_CBPF = 51,
		SO_ATTACH_REUSEPORT_EBPF = 52,
		SO_CNX_ADVICE = 53,
		SO_MEMINFO = 55,
		SO_INCOMING_NAPI_ID = 56,
		SO_COOKIE = 57,
		SO_PEERGROUPS = 59,
		SO_ZEROCOPY = 60,
		SO_TXTIME = 61,
		SOL_SOCKET = 1,
		SOL_TCP = 6,
		SOMAXCONN = 128,
		IPPROTO_IP = 0,
		IPPROTO_HOPOPTS = 0,
		IPPROTO_ICMP = 1,
		IPPROTO_IGMP = 2,
		IPPROTO_IPIP = 4,
		IPPROTO_TCP = 6,
		IPPROTO_EGP = 8,
		IPPROTO_PUP = 12,
		IPPROTO_UDP = 17,
		IPPROTO_IDP = 22,
		IPPROTO_TP = 29,
		IPPROTO_DCCP = 33,
		IPPROTO_IPV6 = 41,
		IPPROTO_ROUTING = 43,
		IPPROTO_FRAGMENT = 44,
		IPPROTO_RSVP = 46,
		IPPROTO_GRE = 47,
		IPPROTO_ESP = 50,
		IPPROTO_AH = 51,
		IPPROTO_ICMPV6 = 58,
		IPPROTO_NONE = 59,
		IPPROTO_DSTOPTS = 60,
		IPPROTO_MTP = 92,
		IPPROTO_ENCAP = 98,
		IPPROTO_PIM = 103,
		IPPROTO_COMP = 108,
		IPPROTO_SCTP = 132,
		IPPROTO_UDPLITE = 136,
		IPPROTO_RAW = 255,
		SOCK_STREAM = 1,
		SOCK_DGRAM = 2,
		SOCK_RAW = 3,
		SOCK_RDM = 4,
		SOCK_SEQPACKET = 5,
		SOCK_DCCP = 6,
		SOCK_PACKET = 10,
		SOCK_CLOEXEC = 02000000,
		SOCK_NONBLOCK = 04000,
		AI_PASSIVE = 0x00000001,
		AI_CANONNAME = 0x00000002,
		AI_NUMERICHOST = 0x00000004,
		AI_NUMERICSERV = 0x00000008,
		AI_ALL = 0x00000100,
		AI_ADDRCONFIG = 0x00000400,
		AI_V4MAPPED = 0x00000800,
		AI_NON_AUTHORITATIVE = 0x00004000,
		AI_SECURE = 0x00008000,
		AI_RETURN_PREFERRED_NAMES = 0x00010000,
		AI_FQDN = 0x00020000,
		AI_FILESERVER = 0x00040000,
		POLLIN = 0x0001,
		POLLPRI = 0x0002,
		POLLOUT = 0x0004,
		POLLRDNORM = 0x0040,
		POLLWRNORM = 0x0004,
		POLLRDBAND = 0x0080,
		POLLWRBAND = 0x0100,
		POLLEXTEND = 0x0200,
		POLLATTRIB = 0x0400,
		POLLNLINK = 0x0800,
		POLLWRITE = 0x1000,
		POLLERR = 0x0008,
		POLLHUP = 0x0010,
		POLLNVAL = 0x0020,
		MSG_OOB = 0x01,
		MSG_PEEK = 0x02,
		MSG_DONTROUTE = 0x04,
		MSG_CTRUNC = 0x08,
		MSG_PROXY = 0x10,
		MSG_TRUNC = 0x20,
		MSG_DONTWAIT = 0x40,
		MSG_EOR = 0x80,
		MSG_WAITALL = 0x100,
		MSG_FIN = 0x200,
		MSG_SYN = 0x400,
		MSG_CONFIRM = 0x800,
		MSG_RST = 0x1000,
		MSG_ERRQUEUE = 0x2000,
		MSG_NOSIGNAL = 0x4000,
		MSG_MORE = 0x8000,
		MSG_WAITFORONE = 0x10000,
		MSG_CMSG_CLOEXEC = 0x40000000,
	}
	errno = {
		EAGAIN = 11,
		EWOULDBLOCK = 11, -- is errno.EAGAIN
		EINVAL = 22,
		ENOTSOCK = 88,
		ECONNRESET = 104,
		EINPROGRESS = 115,
		ETIMEDOUT = 60,
	}

	if ffi.os == "Windows" then
		e.SO_SNDLOWAT = 4099
		e.SO_REUSEADDR = 4
		e.SO_KEEPALIVE = 8
		e.SOMAXCONN = 2147483647
		e.AF_INET6 = 23
		e.SO_RCVTIMEO = 4102
		e.SOL_SOCKET = 65535
		e.SO_LINGER = 128
		e.SO_OOBINLINE = 256
		e.POLLWRNORM = 16
		e.SO_ERROR = 4103
		e.SO_BROADCAST = 32
		e.SO_ACCEPTCONN = 2
		e.SO_RCVBUF = 4098
		e.SO_SNDTIMEO = 4101
		e.POLLIN = 768
		e.POLLPRI = 1024
		e.POLLOUT = 16
		e.SO_TYPE = 4104
		e.POLLRDBAND = 512
		e.POLLWRBAND = 32
		e.SO_SNDBUF = 4097
		e.POLLNVAL = 4
		e.POLLHUP = 2
		e.POLLERR = 1
		e.POLLRDNORM = 256
		e.SO_DONTROUTE = 16
		e.SO_RCVLOWAT = 4100
		errno.EINVAL = 10022
		errno.EAGAIN = 10035 -- Note: Does not exist on Windows
		errno.EWOULDBLOCK = 10035
		errno.EINPROGRESS = 10036
		errno.ENOTSOCK = 10038
		errno.ECONNRESET = 10054
		errno.ETIMEDOUT = 10060
	end

	if ffi.os == "OSX" then
		e.SOL_SOCKET = 0xffff
		e.SO_DEBUG = 0x0001
		e.SO_ACCEPTCONN = 0x0002
		e.SO_REUSEADDR = 0x0004
		e.SO_KEEPALIVE = 0x0008
		e.SO_DONTROUTE = 0x0010
		e.SO_BROADCAST = 0x0020
		e.SO_LINGER = 0x0080
		e.SO_OOBINLINE = 0x0100
		e.SO_SNDBUF = 0x1001
		e.SO_RCVBUF = 0x1002
		e.SO_SNDLOWAT = 0x1003
		e.SO_RCVLOWAT = 0x1004
		e.SO_SNDTIMEO = 0x1005
		e.SO_RCVTIMEO = 0x1006
		e.SO_ERROR = 0x1007
		e.SO_TYPE = 0x1008
		e.POLLIN = 0x0001     
		e.POLLPRI = 0x0002    
		e.POLLOUT = 0x0004    
		e.POLLRDNORM = 0x0040 
		e.POLLWRNORM = 0x0004 
		e.POLLRDBAND = 0x0080 
		e.POLLWRBAND = 0x0100 
		e.POLLERR = 0x0008    
		e.POLLHUP = 0x0010    
		e.POLLNVAL = 0x0020   

		e.POLLEXTEND = 0x0200  
		e.POLLATTRIB = 0x0400  
		e.POLLNLINK = 0x0800   
		e.POLLWRITE = 0x1000   
		errno.EINVAL = 22
		errno.EAGAIN = 35
		errno.EWOULDBLOCK = errno.EAGAIN
		errno.EINPROGRESS = 36
		errno.ENOTSOCK = 38
		errno.ECONNRESET = 54
		errno.ETIMEDOUT = 60
	end

	if socket.initialize then assert(socket.initialize()) end
end

local function capture_flags(what)
	local flags = {}
	local reverse = {}

	for k, v in pairs(e) do
		if k:sub(0, #what) == what then
			k = k:sub(#what + 1):lower()
			reverse[v] = k
			flags[k] = v
		end
	end

	local valid_flags = flags
	return {
		lookup = flags,
		reverse = reverse,
		strict_reverse = function(key)
			if not key then error("invalid " .. what:sub(0, -2) .. " flag: nil") end

			if not reverse[key] then
				error("invalid " .. what:sub(0, -2) .. " flag: " .. key, 2)
			end

			return reverse[key]
		end,
		strict_lookup = function(key)
			if not key then error("invalid " .. what:sub(0, -2) .. " flag: nil") end

			if not flags[key] then
				error("invalid " .. what:sub(0, -2) .. " flag: " .. key, 2)
			end

			return flags[key]
		end,
		table_to_flags = function(flags, operation)
			if type(flags) == "string" then flags = {flags} end

			operation = operation or bit.band
			local out = 0

			for k, v in pairs(flags) do
				local flag = valid_flags[v] or valid_flags[k]

				if not flag then error("invalid flag " .. tostring(v), 2) end

				out = operation(out, tonumber(flag))
			end

			return out
		end,
		flags_to_table = function(flags, operation)
			if not flags then return valid_flags.default_valid_flag end

			operation = operation or bit.band
			local out = {}

			for k, v in pairs(valid_flags) do
				if operation(flags, v) > 0 then out[k] = true end
			end

			return out
		end,
	}
end

local SOCK = capture_flags("SOCK_")
local AF = capture_flags("AF_")
local IPPROTO = capture_flags("IPPROTO_")
local AI = capture_flags("AI_")
local SOL = capture_flags("SOL_")
local SO = capture_flags("SO_")
local TCP = capture_flags("TCP_")
local POLL = capture_flags("POLL")
local M = {}
local timeout_messages = {}
timeout_messages[errno.EINPROGRESS] = true
timeout_messages[errno.EAGAIN] = true
timeout_messages[errno.EWOULDBLOCK] = true
timeout_messages[errno.ETIMEDOUT] = true
local pollfd_box = ffi.typeof("$[1]", pollfd)

function M.poll(socks, flags, timeout)
	-- Transform single socket to array
	
	local events = 0
	if flags then
		-- On Windows, POLLERR and POLLHUP are output-only flags and cannot be requested
		if ffi.os == "Windows" then
			local filtered_flags = {}
			for i, flag in ipairs(flags) do
				if flag ~= "err" and flag ~= "hup" then
					table.insert(filtered_flags, flag)
				end
			end
			events = #filtered_flags > 0 and POLL.table_to_flags(filtered_flags, bit.bor) or 0
		else
			events = POLL.table_to_flags(flags, bit.bor)
		end
	end

	-- Create pollfd array for all sockets
	local pfds = {}
	for i, sock in ipairs(socks) do
		pfds[i] = {
			fd = sock.fd,
			events = events,
			revents = 0,
		}
	end
	
	local pfd = ffi.new(pollfd_box, pfds)
	local ok, err = socket.poll(pfd, #socks, timeout or 0)

	if not ok then return ok, err end

	-- Return array of results for each socket
	local results = {}
	for i = 0, #socks - 1 do
		results[i + 1] = POLL.flags_to_table(pfd[i].revents, bit.bor)
	end
	
	return results, ok
end

function M.bind(host, service)
	local info, err = M.find_first_address_info(
		host,
		service,
		{"passive"},
		"inet",
		"stream",
		"tcp"
	)

	if not info then return info, err end

	local server, num
	server, err, num = M.create(info.family, info.socket_type, info.protocol)

	if not server then return server, err, num end

	server:set_option("reuseaddr", 1)
	local ok
	ok, err, num = server:bind(info)

	if not ok then return ok, err, num end

	server:set_option("sndbuf", 65536)
	server:set_option("rcvbuf", 65536)
	return server
end

do -- addrinfo
	local addrinfo_ptr = ffi.typeof("$*", addrinfo_out)

	do
		local meta = {}
		meta.__index = meta

		function M.addressinfo(addrinfo_ptr, host, service)
			local info = {}

			if addrinfo_ptr.ai_canonname ~= nil then
				info.canonical_name = ffi.string(addrinfo_ptr.ai_canonname)
			end

			info.host = host ~= "*" and host or nil
			info.service = service
			info.family = AF.reverse[addrinfo_ptr.ai_family]
			info.socket_type = SOCK.reverse[addrinfo_ptr.ai_socktype]
			info.protocol = IPPROTO.reverse[addrinfo_ptr.ai_protocol]
			info.flags = AI.flags_to_table(addrinfo_ptr.ai_flags, bit.band)
			info.addrinfo = addrinfo_ptr

			setmetatable(info, meta)

			return info
		end

		local sockaddr_in_ptr = ffi.typeof("$*", sockaddr_in)

		function meta:get_ip()
			if self.addrinfo.ai_addr == nil then return nil end

			local str = ffi.new("char[256]")
			local addr = assert(
				socket.inet_ntop(
					AF.lookup[self.family],
					ffi.cast(sockaddr_in_ptr, self.addrinfo.ai_addr).sin_addr,
					str,
					ffi.sizeof(str)
				)
			)
			return ffi.string(addr)
		end

		local sockaddr_in6_ptr = ffi.typeof("$*", sockaddr_in6)

		function meta:get_port()
			if self.addrinfo.ai_addr == nil then return nil end

			if self.family == "inet" then
				return socket.ntohs(ffi.cast(sockaddr_in_ptr, self.addrinfo.ai_addr).sin_port)
			elseif self.family == "inet6" then
				return socket.ntohs(ffi.cast(sockaddr_in6_ptr, self.addrinfo.ai_addr).sin6_port)
			end

			return nil, "unknown family " .. tostring(self.family)
		end

		function meta:__tostring()
			return string.format("addrinfo[%s-%s-%s]", self.family, self.socket_type, self.protocol)
		end

		function meta:free()
			if not self.addrinfo then return end
			socket.freeaddrinfo(self.addrinfo)
			self.addrinfo = nil
		end

		function meta:__gc()
			self:free()
		end

		local addrinfo_out_array_boxed = ffi.typeof("$*[1]", addrinfo_out)

		function M.find_address_info(host, service, flags, socket_type, protocol, family)
			local hints = addrinfo_hints(
				{
					ai_family = family and AF.strict_lookup(family) or nil,
					ai_socktype = socket_type and SOCK.strict_lookup(socket_type) or nil,
					ai_protocol = protocol and IPPROTO.strict_lookup(protocol) or nil,
					ai_flags = flags and AI.table_to_flags(flags, bit.bor) or nil,
				}
			)

			local out = addrinfo_out_array_boxed()
			local ok, err = socket.getaddrinfo(
				host,
				service and tostring(service) or nil,
				hints,
				out
			)

			if not ok then return ok, err end

			local tbl = {}
			local addrinfo = out[0]

			while true do
				table.insert(tbl, setmetatable(M.addressinfo(addrinfo, host, service), meta))

				if addrinfo.ai_next == nil then break end

				addrinfo = ffi.cast(addrinfo_ptr, addrinfo.ai_next)
			end

			return tbl
		end
	end

	function M.find_first_address_info(host, service, flags, family, socket_type, protocol)
		if type(host) == "table" and host.addrinfo then return host end

		service = tostring(service)
		family = family or "inet"
		socket_type = socket_type or "stream"
		protocol = protocol or "tcp"


		flags = flags or {}
		if host == "*" then
			table.insert(flags, "passive")
		end

		local addrinfos, err = M.find_address_info(
			host ~= "*" and host or nil,
			service,
			flags,
			socket_type,
			protocol,
			family
		)

		if not addrinfos then return nil, err end

		if not addrinfos[1] then
			return nil, "no addresses found (empty address info table)"
		end

		for _, v in ipairs(addrinfos) do
			if
				v.family == family and
				v.socket_type == socket_type and
				v.protocol == protocol
			then
				return v
			end
		end

		return addrinfos[1]
	end
end

do
	local meta = {}
	meta.__index = meta

	function meta:__tostring()
		return string.format("socket[%s-%s-%s][%s]", self.family, self.socket_type, self.protocol, self.fd)
	end

	function M.create(family, socket_type, protocol)
		local fd, err, num = socket.create(
			AF.strict_lookup(family),
			SOCK.strict_lookup(socket_type),
			IPPROTO.strict_lookup(protocol)
		)

		if not fd then return fd, err, num end

		return setmetatable(
			{
				fd = fd,
				family = family,
				socket_type = socket_type,
				protocol = protocol,
				blocking = true,
			},
			meta
		)
	end

	function meta:close()
		if self.on_close then self:on_close() end

		return socket.close(self.fd)
	end

	function meta:set_blocking(b)
		local ok, err, num = socket.blocking(self.fd, b)

		if ok then self.blocking = b end

		return ok, err, num
	end

	local timeval = ffi.typeof[[
		struct {
			long tv_sec;
			long tv_usec;
		}
	]]

	function meta:set_option(key, val, level)
		level = level or "socket"

		-- Windows doesn't support SO_BROADCAST on SOCK_STREAM sockets
		if ffi.os == "Windows" and key:lower() == "broadcast" and self.socket_type == "stream" then
			-- Store the value for later retrieval and silently succeed
			if type(val) == "boolean" then
				self._broadcast_fake = val and 1 or 0
			elseif type(val) == "number" then
				self._broadcast_fake = val
			elseif type(val) == "cdata" then
				self._broadcast_fake = val[0]
			end
			return true
		end

		if key:lower() == "rcvtimeo" or key:lower() == "sndtimeo" then
			if ffi.os == "Windows" then
				val = ffi.new("int[1]", val)
			else
				local tv = timeval()
				tv.tv_sec = math.floor(val / 1000)
				tv.tv_usec = (val % 1000) * 1000
				val = tv
			end
		else
			if type(val) == "boolean" then
				val = ffi.new("int[1]", val and 1 or 0)
			elseif type(val) == "number" then
				val = ffi.new("int[1]", val)
			elseif type(val) ~= "cdata" then
				error("unknown value type: " .. type(val))
			end
		end

		local env = SO

		if level == "tcp" then env = TCP end

		return socket.setsockopt(
			self.fd,
			SOL.strict_lookup(level),
			env.strict_lookup(key),
			ffi.cast("void *", val),
			ffi.sizeof(val)
		)
	end

	function meta:get_option(key, level)
		level = level or "socket"

		-- Windows doesn't support SO_BROADCAST on SOCK_STREAM sockets
		if ffi.os == "Windows" and key:lower() == "broadcast" and self.socket_type == "stream" then
			-- Return the value from our fake storage if it was set, otherwise 0
			return self._broadcast_fake or 0
		end

		local env = SO

		if level == "tcp" then env = TCP end

		local val
		local size

		-- Determine the appropriate type and size for the option
		if key:lower() == "rcvtimeo" or key:lower() == "sndtimeo" then
			if ffi.os == "Windows" then
				val = ffi.new("int[1]")
				size = ffi.new("uint32_t[1]", ffi.sizeof("int"))
			else
				val = timeval()
				size = ffi.new("uint32_t[1]", ffi.sizeof(timeval))
			end
		else
			-- Default to int for most socket options
			val = ffi.new("int[1]")
			size = ffi.new("uint32_t[1]", ffi.sizeof("int"))
		end

		local ok, err, num = socket.getsockopt(
			self.fd,
			SOL.strict_lookup(level),
			env.strict_lookup(key),
			ffi.cast("void *", val),
			size
		)

		if not ok then return ok, err, num end

		-- Convert the result based on the option type
		if key:lower() == "rcvtimeo" or key:lower() == "sndtimeo" then
			if ffi.os == "Windows" then
				return val[0]
			else
				return val.tv_usec / 1000
			end
		else
			-- Return as number for most options
			return val[0]
		end
	end

	function meta:connect(host, service)
		local res, err = M.find_first_address_info(host, service, nil, self.family, self.socket_type, self.protocol)

		if not res then return res, err end

		local ok, err, num = socket.connect(self.fd, res.addrinfo.ai_addr, res.addrinfo.ai_addrlen)

		if not ok then
			if not self.blocking and timeout_messages[num] then
				self.timeout_connected = {host, service}
				return true
			end

			if timeout_messages[num] then return nil, "timeout", num end

			return ok, err, num
		end

		if self.on_connect then self:on_connect(host, service) end

		return true
	end

	function meta:try_connect()
		if self.on_connect and self.timeout_connected and self:is_connected() then
			local ok, err, num = self:on_connect(unpack(self.timeout_connected))
			self.timeout_connected = nil
			return ok, err, num
		end

		return nil, "tryagain"
	end

	function meta:bind(host, service)
		if host == "*" then host = nil end

		local res, err = M.find_first_address_info(host, service, nil, self.family, self.socket_type, self.protocol)

		if not res then return res, err end

		return socket.bind(self.fd, res.addrinfo.ai_addr, res.addrinfo.ai_addrlen)
	end

	function meta:listen(max_connections)
		max_connections = max_connections or e.SOMAXCONN
		return socket.listen(self.fd, max_connections)
	end

	function meta:accept()
		local address = sockaddr_in()
		local fd, err, num = socket.accept(
			self.fd,
			ffi.cast(sockaddr_ptr, address),
			ffi.new("unsigned int[1]", ffi.sizeof(address))
		)

		if not self.blocking and timeout_messages[num] then
			return nil, "tryagain", num
		end

		if timeout_messages[num] then return nil, "timeout", num end

		if fd ~= socket.INVALID_SOCKET then
			local client = setmetatable(
				{
					fd = fd,
					family = "unknown",
					socket_type = "unknown",
					protocol = "unknown",
					blocking = true,
				},
				meta
			)

			if self.debug then
				print(tostring(self), ": accept client: ", tostring(client))
			end

			return client
		end

		if self.debug then
			print(tostring(self), ": accept error", num, ":", err)
		end

		return nil, err, num
	end

	function meta:poll(timeout, ...)
		local results, count = M.poll({self}, {...}, timeout)

		if not results then return results, count end
		if count == 0 then return true end

		return results[1]
	end

	function meta:is_connected()
		local ip, service, num = self:get_peer_name()
		local ip2, service2, _ = self:get_name()

		if not ip and (num == errno.ECONNRESET or num == errno.ENOTSOCK) then
			return false, service, num
		end

		if ffi.os == "Windows" then
			return ip ~= "0.0.0.0" and ip2 ~= "0.0.0.0" and service ~= 0 and service2 ~= 0
		else
			return ip and ip2 and service ~= 0 and service2 ~= 0
		end
	end

	function meta:get_peer_name()
		local data = sockaddr_in()
		local len = ffi.new("unsigned int[1]", ffi.sizeof(data))
		local ok, err, num = socket.getpeername(self.fd, ffi.cast(sockaddr_ptr, data), len)

		if not ok then return ok, err, num end

		return ffi.string(socket.inet_ntoa(data.sin_addr)), socket.ntohs(data.sin_port)
	end

	function meta:get_name()
		local data = sockaddr_in()
		local len = ffi.new("unsigned int[1]", ffi.sizeof(data))
		local ok, err, num = socket.getsockname(self.fd, ffi.cast(sockaddr_ptr, data), len)

		if not ok then return ok, err, num end

		return ffi.string(socket.inet_ntoa(data.sin_addr)), socket.ntohs(data.sin_port)
	end

	local default_flags = 0

	if ffi.os ~= "Windows" then default_flags = e.MSG_NOSIGNAL end

	function meta:send_to(addr, data, flags)
		return self:send(data, flags, addr)
	end

	function meta:send(data, flags, addr)
		flags = flags or default_flags

		if self.on_send then return self:on_send(data, flags) end

		local len, err, num

		if addr then
			len, err, num = socket.sendto(self.fd, data, #data, flags, addr.addrinfo.ai_addr, addr.addrinfo.ai_addrlen)
		else
			len, err, num = socket.send(self.fd, data, #data, flags)
		end

		if timeout_messages[num] then
			if not self.blocking then
				return nil, "tryagain", num
			end

			return nil, "timeout", num
		end

		if not len then return len, err, num end

		if len > 0 then return len end
	end

	local sockaddr_in_boxed = ffi.typeof("$[1]", sockaddr_in)

	function meta:receive_from(size, flags)
		return self:receive(size, flags, true)
	end

	function meta:receive(size, flags, return_address)
		size = size or 64000
		local buff = ffi.new("char[?]", size)

		if self.on_receive then return self:on_receive(buff, size, flags) end

		local len, err, num

		local addrinfo

		if return_address then
			local src_address = sockaddr_in_boxed()
			local ai_addrlen_res = ffi.new("int[1]", ffi.sizeof(sockaddr_in))

			len, err, num = socket.recvfrom(
				self.fd,
				buff,
				ffi.sizeof(buff),
				flags or 0,
				ffi.cast(sockaddr_ptr, src_address),
				ai_addrlen_res
			)

			if len and len > 0 then
				addrinfo = M.addressinfo(addrinfo_out({
					ai_addr = ffi.cast(sockaddr_ptr, src_address),
					ai_addrlen = ai_addrlen_res[0],
					ai_family = AF.strict_lookup(self.family),
				}))
			end
		else
			len, err, num = socket.recv(self.fd, buff, ffi.sizeof(buff), flags or 0)
		end

		if num == errno.ECONNRESET then
			self:close()

			if self.debug then print(tostring(self), ": closed") end

			return nil, "closed", num
		end

		if not len then
			if not self.blocking and timeout_messages[num] then
				return nil, "tryagain", num
			end

			if timeout_messages[num] then
				if self.debug then print(tostring(self), ": timeout") end

				return nil, "timeout", num
			end

			if self.debug then print(tostring(self), " error", num, ":", err) end

			return len, err, num
		end

		if len == 0 then
			-- Connection closed gracefully by remote end (FIN received)
			if self.debug then print(tostring(self), ": connection closed by peer") end
			return nil, "closed", 0
		end

		if len > 0 then
			if self.debug then print(tostring(self), ": received ", len, " bytes") end

			return ffi.string(buff, len), addrinfo
		end

		return nil, err, num
	end
end

M.e = e
M.errno = errno
M.socket = socket

return M
