--[[
    berkeley sockets with unix and windows support

    the goal is to provide a minimal abstraction for
    the unix domain socket api, hide platform differences
    and expose enums.

    It also handles errors and so the function calls will
    return errors lua-style.

    ---
    local bsock = require("bsocket_ffi")
    local e = bsock.e
    local fd, err = bsock.socket(e.AF_INET, e.SOCK_STREAM, 0)
    if fd then
        print("got file descriptor: ", fd)
    else
        error(err)
    end
    ---

    This file is not intended for direct use. It was made as
    a building block for a higher level socket abstraction
]]

local ffi = require("ffi")

local C

if jit.os == "Windows" then
    C = assert(ffi.load("ws2_32"))
else
    C = ffi.C
end

local M = {}

local function generic_function(C_name, cdef, alias, size_error_handling)
    ffi.cdef(cdef)

    alias = alias or C_name
    local func_name = "socket_" .. alias
    local func = C[C_name]

    if size_error_handling == false then
        M[func_name] = func
    elseif size_error_handling then
        M[func_name] = function(...)
            local len = func(...)
            if len < 0 then
                return nil, M.lasterror()
            end

            return len
        end
    else
        M[func_name] = function(...)
            local ret = func(...)

            if ret == 0 then
                return true
            end

            return nil, M.lasterror()
        end
    end
end

ffi.cdef([[
    struct sockaddr {
        unsigned short sa_family;
        char sa_data[14];
    };

    struct in_addr
    {
        uint32_t s_addr;
    };

    char *strerror(int errnum);
    int getaddrinfo(char const *node, char const *service, struct addrinfo const *hints, struct addrinfo **res);
    int getnameinfo(const struct sockaddr* sa, uint32_t salen, char* host, size_t hostlen, char* serv, size_t servlen, int flags);
    void freeaddrinfo(struct addrinfo *ai);
    const char *gai_strerror(int errcode);
    char *inet_ntoa(struct in_addr in);
    uint16_t ntohs(uint16_t netshort);

]])

function M.getaddrinfo(node_name, service_name, hints, result)
    local ret = C.getaddrinfo(node_name, service_name, hints, result)
    if ret == 0 then
        return true
    end

    return nil, ffi.string(C.gai_strerror(ret))
end

function M.getnameinfo(address, length, host, hostlen, serv, servlen, flags)
    local ret = C.getnameinfo(address, length, host, hostlen, serv, servlen, flags)
    if ret == 0 then
        return true
    end

    return nil, ffi.string(C.gai_strerror(ret))
end

do
    ffi.cdef("const char *inet_ntop(int __af, const void *__cp, char *__buf, unsigned int __len);")

    function M.inet_ntop(family, addrinfo, strptr, strlen)
        if C.inet_ntop(family, addrinfo, strptr, strlen) == nil then
            return nil, M.lasterror()
        end

        return strptr
    end
end


if jit.os == "Windows" then
    ffi.cdef([[
        typedef uint64_t SOCKET;

        struct addrinfo
        {
            int ai_flags;
            int ai_family;
            int ai_socktype;
            int ai_protocol;
            size_t ai_addrlen;
            char *ai_canonname;
            struct sockaddr *ai_addr;
            struct addrinfo *ai_next;
        };

        struct sockaddr_in {
            int16_t sin_family;
            uint16_t sin_port;
            struct in_addr sin_addr;
            uint8_t sin_zero[8];
        };

        struct pollfd {
            SOCKET fd;
            short events;
            short revents;
        };
        int WSAPoll(struct pollfd *fds, unsigned long int nfds, int timeout);

        uint32_t GetLastError();
        uint32_t FormatMessageA(
            uint32_t dwFlags,
            const void* lpSource,
            uint32_t dwMessageId,
            uint32_t dwLanguageId,
            char* lpBuffer,
            uint32_t nSize,
            va_list *Arguments
        );
    ]])

    M.INVALID_SOCKET = ffi.new("SOCKET", -1)

    local function WORD(low, high)
        return bit.bor(low , bit.lshift(high , 8))
    end

    do
        ffi.cdef("int GetLastError();")

        local FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
        local FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200
        local flags = bit.bor(FORMAT_MESSAGE_IGNORE_INSERTS, FORMAT_MESSAGE_FROM_SYSTEM)

        local cache = {}

        function M.lasterror(num)
            num = num or ffi.C.GetLastError()

            if not cache[num] then
                local buffer = ffi.new("char[512]")
                local len = ffi.C.FormatMessageA(flags, nil, num, 0, buffer, ffi.sizeof(buffer), nil)
                cache[num] = ffi.string(buffer, len - 2)
            end

            return cache[num]
        end
    end

    do
        ffi.cdef("int WSAStartup(uint16_t version, void *wsa_data);")

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

        function M.initialize()
            local data = wsa_data()

            if C.WSAStartup(WORD(2, 2), data) == 0 then
                return data
            end

            return nil, M.lasterror()
        end
    end

    do
        ffi.cdef("int WSACleanup();")

        function M.shutdown()
            if C.WSACleanup() == 0 then
                return true
            end

            return nil, M.lasterror()
        end
    end

    if jit.arch ~= "x64" then -- xp or something
        ffi.cdef("int WSAAddressToStringA(struct sockaddr *, unsigned long, void *, char *, unsigned long *);")

        function M.inet_ntop(family, pAddr, strptr, strlen)
            -- win XP: http://memset.wordpress.com/2010/10/09/inet_ntop-for-win32/
            local srcaddr = ffi.new("struct sockaddr_in")
            ffi.copy(srcaddr.sin_addr, pAddr, ffi.sizeof(srcaddr.sin_addr))
            srcaddr.sin_family = family
            local len = ffi.new("unsigned long[1]", strlen)
            return C.WSAAddressToStringA(ffi.cast("struct sockaddr *", srcaddr), ffi.sizeof(srcaddr), nil, strptr, len)
        end
    end

    function M.wouldblock()
        return ffi.C.GetLastError() == 10035
    end

    generic_function("closesocket", "int closesocket(SOCKET s);", "close")

    do
        ffi.cdef("int ioctlsocket(SOCKET s, long cmd, unsigned long* argp);")

        local IOCPARM_MASK    = 0x7
        local IOC_IN          = 0x80000000
        local function _IOW(x,y,t)
            return bit.bor(IOC_IN, bit.lshift(bit.band(ffi.sizeof(t),IOCPARM_MASK),16), bit.lshift(x,8), y)
        end

        local FIONBIO = _IOW(string.byte'f', 126, "uint32_t") -- -2147195266 -- 2147772030ULL

        function M.socket_blocking(fd, b)
            local ret = C.ioctlsocket(fd, FIONBIO, ffi.new("int[1]", b and 0 or 1))
            if ret == 0 then
                return true
            end

            return nil, M.lasterror()
        end
    end

    function M.poll(fds, ndfs, timeout)
        local ret = C.WSAPoll(fds, ndfs, timeout)
        if ret < 0 then
            return nil, M.lasterror()
        end
        return ret
    end
else
    ffi.cdef([[
        typedef int SOCKET;

        struct addrinfo {
			int ai_flags;
			int ai_family;
			int ai_socktype;
			int ai_protocol;
			unsigned int ai_addrlen;
			struct sockaddr *ai_addr;
			char *ai_canonname;
			struct addrinfo *ai_next;
        };


        struct sockaddr_in {
            uint8_t sin_len;
            unsigned short sin_family;
            uint16_t sin_port;
            struct in_addr sin_addr;
            char sin_zero[8];
        };

        struct pollfd {
            SOCKET fd;
            short events;
            short revents;
        };

        int poll(struct pollfd *fds, unsigned long nfds, int timeout);
    ]])

    M.INVALID_SOCKET = -1

    do
        local cache = {}

        function M.lasterror(num)
            num = num or ffi.errno()

            if not cache[num] then
                local err = ffi.string(ffi.C.strerror(num))
                cache[num] = err == "" and tostring(num) or err
            end

            return cache[num]
        end
    end

    generic_function("close", "int close(SOCKET s);")

    do
        ffi.cdef("int fcntl(int, int, ...);")

        local F_GETFL = 3
        local F_SETFL = 4
        local O_NONBLOCK = 04000

        function M.socket_blocking(fd, b)
            local flags = ffi.C.fcntl(fd, F_GETFL, 0)

            if flags < 0 then
                -- error
                return nil, M.lasterror()
            end

            if b then
                flags = bit.band(flags, bit.bnot(O_NONBLOCK))
            else
                flags = bit.bor(flags, O_NONBLOCK)
            end

            local ret = ffi.C.fcntl(fd, F_SETFL, ffi.new("int", flags))

            if ret < 0 then
                return nil, M.lasterror()
            end

            return true
        end
    end

    function M.wouldblock()
        local err = ffi.errno()
        return err == 11 or err == 115 or err == 114
    end

    function M.poll(fds, ndfs, timeout)
        local ret = C.poll(fds, ndfs, timeout)
        if ret < 0 then
            return nil, M.lasterror()
        end
        return ret
    end
end

do
    ffi.cdef("SOCKET socket(int af, int type, int protocol);")

    function M.socket(af, type, protocol)
        local fd = C.socket(af, type, protocol)

        if fd <= 0 then
            return nil, M.lasterror()
        end

        return fd
    end
end

generic_function("shutdown", "int shutdown(SOCKET s, int how);")

generic_function("setsockopt", "int setsockopt(SOCKET s, int level, int optname, const void* optval, uint32_t optlen);")
generic_function("getsockopt", "int getsockopt(SOCKET s, int level, int optname, void *optval, uint32_t *optlen);")

generic_function("accept", "SOCKET accept(SOCKET s, struct sockaddr *, int *);", nil, false)
generic_function("bind", "int bind(SOCKET s, const struct sockaddr* name, int namelen);")
generic_function("connect", "int connect(SOCKET s, const struct sockaddr * name, int namelen);")

generic_function("listen", "int listen(SOCKET s, int backlog);")
generic_function("recv", "int recv(SOCKET s, char* buf, int len, int flags);", nil, true)

generic_function("send", "int send(SOCKET s, const char* buf, int len, int flags);", nil, true)
generic_function("sendto", "int sendto(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen);", nil, true)

generic_function("getpeername", "int getpeername(SOCKET s, struct sockaddr *, unsigned int *);")
generic_function("getsockname", "int getsockname(SOCKET s, struct sockaddr *, unsigned int *);")

M.inet_ntoa = C.inet_ntoa
M.ntohs = C.ntohs

function M.poll(fd, events, revents)

end

M.e = {
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

if jit.os == "Windows" then
    M.e.SO_SNDLOWAT = 4099
    M.e.SO_REUSEADDR = 4
    M.e.SO_KEEPALIVE = 8
    M.e.SOMAXCONN = 2147483647
    M.e.AF_INET6 = 23
    M.e.SO_RCVTIMEO = 4102
    M.e.SOL_SOCKET = 65535
    M.e.SO_LINGER = 128
    M.e.SO_OOBINLINE = 256
    M.e.POLLWRNORM = 16
    M.e.SO_ERROR = 4103
    M.e.SO_BROADCAST = 32
    M.e.SO_ACCEPTCONN = 2
    M.e.SO_RCVBUF = 4098
    M.e.SO_SNDTIMEO = 4101
    M.e.POLLIN = 768
    M.e.POLLPRI = 1024
    M.e.SO_TYPE = 4104
    M.e.POLLRDBAND = 512
    M.e.POLLWRBAND = 32
    M.e.SO_SNDBUF = 4097
    M.e.POLLNVAL = 4
    M.e.POLLHUP = 2
    M.e.POLLERR = 1
    M.e.POLLRDNORM = 256
    M.e.SO_DONTROUTE = 16
    M.e.SO_RCVLOWAT = 4100
end

return M