#!/usr/bin/env luajit
local socket = require("ljsocket")
local test = require("test.gambarina")
local ffi = require("ffi")

-- Helper: get wall time in milliseconds using FFI
local get_time_ms
if ffi.os == "Windows" then
    ffi.cdef[[
        unsigned long GetTickCount(void);
    ]]
    get_time_ms = function()
        return tonumber(ffi.C.GetTickCount())
    end
else
    ffi.cdef[[
        typedef long time_t;
        typedef struct { time_t tv_sec; long tv_usec; } timeval;
        int gettimeofday(timeval *tv, void *tz);
    ]]
    local tv = ffi.new("timeval")
    get_time_ms = function()
        ffi.C.gettimeofday(tv, nil)
        return tonumber(tv.tv_sec) * 1000 + tonumber(tv.tv_usec) / 1000
    end
end

-- Helper: simple sleep
local function sleep(ms)
    local start = get_time_ms()
    while get_time_ms() - start < ms do end
end

test('poll() returns immediately with timeout=0', function()
    local sock = assert(socket.create("inet", "dgram", "udp"))
    ok(sock ~= nil, "should create socket")
    sock:set_blocking(false)

    local start = get_time_ms()
    local events = assert(sock:poll(0, "in"))
    local elapsed = get_time_ms() - start

    ok(elapsed < 50, "poll(timeout=0) should return quickly")

    sock:close()
end)

test('poll() respects timeout duration', function()
    local sock = assert(socket.create("inet", "dgram", "udp"))
    sock:set_blocking(false)

    local timeout = 100
    local start = get_time_ms()
    local events = assert(sock:poll(timeout, "in"))
    local elapsed = get_time_ms() - start

    ok(elapsed >= timeout - 10, "poll should wait for timeout")
    ok(elapsed < timeout + 100, "poll should not wait too long")

    sock:close()
end)

test('POLLIN flag set when data available (UDP)', function()
    local server = assert(socket.create("inet", "dgram", "udp"))
    local bind_addr = assert(socket.find_first_address_info("127.0.0.1", 0))
    assert(server:bind(bind_addr))
    assert(server:set_blocking(false))

    local ip, port = server:get_name()
    ok(port ~= nil, "should get server port")

    local client = assert(socket.create("inet", "dgram", "udp"))
    local send_addr = assert(socket.find_first_address_info("127.0.0.1", port))
    assert(client:send_to(send_addr, "test data"))
    sleep(50)

    local events = assert(server:poll(100, "in"))
    ok(events["in"] == true, "POLLIN should be set when data available")

    local data, addr = assert(server:receive_from())
    ok(data == "test data", "should receive correct data")

    server:close()
    client:close()
end)

test('POLLOUT flag set when socket writable', function()
    local sock = assert(socket.create("inet", "dgram", "udp"))
    assert(sock:set_blocking(false))

    local events = assert(sock:poll(100, "out"))
    ok(events["out"] == true, "POLLOUT should be set on writable socket")

    sock:close()
end)

test('Multiple poll flags work correctly', function()
    local sock = assert(socket.create("inet", "dgram", "udp"))
    assert(sock:set_blocking(false))

    local events = assert(sock:poll(100, "in", "out"))
    ok(events["out"] == true, "POLLOUT should be set")

    sock:close()
end)

test('POLLERR detection', function()
    local sock = assert(socket.create("inet", "stream", "tcp"))
    assert(sock:set_blocking(false))

    local connect_addr = assert(socket.find_first_address_info("127.0.0.1", 1))
    sock:connect(connect_addr)

    local events = assert(sock:poll(1000, "out", "err"))
    ok(events["out"] or events["err"], "should have POLLOUT or POLLERR")

    sock:close()
end)

test('TCP non-blocking connect detection with POLLOUT', function()
    local server = assert(socket.create("inet", "stream", "tcp"))
    local bind_addr = assert(socket.find_first_address_info("127.0.0.1", 0))
    assert(server:bind(bind_addr))
    assert(server:listen(1))

    local ip, port = server:get_name()
    ok(port ~= nil, "should get server port")

    local client = assert(socket.create("inet", "stream", "tcp"))
    assert(client:set_blocking(false))

    local connect_addr = assert(socket.find_first_address_info("127.0.0.1", port))
    client:connect(connect_addr)

    local events = assert(client:poll(2000, "out"))
    ok(events["out"] == true, "POLLOUT should be set after connect")

    local errno = client:get_option("error", "socket")
    ok(errno == 0, "connection should succeed")

    client:close()
    server:close()
end)

test('POLLHUP detection on peer disconnect', function()
    local server = assert(socket.create("inet", "stream", "tcp"))
    local bind_addr = assert(socket.find_first_address_info("127.0.0.1", 0))
    assert(server:bind(bind_addr))
    assert(server:listen(1))
    assert(server:set_blocking(false))

    local ip, port = server:get_name()
    ok(port ~= nil, "should get server port")

    local client = assert(socket.create("inet", "stream", "tcp"))
    local connect_addr = assert(socket.find_first_address_info("127.0.0.1", port))
    assert(client:connect(connect_addr))

    sleep(50)
    local conn, err = server:accept()
    ok(conn ~= nil, "should accept connection")
    assert(conn:set_blocking(false))

    client:close()
    sleep(100)

    local events = assert(conn:poll(500, "in", "hup"))
    ok(events["in"] or events["hup"], "should have POLLIN or POLLHUP after close")

    conn:close()
    server:close()
end)

test('poll() with empty flags returns zero events', function()
    local sock = assert(socket.create("inet", "dgram", "udp"))
    assert(sock:set_blocking(false))

    local events = assert(sock:poll(100))
    ok(events == true, "should have no events with empty flags")

    sock:close()
end)

test('Rapid polling with timeout=0 does not block', function()
    local sock = assert(socket.create("inet", "dgram", "udp"))
    assert(sock:set_blocking(false))

    local start = get_time_ms()
    for i = 1, 100 do
        assert(sock:poll(0, "in"))
    end
    local elapsed = get_time_ms() - start

    ok(elapsed < 500, "100 rapid polls should complete quickly")

    sock:close()
end)

test('poll() on closed socket returns error', function()
    local sock = assert(socket.create("inet", "dgram", "udp"))
    sock:close()

    local events, err = sock:poll(100, "in")
    ok(events == nil or (events and events["nval"]), "poll on closed socket should error or return POLLNVAL")
end)

test('Full UDP send/receive cycle with poll()', function()
    local server = assert(socket.create("inet", "dgram", "udp"))
    local bind_addr = assert(socket.find_first_address_info("127.0.0.1", 0))
    assert(server:bind(bind_addr))
    assert(server:set_blocking(false))

    local ip, port = server:get_name()
    ok(port ~= nil, "should get server port")

    local client = assert(socket.create("inet", "dgram", "udp"))
    assert(client:set_blocking(false))
    local send_addr = assert(socket.find_first_address_info("127.0.0.1", port))

    local events = assert(client:poll(100, "out"))
    ok(events["out"], "client should be writable")
    client:send_to(send_addr, "ping")

    sleep(50)

    events = assert(server:poll(500, "in"))
    ok(events["in"], "server should have data")

    local data, addr = assert(server:receive_from())
    ok(data == "ping", "server should receive ping")

    events = assert(server:poll(100, "out"))
    ok(events["out"], "server should be writable")
    server:send_to(addr, "pong")

    sleep(50)

    events = assert(client:poll(500, "in"))
    ok(events["in"], "client should have data")

    data, addr = assert(client:receive_from())
    ok(data == "pong", "client should receive pong")

    server:close()
    client:close()
end)

test('POLLIN on listening socket indicates accept readiness', function()
    local server = assert(socket.create("inet", "stream", "tcp"))
    local bind_addr = assert(socket.find_first_address_info("127.0.0.1", 0))
    assert(server:bind(bind_addr))
    assert(server:listen(1))
    assert(server:set_blocking(false))

    local ip, port = server:get_name()
    ok(port ~= nil, "should get server port")

    local client = assert(socket.create("inet", "stream", "tcp"))
    local connect_addr = assert(socket.find_first_address_info("127.0.0.1", port))
    assert(client:connect(connect_addr))

    sleep(50)

    local events = assert(server:poll(500, "in"))
    ok(events["in"], "POLLIN should be set when connection pending")

    local conn = server:accept()
    ok(conn ~= nil, "accept should succeed when POLLIN set")

    conn:close()
    client:close()
    server:close()
end)

test('poll() with -1 timeout waits indefinitely', function()
    local sock = assert(socket.create("inet", "dgram", "udp"))
    ok(sock ~= nil, "should create socket")
    sock:set_blocking(false)

    local sender = assert(socket.create("inet", "dgram", "udp"))
    local bind_addr = assert(socket.find_first_address_info("127.0.0.1", 0))
    assert(sock:bind(bind_addr))

    local ip, port = sock:get_name()
    ok(port ~= nil, "should get socket port")
    local send_addr = assert(socket.find_first_address_info("127.0.0.1", port))

    assert(sender:send_to(send_addr, "wake up"))
    sleep(50)

    local start = get_time_ms()
    local events = assert(sock:poll(-1, "in"))
    local elapsed = get_time_ms() - start

    ok(events["in"], "poll(-1) should detect data")
    ok(elapsed < 5000, "poll(-1) should return when data available")

    sender:close()
    sock:close()
end)

test('Large UDP datagram handling with poll()', function()
    local server = assert(socket.create("inet", "dgram", "udp"))
    local bind_addr = assert(socket.find_first_address_info("127.0.0.1", 0))
    assert(server:bind(bind_addr))
    assert(server:set_blocking(false))

    local ip, port = server:get_name()
    ok(port ~= nil, "should get server port")

    local client = assert(socket.create("inet", "dgram", "udp"))
    local send_addr = assert(socket.find_first_address_info("127.0.0.1", port))

    local large_data = string.rep("X", 1024)

    assert(client:send_to(send_addr, large_data))
    sleep(50)

    local events = assert(server:poll(500, "in"))
    ok(events["in"], "server should receive large datagram")

    local data = assert(server:receive_from())
    ok(#data == 1024, "should receive full 1024 bytes")
    ok(data == large_data, "data should not be corrupted")

    server:close()
    client:close()
end)
