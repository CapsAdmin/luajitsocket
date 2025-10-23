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
    local sock = socket.create("inet", "dgram", "udp")
    ok(sock ~= nil, "should create socket")
    sock:set_blocking(false)

    local start = get_time_ms()
    local events, count = socket.poll(sock, {"in"}, 0)
    local elapsed = get_time_ms() - start

    ok(elapsed < 50, "poll(timeout=0) should return quickly")
    ok(count ~= nil, "poll should return count")

    sock:close()
end)

test('poll() respects timeout duration', function()
    local sock = socket.create("inet", "dgram", "udp")
    ok(sock ~= nil, "should create socket")
    sock:set_blocking(false)

    local timeout = 100
    local start = get_time_ms()
    local events, count = socket.poll(sock, {"in"}, timeout)
    local elapsed = get_time_ms() - start

    ok(elapsed >= timeout - 10, "poll should wait for timeout")
    ok(elapsed < timeout + 100, "poll should not wait too long")
    ok(count == 0, "should have no events")

    sock:close()
end)

test('POLLIN flag set when data available (UDP)', function()
    local server = socket.create("inet", "dgram", "udp")
    ok(server ~= nil, "should create server socket")
    local bind_addr = socket.find_first_address_info("127.0.0.1", 0)
    ok(bind_addr ~= nil, "should find bind address")
    server:bind(bind_addr)
    server:set_blocking(false)

    local ip, port = server:get_name()
    ok(port ~= nil, "should get server port")

    local client = socket.create("inet", "dgram", "udp")
    ok(client ~= nil, "should create client socket")
    local send_addr = socket.find_first_address_info("127.0.0.1", port)
    ok(send_addr ~= nil, "should find send address")

    client:send_to(send_addr, "test data")
    sleep(50)

    local events, count = socket.poll(server, {"in"}, 100)
    ok(events ~= nil, "poll should return events")
    ok(events["in"] == true, "POLLIN should be set when data available")
    ok(count == 1, "should have 1 event")

    local data, addr = server:receive_from()
    ok(data == "test data", "should receive correct data")

    server:close()
    client:close()
end)

test('POLLOUT flag set when socket writable', function()
    local sock = socket.create("inet", "dgram", "udp")
    ok(sock ~= nil, "should create socket")
    sock:set_blocking(false)

    local events, count = socket.poll(sock, {"out"}, 100)
    ok(events ~= nil, "poll should return events")
    ok(events["out"] == true, "POLLOUT should be set on writable socket")

    sock:close()
end)

test('Multiple poll flags work correctly', function()
    local sock = socket.create("inet", "dgram", "udp")
    ok(sock ~= nil, "should create socket")
    sock:set_blocking(false)

    local events, count = socket.poll(sock, {"in", "out"}, 100)
    ok(events ~= nil, "poll should return events")
    ok(events["out"] == true, "POLLOUT should be set")
    ok(count >= 1, "should have at least 1 event")

    sock:close()
end)

test('POLLERR detection', function()
    local sock = socket.create("inet", "stream", "tcp")
    ok(sock ~= nil, "should create socket")
    sock:set_blocking(false)

    local connect_addr = socket.find_first_address_info("127.0.0.1", 1)
    ok(connect_addr ~= nil, "should find connect address")
    sock:connect(connect_addr)

    local events, count = socket.poll(sock, {"out", "err"}, 1000)
    ok(events ~= nil, "poll should return events")
    ok(events["out"] or events["err"], "should have POLLOUT or POLLERR")

    sock:close()
end)

test('TCP non-blocking connect detection with POLLOUT', function()
    local server = socket.create("inet", "stream", "tcp")
    ok(server ~= nil, "should create server socket")
    local bind_addr = socket.find_first_address_info("127.0.0.1", 0)
    ok(bind_addr ~= nil, "should find bind address")
    server:bind(bind_addr)
    server:listen(1)

    local ip, port = server:get_name()
    ok(port ~= nil, "should get server port")

    local client = socket.create("inet", "stream", "tcp")
    ok(client ~= nil, "should create client socket")
    client:set_blocking(false)

    local connect_addr = socket.find_first_address_info("127.0.0.1", port)
    ok(connect_addr ~= nil, "should find connect address")
    client:connect(connect_addr)

    local events, count = socket.poll(client, {"out"}, 2000)
    ok(events ~= nil, "poll should return events")
    ok(events["out"] == true, "POLLOUT should be set after connect")

    local errno = client:get_option("error", "socket")
    ok(errno == 0, "connection should succeed")

    client:close()
    server:close()
end)

test('POLLHUP detection on peer disconnect', function()
    local server = socket.create("inet", "stream", "tcp")
    ok(server ~= nil, "should create server socket")
    local bind_addr = socket.find_first_address_info("127.0.0.1", 0)
    ok(bind_addr ~= nil, "should find bind address")
    server:bind(bind_addr)
    server:listen(1)
    server:set_blocking(false)

    local ip, port = server:get_name()
    ok(port ~= nil, "should get server port")

    local client = socket.create("inet", "stream", "tcp")
    ok(client ~= nil, "should create client socket")
    local connect_addr = socket.find_first_address_info("127.0.0.1", port)
    ok(connect_addr ~= nil, "should find connect address")
    client:connect(connect_addr)

    sleep(50)
    local conn, err = server:accept()
    ok(conn ~= nil, "should accept connection")
    conn:set_blocking(false)

    client:close()
    sleep(100)

    local events, count = socket.poll(conn, {"in", "hup"}, 500)
    ok(events ~= nil, "poll should return events")
    ok(events["in"] or events["hup"], "should have POLLIN or POLLHUP after close")

    conn:close()
    server:close()
end)

test('poll() with empty flags returns zero events', function()
    local sock = socket.create("inet", "dgram", "udp")
    ok(sock ~= nil, "should create socket")
    sock:set_blocking(false)

    local events, count = socket.poll(sock, {}, 100)
    ok(count == 0, "should have no events with empty flags")

    sock:close()
end)

test('Rapid polling with timeout=0 does not block', function()
    local sock = socket.create("inet", "dgram", "udp")
    ok(sock ~= nil, "should create socket")
    sock:set_blocking(false)

    local start = get_time_ms()
    for i = 1, 100 do
        socket.poll(sock, {"in"}, 0)
    end
    local elapsed = get_time_ms() - start

    ok(elapsed < 500, "100 rapid polls should complete quickly")

    sock:close()
end)

test('poll() on closed socket returns error', function()
    local sock = socket.create("inet", "dgram", "udp")
    ok(sock ~= nil, "should create socket")
    sock:close()

    local events, err = socket.poll(sock, {"in"}, 100)
    ok(events == nil or (events and events["nval"]), "poll on closed socket should error or return POLLNVAL")
end)

test('Full UDP send/receive cycle with poll()', function()
    local server = socket.create("inet", "dgram", "udp")
    ok(server ~= nil, "should create server socket")
    local bind_addr = socket.find_first_address_info("127.0.0.1", 0)
    ok(bind_addr ~= nil, "should find bind address")
    server:bind(bind_addr)
    server:set_blocking(false)

    local ip, port = server:get_name()
    ok(port ~= nil, "should get server port")

    local client = socket.create("inet", "dgram", "udp")
    ok(client ~= nil, "should create client socket")
    client:set_blocking(false)
    local send_addr = socket.find_first_address_info("127.0.0.1", port)
    ok(send_addr ~= nil, "should find send address")

    local events = socket.poll(client, {"out"}, 100)
    ok(events and events["out"], "client should be writable")
    client:send_to(send_addr, "ping")

    sleep(50)

    events = socket.poll(server, {"in"}, 500)
    ok(events and events["in"], "server should have data")

    local data, addr = server:receive_from()
    ok(data == "ping", "server should receive ping")

    events = socket.poll(server, {"out"}, 100)
    ok(events and events["out"], "server should be writable")
    server:send_to(addr, "pong")

    sleep(50)

    events = socket.poll(client, {"in"}, 500)
    ok(events and events["in"], "client should have data")

    data, addr = client:receive_from()
    ok(data == "pong", "client should receive pong")

    server:close()
    client:close()
end)

test('POLLIN on listening socket indicates accept readiness', function()
    local server = socket.create("inet", "stream", "tcp")
    ok(server ~= nil, "should create server socket")
    local bind_addr = socket.find_first_address_info("127.0.0.1", 0)
    ok(bind_addr ~= nil, "should find bind address")
    server:bind(bind_addr)
    server:listen(1)
    server:set_blocking(false)

    local ip, port = server:get_name()
    ok(port ~= nil, "should get server port")

    local client = socket.create("inet", "stream", "tcp")
    ok(client ~= nil, "should create client socket")
    local connect_addr = socket.find_first_address_info("127.0.0.1", port)
    ok(connect_addr ~= nil, "should find connect address")
    client:connect(connect_addr)

    sleep(50)

    local events = socket.poll(server, {"in"}, 500)
    ok(events and events["in"], "POLLIN should be set when connection pending")

    local conn = server:accept()
    ok(conn ~= nil, "accept should succeed when POLLIN set")

    conn:close()
    client:close()
    server:close()
end)

test('poll() with -1 timeout waits indefinitely', function()
    local sock = socket.create("inet", "dgram", "udp")
    ok(sock ~= nil, "should create socket")
    sock:set_blocking(false)

    local sender = socket.create("inet", "dgram", "udp")
    ok(sender ~= nil, "should create sender socket")
    local bind_addr = socket.find_first_address_info("127.0.0.1", 0)
    ok(bind_addr ~= nil, "should find bind address")
    sock:bind(bind_addr)

    local ip, port = sock:get_name()
    ok(port ~= nil, "should get socket port")
    local send_addr = socket.find_first_address_info("127.0.0.1", port)
    ok(send_addr ~= nil, "should find send address")

    sender:send_to(send_addr, "wake up")
    sleep(50)

    local start = get_time_ms()
    local events = socket.poll(sock, {"in"}, -1)
    local elapsed = get_time_ms() - start

    ok(events and events["in"], "poll(-1) should detect data")
    ok(elapsed < 5000, "poll(-1) should return when data available")

    sender:close()
    sock:close()
end)

test('Large UDP datagram handling with poll()', function()
    local server = socket.create("inet", "dgram", "udp")
    ok(server ~= nil, "should create server socket")
    local bind_addr = socket.find_first_address_info("127.0.0.1", 0)
    ok(bind_addr ~= nil, "should find bind address")
    server:bind(bind_addr)
    server:set_blocking(false)

    local ip, port = server:get_name()
    ok(port ~= nil, "should get server port")

    local client = socket.create("inet", "dgram", "udp")
    ok(client ~= nil, "should create client socket")
    local send_addr = socket.find_first_address_info("127.0.0.1", port)
    ok(send_addr ~= nil, "should find send address")

    local large_data = string.rep("X", 1024)

    client:send_to(send_addr, large_data)
    sleep(50)

    local events = socket.poll(server, {"in"}, 500)
    ok(events and events["in"], "server should receive large datagram")

    local data = server:receive_from()
    ok(#data == 1024, "should receive full 1024 bytes")
    ok(data == large_data, "data should not be corrupted")

    server:close()
    client:close()
end)
