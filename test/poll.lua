#!/usr/bin/env luajit
--[[
Comprehensive poll() test suite for ljsocket
Tests expected behavior across different scenarios and platforms
]]

local socket = require("ljsocket")

-- Test results tracking
local tests_passed = 0
local tests_failed = 0
local test_output = {}

-- Helper: colored output
local function colored(color, text)
    local colors = {
        red = "\27[31m",
        green = "\27[32m",
        yellow = "\27[33m",
        blue = "\27[34m",
        reset = "\27[0m"
    }
    return (colors[color] or "") .. text .. colors.reset
end

-- Helper: assert with custom message
local function test_assert(condition, message)
    if not condition then
        error(message or "Assertion failed", 2)
    end
end

-- Helper: run a test
local function run_test(name, func)
    io.write(string.format("%-60s", name .. " ... "))
    io.flush()
    
    local success, err = pcall(func)
    
    if success then
        tests_passed = tests_passed + 1
        print(colored("green", "✓ PASS"))
    else
        tests_failed = tests_failed + 1
        print(colored("red", "✗ FAIL"))
        print(colored("red", "  Error: " .. tostring(err)))
        table.insert(test_output, {name = name, error = err})
    end
end

-- Helper: get wall time in milliseconds using FFI
local ffi = require("ffi")
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

print("\n" .. colored("blue", "=== ljsocket poll() Test Suite ==="))
print("Platform: " .. (jit and jit.os or "unknown"))
print("")

-- ====================
-- TEST 1: Basic poll() with timeout
-- ====================
run_test("Test 1: poll() returns immediately with timeout=0", function()
    local sock = assert(socket.create("inet", "dgram", "udp"))
    sock:set_blocking(false)
    
    local start = get_time_ms()
    local events, count = socket.poll(sock, {"in"}, 0)
    local elapsed = get_time_ms() - start
    
    test_assert(elapsed < 50, "poll(timeout=0) took too long: " .. elapsed .. "ms")
    test_assert(count ~= nil, "poll should return count even on timeout")
    
    sock:close()
end)

-- ====================
-- TEST 2: poll() timeout works correctly
-- ====================
run_test("Test 2: poll() respects timeout duration", function()
    local sock = assert(socket.create("inet", "dgram", "udp"))
    sock:set_blocking(false)
    
    local timeout = 100
    local start = get_time_ms()
    local events, count = socket.poll(sock, {"in"}, timeout)
    local elapsed = get_time_ms() - start
    
    -- Should timeout around 100ms (allow 50ms margin)
    test_assert(elapsed >= timeout - 10, "poll returned too early: " .. elapsed .. "ms")
    test_assert(elapsed < timeout + 100, "poll took too long: " .. elapsed .. "ms")
    test_assert(count == 0, "Expected 0 events, got " .. tostring(count))
    
    sock:close()
end)

-- ====================
-- TEST 3: POLLIN flag on UDP socket with data available
-- ====================
run_test("Test 3: POLLIN flag set when data available (UDP)", function()
    -- Create server socket
    local server = assert(socket.create("inet", "dgram", "udp"))
    local bind_addr = assert(socket.find_first_address_info("127.0.0.1", 0)) -- auto port
    assert(server:bind(bind_addr))
    server:set_blocking(false)
    
    -- Get actual bound port
    local ip, port = assert(server:get_name())
    
    -- Create client socket
    local client = assert(socket.create("inet", "dgram", "udp"))
    local send_addr = assert(socket.find_first_address_info("127.0.0.1", port))
    
    -- Send data
    assert(client:send_to(send_addr, "test data"))
    
    -- Give time for packet to arrive
    sleep(50)
    
    -- Poll should show POLLIN
    local events, count = socket.poll(server, {"in"}, 100)
    test_assert(events ~= nil, "poll returned nil")
    test_assert(events["in"] == true, "POLLIN not set when data available")
    test_assert(count == 1, "Expected count=1, got " .. tostring(count))
    
    -- Verify we can actually read
    local data, addr = server:receive_from()
    test_assert(data == "test data", "Received wrong data: " .. tostring(data))
    
    server:close()
    client:close()
end)

-- ====================
-- TEST 4: POLLOUT flag (socket writable)
-- ====================
run_test("Test 4: POLLOUT flag set when socket writable", function()
    local sock = assert(socket.create("inet", "dgram", "udp"))
    sock:set_blocking(false)
    
    -- UDP socket should always be writable initially
    local events, count = socket.poll(sock, {"out"}, 100)
    test_assert(events ~= nil, "poll returned nil")
    test_assert(events["out"] == true, "POLLOUT not set on writable UDP socket")
    
    sock:close()
end)

-- ====================
-- TEST 5: Multiple flags (POLLIN | POLLOUT)
-- ====================
run_test("Test 5: Multiple poll flags work correctly", function()
    local sock = assert(socket.create("inet", "dgram", "udp"))
    sock:set_blocking(false)
    
    -- Poll for both IN and OUT
    local events, count = socket.poll(sock, {"in", "out"}, 100)
    test_assert(events ~= nil, "poll returned nil")
    test_assert(events["out"] == true, "POLLOUT should be set")
    -- POLLIN may or may not be set depending on platform behavior
    -- The important thing is that we can request multiple flags
    test_assert(count >= 1, "Expected at least 1 event")
    
    sock:close()
end)

-- ====================
-- TEST 6: POLLERR flag on invalid socket operation
-- ====================
run_test("Test 6: POLLERR detection", function()
    local sock = assert(socket.create("inet", "stream", "tcp"))
    sock:set_blocking(false)
    
    -- Try to connect to invalid address
    local connect_addr = assert(socket.find_first_address_info("127.0.0.1", 1)) -- port 1, likely closed
    sock:connect(connect_addr) -- Will return error or EINPROGRESS
    
    -- Poll should eventually show error or success
    local events, count = socket.poll(sock, {"out", "err"}, 1000)
    test_assert(events ~= nil, "poll returned nil")
    -- Either connection succeeds (out) or fails (err), both are valid
    test_assert(events["out"] or events["err"], "Neither POLLOUT nor POLLERR set")
    
    sock:close()
end)

-- ====================
-- TEST 7: TCP socket POLLOUT on non-blocking connect
-- ====================
run_test("Test 7: TCP non-blocking connect detection with POLLOUT", function()
    -- Create listening socket
    local server = assert(socket.create("inet", "stream", "tcp"))
    local bind_addr = assert(socket.find_first_address_info("127.0.0.1", 0))
    assert(server:bind(bind_addr))
    assert(server:listen(1))
    
    local ip, port = assert(server:get_name())
    
    -- Create non-blocking client
    local client = assert(socket.create("inet", "stream", "tcp"))
    client:set_blocking(false)
    
    local connect_addr = assert(socket.find_first_address_info("127.0.0.1", port))
    local ok, err = client:connect(connect_addr)
    -- Non-blocking connect returns error (EINPROGRESS expected)
    
    -- Poll for POLLOUT indicates connection complete
    local events, count = socket.poll(client, {"out"}, 2000)
    test_assert(events ~= nil, "poll returned nil")
    test_assert(events["out"] == true, "POLLOUT not set after connect")
    
    -- Verify connection succeeded by checking SO_ERROR
    local errno = client:get_option("error", "socket")
    test_assert(errno == 0, "Connection failed with errno: " .. tostring(errno))
    
    client:close()
    server:close()
end)

-- ====================
-- TEST 8: POLLHUP on connection close
-- ====================
run_test("Test 8: POLLHUP detection on peer disconnect", function()
    -- Create server
    local server = assert(socket.create("inet", "stream", "tcp"))
    local bind_addr = assert(socket.find_first_address_info("127.0.0.1", 0))
    assert(server:bind(bind_addr))
    assert(server:listen(1))
    server:set_blocking(false)
    
    local ip, port = assert(server:get_name())
    
    -- Create client and connect
    local client = assert(socket.create("inet", "stream", "tcp"))
    local connect_addr = assert(socket.find_first_address_info("127.0.0.1", port))
    assert(client:connect(connect_addr))
    
    -- Accept connection
    sleep(50)
    local conn, err = server:accept()
    test_assert(conn ~= nil, "Failed to accept: " .. tostring(err))
    conn:set_blocking(false)
    
    -- Client closes
    client:close()
    
    -- Give time for FIN to arrive
    sleep(100)
    
    -- Poll should show HUP or IN (for EOF)
    local events, count = socket.poll(conn, {"in", "hup"}, 500)
    test_assert(events ~= nil, "poll returned nil")
    test_assert(events["in"] or events["hup"], "Neither POLLIN nor POLLHUP set after close")
    
    conn:close()
    server:close()
end)

-- ====================
-- TEST 9: No events when polling with no flags
-- ====================
run_test("Test 9: poll() with empty flags returns zero events", function()
    local sock = assert(socket.create("inet", "dgram", "udp"))
    sock:set_blocking(false)
    
    -- Poll with no flags (or empty table)
    local events, count = socket.poll(sock, {}, 100)
    test_assert(count == 0, "Expected 0 events with no flags, got " .. tostring(count))
    
    sock:close()
end)

-- ====================
-- TEST 10: Rapid polling doesn't block
-- ====================
run_test("Test 10: Rapid polling with timeout=0 doesn't block", function()
    local sock = assert(socket.create("inet", "dgram", "udp"))
    sock:set_blocking(false)
    
    local start = get_time_ms()
    for i = 1, 100 do
        socket.poll(sock, {"in"}, 0)
    end
    local elapsed = get_time_ms() - start
    
    test_assert(elapsed < 500, "100 polls took too long: " .. elapsed .. "ms")
    
    sock:close()
end)

-- ====================
-- TEST 11: poll() on closed socket returns error
-- ====================
run_test("Test 11: poll() on closed socket returns error", function()
    local sock = assert(socket.create("inet", "dgram", "udp"))
    sock:close()
    
    local events, err = socket.poll(sock, {"in"}, 100)
    -- On closed socket, either returns error OR returns with POLLNVAL flag
    test_assert(events == nil or (events and events["nval"]), 
        "poll on closed socket should return error or POLLNVAL")
end)

-- ====================
-- TEST 12: UDP send/receive with poll() coordination
-- ====================
run_test("Test 12: Full UDP send/receive cycle with poll()", function()
    -- Server setup
    local server = assert(socket.create("inet", "dgram", "udp"))
    local bind_addr = assert(socket.find_first_address_info("127.0.0.1", 0))
    assert(server:bind(bind_addr))
    server:set_blocking(false)
    
    local ip, port = assert(server:get_name())
    
    -- Client setup
    local client = assert(socket.create("inet", "dgram", "udp"))
    client:set_blocking(false)
    local send_addr = assert(socket.find_first_address_info("127.0.0.1", port))
    
    -- Client sends
    local events = socket.poll(client, {"out"}, 100)
    test_assert(events and events["out"], "Client not writable")
    assert(client:send_to(send_addr, "ping"))
    
    -- Give packet time to arrive
    sleep(50)
    
    -- Server receives
    events = socket.poll(server, {"in"}, 500)
    test_assert(events and events["in"], "Server has no data after send")
    
    local data, addr = server:receive_from()
    test_assert(data == "ping", "Server got wrong data: " .. tostring(data))
    
    -- Server sends reply
    events = socket.poll(server, {"out"}, 100)
    test_assert(events and events["out"], "Server not writable")
    assert(server:send_to(addr, "pong"))
    
    -- Give packet time to arrive
    sleep(50)
    
    -- Client receives reply
    events = socket.poll(client, {"in"}, 500)
    test_assert(events and events["in"], "Client has no data after reply")
    
    data, addr = client:receive_from()
    test_assert(data == "pong", "Client got wrong data: " .. tostring(data))
    
    server:close()
    client:close()
end)

-- ====================
-- TEST 13: TCP accept readiness with poll()
-- ====================
run_test("Test 13: POLLIN on listening socket indicates accept readiness", function()
    local server = assert(socket.create("inet", "stream", "tcp"))
    local bind_addr = assert(socket.find_first_address_info("127.0.0.1", 0))
    assert(server:bind(bind_addr))
    assert(server:listen(1))
    server:set_blocking(false)
    
    local ip, port = assert(server:get_name())
    
    -- Client connects
    local client = assert(socket.create("inet", "stream", "tcp"))
    local connect_addr = assert(socket.find_first_address_info("127.0.0.1", port))
    assert(client:connect(connect_addr))
    
    sleep(50)
    
    -- Now POLLIN should be set
    local events = socket.poll(server, {"in"}, 500)
    test_assert(events and events["in"], "POLLIN not set when connection pending")
    
    -- Accept should succeed
    local conn = server:accept()
    test_assert(conn ~= nil, "accept() failed when POLLIN was set")
    
    conn:close()
    client:close()
    server:close()
end)

-- ====================
-- TEST 14: poll() with negative timeout (wait forever) can be interrupted
-- ====================
run_test("Test 14: poll() with -1 timeout waits indefinitely", function()
    -- This test just verifies the call doesn't crash with -1
    -- We won't actually wait forever
    local sock = assert(socket.create("inet", "dgram", "udp"))
    sock:set_blocking(false)
    
    -- Create a separate socket that will send data
    local sender = assert(socket.create("inet", "dgram", "udp"))
    local bind_addr = assert(socket.find_first_address_info("127.0.0.1", 0))
    assert(sock:bind(bind_addr))
    
    local ip, port = assert(sock:get_name())
    local send_addr = assert(socket.find_first_address_info("127.0.0.1", port))
    
    -- Send data immediately so poll returns
    assert(sender:send_to(send_addr, "wake up"))
    sleep(50)
    
    -- Poll with -1 should return when data arrives (not hang forever)
    local start = get_time_ms()
    local events = socket.poll(sock, {"in"}, -1)
    local elapsed = get_time_ms() - start
    
    test_assert(events and events["in"], "poll(-1) didn't detect data")
    test_assert(elapsed < 5000, "poll(-1) took too long: " .. elapsed .. "ms")
    
    sender:close()
    sock:close()
end)

-- ====================
-- TEST 15: Large data transfer with poll() coordination
-- ====================
run_test("Test 15: Large UDP datagram handling with poll()", function()
    local server = assert(socket.create("inet", "dgram", "udp"))
    local bind_addr = assert(socket.find_first_address_info("127.0.0.1", 0))
    assert(server:bind(bind_addr))
    server:set_blocking(false)
    
    local ip, port = assert(server:get_name())
    
    local client = assert(socket.create("inet", "dgram", "udp"))
    local send_addr = assert(socket.find_first_address_info("127.0.0.1", port))
    
    -- Create large payload (but under typical UDP MTU)
    local large_data = string.rep("X", 1024)
    
    assert(client:send_to(send_addr, large_data))
    sleep(50)
    
    local events = socket.poll(server, {"in"}, 500)
    test_assert(events and events["in"], "Server didn't receive large datagram")
    
    local data = server:receive_from()
    test_assert(#data == 1024, "Received truncated data: " .. #data .. " bytes")
    test_assert(data == large_data, "Data corruption detected")
    
    server:close()
    client:close()
end)

-- ====================
-- Summary
-- ====================
print("\n" .. colored("blue", "=== Test Summary ==="))
print(colored("green", "Passed: " .. tests_passed))
if tests_failed > 0 then
    print(colored("red", "Failed: " .. tests_failed))
    print("\n" .. colored("red", "Failed tests:"))
    for _, result in ipairs(test_output) do
        print(colored("red", "  - " .. result.name))
        print(colored("red", "    " .. result.error))
    end
else
    print(colored("green", "All tests passed! ✓"))
end
print("")

os.exit(tests_failed == 0 and 0 or 1)
