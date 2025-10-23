local socket = require("ljsocket")
local ffi = require("ffi")
local test = require("test.gambarina")

-- Platform-specific expected values
-- On macOS, boolean options return their SO_* constant value when enabled
local function get_expected_enabled_value(option_name)
	if ffi.os == "OSX" then
		return socket.e["SO_" .. option_name:upper()]
	else
		return 1  -- Most other platforms return 1
	end
end

test('Socket options - SO_REUSEADDR set and get', function()
	local sock = socket.create("inet", "stream", "tcp")
	ok(sock ~= nil, "should create socket")

	local set_ok, err = sock:set_option("reuseaddr", 1)
	ok(set_ok, "should set reuseaddr: " .. tostring(err))

	local value, err = sock:get_option("reuseaddr")
	ok(value ~= nil, "should get reuseaddr: " .. tostring(err))

	local expected = get_expected_enabled_value("reuseaddr")
	ok(value == expected, "SO_REUSEADDR should match expected value")

	sock:close()
end)

test('Socket options - SO_REUSEADDR toggle off', function()
	local sock = socket.create("inet", "stream", "tcp")
	ok(sock ~= nil, "should create socket")

	sock:set_option("reuseaddr", 1)

	local set_ok, err = sock:set_option("reuseaddr", 0)
	ok(set_ok, "should set reuseaddr to 0: " .. tostring(err))

	local value, err = sock:get_option("reuseaddr")
	ok(value ~= nil, "should get reuseaddr: " .. tostring(err))
	ok(value == 0, "SO_REUSEADDR should be 0 when disabled")

	sock:close()
end)

test('Socket options - SO_KEEPALIVE', function()
	local sock = socket.create("inet", "stream", "tcp")
	ok(sock ~= nil, "should create socket")

	local set_ok, err = sock:set_option("keepalive", 1)
	ok(set_ok, "should set keepalive: " .. tostring(err))

	local value, err = sock:get_option("keepalive")
	ok(value ~= nil, "should get keepalive: " .. tostring(err))

	local expected = get_expected_enabled_value("keepalive")
	ok(value == expected, "SO_KEEPALIVE should match expected value")

	sock:close()
end)

test('Socket options - SO_SNDBUF', function()
	local sock = socket.create("inet", "stream", "tcp")
	ok(sock ~= nil, "should create socket")

	local default_value, err = sock:get_option("sndbuf")
	ok(default_value ~= nil, "should get default sndbuf: " .. tostring(err))

	local new_size = 65536
	local set_ok, err = sock:set_option("sndbuf", new_size)
	ok(set_ok, "should set sndbuf: " .. tostring(err))

	local value, err = sock:get_option("sndbuf")
	ok(value ~= nil, "should get sndbuf after set: " .. tostring(err))
	ok(value > 0, "SO_SNDBUF should be greater than 0")
	ok(value >= new_size or value >= new_size/2, "SO_SNDBUF should be at least half the requested size")

	sock:close()
end)

test('Socket options - SO_RCVBUF', function()
	local sock = socket.create("inet", "stream", "tcp")
	ok(sock ~= nil, "should create socket")

	local default_value, err = sock:get_option("rcvbuf")
	ok(default_value ~= nil, "should get default rcvbuf: " .. tostring(err))

	local new_size = 65536
	local set_ok, err = sock:set_option("rcvbuf", new_size)
	ok(set_ok, "should set rcvbuf: " .. tostring(err))

	local value, err = sock:get_option("rcvbuf")
	ok(value ~= nil, "should get rcvbuf after set: " .. tostring(err))
	ok(value > 0, "SO_RCVBUF should be greater than 0")
	ok(value >= new_size or value >= new_size/2, "SO_RCVBUF should be at least half the requested size")

	sock:close()
end)

test('Socket options - SO_BROADCAST', function()
	local sock = socket.create("inet", "stream", "tcp")
	ok(sock ~= nil, "should create socket")

	local set_ok, err = sock:set_option("broadcast", 1)
	ok(set_ok, "should set broadcast: " .. tostring(err))

	local value, err = sock:get_option("broadcast")
	ok(value ~= nil, "should get broadcast: " .. tostring(err))

	local expected = get_expected_enabled_value("broadcast")
	ok(value == expected, "SO_BROADCAST should match expected value")

	sock:close()
end)

test('Socket options - SO_TYPE (read-only)', function()
	local sock = socket.create("inet", "stream", "tcp")
	ok(sock ~= nil, "should create socket")

	local value, err = sock:get_option("type")
	ok(value ~= nil, "should get socket type: " .. tostring(err))
	ok(value == socket.e.SOCK_STREAM, "SO_TYPE should be SOCK_STREAM")

	sock:close()
end)

test('Socket options - SO_ERROR (read-only)', function()
	local sock = socket.create("inet", "stream", "tcp")
	ok(sock ~= nil, "should create socket")

	local value, err = sock:get_option("error")
	ok(value ~= nil, "should get socket error: " .. tostring(err))
	ok(value == 0, "SO_ERROR should be 0 for a healthy socket")

	sock:close()
end)

test('Socket options - Multiple toggles of boolean option', function()
	local sock = socket.create("inet", "stream", "tcp")
	ok(sock ~= nil, "should create socket")

	for i = 1, 5 do
		-- Toggle on
		sock:set_option("reuseaddr", 1)
		local val_on = sock:get_option("reuseaddr")
		ok(val_on == get_expected_enabled_value("reuseaddr"),
			"Iteration " .. i .. ": ON value should match")

		-- Toggle off
		sock:set_option("reuseaddr", 0)
		local val_off = sock:get_option("reuseaddr")
		ok(val_off == 0, "Iteration " .. i .. ": OFF value should be 0")
	end

	sock:close()
end)
