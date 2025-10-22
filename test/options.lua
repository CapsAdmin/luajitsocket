local socket = require("ljsocket")
local ffi = require("ffi")

-- Create a socket for testing
local sock = socket.create("inet", "stream", "tcp")
assert(sock, "Failed to create socket")

-- Platform-specific expected values
-- On macOS, boolean options return their SO_* constant value when enabled
local function get_expected_enabled_value(option_name)
	if ffi.os == "OSX" then
		return socket.e["SO_" .. option_name:upper()]
	else
		return 1  -- Most other platforms return 1
	end
end

do -- SO_REUSEADDR set and get
	local ok, err = sock:set_option("reuseaddr", 1)
	assert(ok, "Failed to set reuseaddr: " .. tostring(err))
	
	local value, err = sock:get_option("reuseaddr")
	assert(value, "Failed to get reuseaddr: " .. tostring(err))
	
	local expected = get_expected_enabled_value("reuseaddr")
	print("  Set: 1, Got: " .. tostring(value) .. ", Expected: " .. expected)
	assert(value == expected, "SO_REUSEADDR mismatch")
end

do -- SO_REUSEADDR toggle off
	local ok, err = sock:set_option("reuseaddr", 0)
	assert(ok, "Failed to set reuseaddr to 0: " .. tostring(err))
	
	local value, err = sock:get_option("reuseaddr")
	assert(value, "Failed to get reuseaddr: " .. tostring(err))
	print("  Set: 0, Got: " .. tostring(value))
	assert(value == 0, "SO_REUSEADDR should be 0 when disabled")
	
	-- Set it back to 1
	sock:set_option("reuseaddr", 1)
end

do -- SO_KEEPALIVE
	local ok, err = sock:set_option("keepalive", 1)
	assert(ok, "Failed to set keepalive: " .. tostring(err))
	
	local value, err = sock:get_option("keepalive")
	assert(value, "Failed to get keepalive: " .. tostring(err))
	
	local expected = get_expected_enabled_value("keepalive")
	print("  Set: 1, Got: " .. tostring(value) .. ", Expected: " .. expected)
	assert(value == expected, "SO_KEEPALIVE mismatch")
end

do -- SO_SNDBUF
	-- First get the default value
	local default_value, err = sock:get_option("sndbuf")
	assert(default_value, "Failed to get default sndbuf: " .. tostring(err))
	print("  Default sndbuf: " .. tostring(default_value))
	
	-- Try to set a new value
	local new_size = 65536
	local ok, err = sock:set_option("sndbuf", new_size)
	assert(ok, "Failed to set sndbuf: " .. tostring(err))
	
	-- Get it back
	local value, err = sock:get_option("sndbuf")
	assert(value, "Failed to get sndbuf after set: " .. tostring(err))
	print("  Set: " .. new_size .. ", Got: " .. tostring(value))
	-- Note: OS may adjust the value (often doubles it), so we just check it's not nil and > 0
	assert(value > 0, "SO_SNDBUF should be greater than 0")
	assert(value >= new_size or value >= new_size/2, "SO_SNDBUF should be at least half the requested size")
end

do -- SO_RCVBUF
	-- First get the default value
	local default_value, err = sock:get_option("rcvbuf")
	assert(default_value, "Failed to get default rcvbuf: " .. tostring(err))
	print("  Default rcvbuf: " .. tostring(default_value))
	
	-- Try to set a new value
	local new_size = 65536
	local ok, err = sock:set_option("rcvbuf", new_size)
	assert(ok, "Failed to set rcvbuf: " .. tostring(err))
	
	-- Get it back
	local value, err = sock:get_option("rcvbuf")
	assert(value, "Failed to get rcvbuf after set: " .. tostring(err))
	print("  Set: " .. new_size .. ", Got: " .. tostring(value))
	assert(value > 0, "SO_RCVBUF should be greater than 0")
	assert(value >= new_size or value >= new_size/2, "SO_RCVBUF should be at least half the requested size")
end

do -- SO_BROADCAST
	local ok, err = sock:set_option("broadcast", 1)
	assert(ok, "Failed to set broadcast: " .. tostring(err))
	
	local value, err = sock:get_option("broadcast")
	assert(value, "Failed to get broadcast: " .. tostring(err))
	
	local expected = get_expected_enabled_value("broadcast")
	print("  Set: 1, Got: " .. tostring(value) .. ", Expected: " .. expected)
	assert(value == expected, "SO_BROADCAST mismatch")
end

do -- SO_TYPE (read-only)
	local value, err = sock:get_option("type")
	assert(value, "Failed to get socket type: " .. tostring(err))
	assert(value == socket.e.SOCK_STREAM, "SO_TYPE should be SOCK_STREAM")
end

do -- SO_ERROR (read-only)
	local value, err = sock:get_option("error")
	assert(value, "Failed to get socket error: " .. tostring(err))
	assert(value == 0, "SO_ERROR should be 0 for a healthy socket")
end

for i = 1, 5 do -- Multiple toggles of boolean option
	-- Toggle on
	sock:set_option("reuseaddr", 1)
	local val_on = sock:get_option("reuseaddr")
	assert(val_on == get_expected_enabled_value("reuseaddr"), 
		"Iteration " .. i .. ": ON value mismatch")
	
	-- Toggle off
	sock:set_option("reuseaddr", 0)
	local val_off = sock:get_option("reuseaddr")
	assert(val_off == 0, "Iteration " .. i .. ": OFF value should be 0")
end

-- Clean up
sock:close()
