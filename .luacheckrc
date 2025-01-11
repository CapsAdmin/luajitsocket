-- Only allow symbols available in all Lua versions
std = "min"

-- Get rid of "unused argument self"-warnings
self = false

-- Include standard globals
globals = {
    "bit",
    "unpack",
    "jit"
}

-- Ignure unused arguments
unused_args = false

-- Ignore too long lines
max_line_length = false
