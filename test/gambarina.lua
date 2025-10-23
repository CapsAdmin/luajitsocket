-- Compatibility for Lua 5.1
local unpack = unpack or table.unpack -- luacheck: ignore 143/table

local gambiarra = {
    _VERSION = 'gambiarra 0.4.1-0',
    _DESCRIPTION = 'A tiny lua unit-testing library.',
    _URL = 'https://codeberg.org/imo/gambiarra',
    _LICENSE = 'MIT',
    passed = 0,
    failed = 0,
    report = function(self)
        if self.failed == 0 then
            print('All ' .. self.passed .. ' tests passed.')
        else
            local total = self.passed + self.failed
            print(self.failed .. ' tests failed out of ' .. total)
        end
    end
}

local function default_handler(e, test, msg)
    if e == 'pass' then
        gambiarra.passed = gambiarra.passed + 1
        print(('[32mPASS[0m %s: %s'):format(test, msg))
    elseif e == 'fail' then
        gambiarra.failed = gambiarra.failed + 1
        print(('[31mFAIL[0m %s: %s'):format(test, msg))
    elseif e == 'except' then
        gambiarra.failed = gambiarra.failed + 1
        print(('[31mECPT[0m %s: %s'):format(test, msg))
    end
end

local function deepeq(a, b)
    -- Different types: false
    if type(a) ~= type(b) then return false end
    -- Functions
    if type(a) == 'function' then
        return string.dump(a) == string.dump(b)
    end
    -- Primitives and equal pointers
    if a == b then return true end
    -- Only equal tables could have passed previous tests
    if type(a) ~= 'table' then return false end
    -- Compare tables size
    if #a ~= #b then return false end
    -- Compare tables field by field
    for k, v in pairs(a) do
        if b[k] == nil or not deepeq(v, b[k]) then return false end
    end
    return true
end

-- Compatibility for Lua 5.1 and Lua 5.2
local function args(...)
    return { n = select('#', ...), ... }
end

local function spy(f)
    local s = {}
    s.called = {}
    setmetatable(s, { __call = function(_s, ...)
        local a = args(...)
        table.insert(_s.called, { ... })
        if f then
            local r = args(pcall(f, unpack(a, 1, a.n)))
            if not r[1] then
                _s.errors = _s.errors or {}
                _s.errors[#_s.called] = r[2]
            else
                return unpack(r, 2, r.n)
            end
        end
    end })
    return s
end

local pendingtests = {}
local env = _G
local handler = default_handler

local function runpending()
    if pendingtests[1] ~= nil then pendingtests[1](runpending) end
end

local function test_function(name, f, async)
    if type(name) == 'function' then
        handler = name
        env = f or _G
        return
    end

    local function testfn(next)
        local prev = {
            ok = env.ok,
            spy = env.spy,
            eq = env.eq,
        }
        local exp, act

        local function restore()
            env.ok = prev.ok
            env.spy = prev.spy
            env.eq = prev.eq
            handler('end', name)
            table.remove(pendingtests, 1)
            if next then next() end
        end

        function env.ok(cond, msg)
            if not msg then
                local d = debug.getinfo(2, 'Sl')
                msg = d.short_src .. ':' .. d.currentline
            end
            if cond then
                handler('pass', name, msg)
            else
                handler('fail', name,
                    ('%s: Expected %q, but got %q.'):format(msg, tostring(exp), tostring(act)))
            end
            act, exp = nil, nil
        end

        function env.eq(a, b)
            act, exp = a, b
            return deepeq(exp, act)
        end

        env.spy = spy

        handler('begin', name)
        local ok, err = pcall(f, restore)
        if not ok then
            handler('except', name, err)
        end

        if not async then
            handler('end', name)
            env.ok = prev.ok
            env.spy = prev.spy
            env.eq = prev.eq
        end
    end

    if not async then
        testfn()
    else
        table.insert(pendingtests, testfn)
        if #pendingtests == 1 then
            runpending()
        end
    end
end

setmetatable(gambiarra,
    { __call = function(_, name, f, async)
        return test_function(name, f, async)
    end })
return gambiarra
