require("luacov")
local lunit = require("lunit")
local socket = require("ljsocket")

module("dns_lookup_test", lunit.testcase, package.seeall)

function test_lookup_google()
    results = socket.get_address_info({host = "www.google.com"})
    lunit.assert_not_nil(results)
    lunit.assert_not_equal(0, #results)

    for i, info in ipairs(results) do
        lunit.assert_equal("www.google.com", info.host)
        lunit.assert_not_nil(info.family)
        lunit.assert_not_nil(info.protocol)
    end
end

lunit.main(...)
