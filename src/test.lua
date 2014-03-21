#!/bin/env lua
local ipacc = require("ipaccount")

ipacc.ip_acc_init()
ips = ipacc.get_account_table("lan")

for k1,v1 in pairs(ips) do
    for k,v in pairs(v1) do
        print(k,v)
    end
    print("\n")
end
