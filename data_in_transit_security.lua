#!/usr/bin/env luajit

local socket = require("socket")
local ssl = require("ssl")

local HOST = arg[1]
local FILENAME = "AUDITREPORT.md"

if not HOST then
    print("Usage: ./full-privacy-val.lua <domain>")
    os.exit()
end

-- Clear/Initialize the Markdown file
local f = io.open(FILENAME, "w")
if f then
    f:write("# Security Audit Report: " .. HOST .. "\n")
    f:write("> Generated on: " .. os.date() .. "\n\n")
    f:write("| Category | Status | Details |\n")
    f:write("| :--- | :---: | :--- |\n")
    f:close()
end

-- Formatting Helpers
local function log_event(category, status, message)
    -- Console Output
    local color = status and "\27[32m[+]\27[0m" or "\27[31m[!]\27[0m"
    print(string.format("%-22s %s %s", category, color, message))
    
    -- Markdown Output
    local file = io.open(FILENAME, "a")
    if file then
        local status_icon = status and "✅" or "❌"
        -- Escape pipe characters in message to avoid breaking the MD table
        local clean_msg = message:gsub("|", "\\|")
        file:write(string.format("| **%s** | %s | %s |\n", category, status_icon, clean_msg))
        file:close()
    end
end

-- ========= 1. TLS Handshake & Downgrade Check =========
local function audit_tls()
    local tcp = socket.tcp()
    tcp:settimeout(5)
    
    if not tcp:connect(HOST, 443) then
        log_event("Connectivity", false, "Port 443 unreachable")
        return
    end

    local params = { mode = "client", protocol = "tlsv1_2", verify = "none", options = "all" }
    local tls = ssl.wrap(tcp, params)
    
    if tls and tls:dohandshake() then
        local cipher = "Unknown"
        if tls.getcipherinfo then 
            local info = tls:getcipherinfo()
            cipher = info.name or "Unknown"
        end
        
        log_event("TLS_Protocol", true, "Established via " .. cipher)
        
        local has_pfs = (cipher:match("ECDHE") or cipher:match("DHE")) ~= nil
        log_event("Forward_Secrecy", has_pfs, has_pfs and "PFS supported" or "RSA Key Exchange (No PFS)")        
        
        tls:close()
    else
        log_event("TLS_Protocol", false, "Handshake failed")
    end
end

-- ========= 2 SCSV Downgrade Check =========
local function scsv_downgrade_audit()
    local tcp2 = socket.tcp()
    tcp2:settimeout(3)
    tcp2:connect(HOST, 443)
    local tls2 = ssl.wrap(tcp2, {mode="client", protocol="tlsv1", verify="none"})
    local hs_ok = tls2 and tls2:dohandshake()
        
    log_event("Downgrade_Attack", not hs_ok, not hs_ok and "Server blocks legacy TLS 1.0" or "Vulnerable: Server accepts TLS 1.0")
        
    if tls2 then tls2:close() end
end

-- ========= 3 HSTS & Privacy Headers =========
local function hsts_check()
    local tcp = socket.tcp()
    tcp:settimeout(5)
    if not tcp:connect(HOST, 80) then return end
    
    tcp:send("GET / HTTP/1.1\r\nHost: " .. HOST .. "\r\nConnection: close\r\n\r\n")
    local resp = tcp:receive("*a") or ""
    tcp:close()

    local hsts = resp:match("Strict%-Transport%-Security") ~= nil
    local has_preload = resp:match("Strict%-Transport%-Security.-preload") ~= nil
    local secure_redirect = resp:match("Location: https://") ~= nil

    if hsts then
        local msg = has_preload and "HSTS Enforced (Preload Requested)" or "HSTS Enforced"
        log_event("HSTS_Privacy", true, msg)
    elseif secure_redirect then
        log_event("HSTS_Privacy", true, "Secure Redirect to HTTPS")
    else
        log_event("HSTS_Privacy", false, "HSTS missing (Insecure)")
    end
end

-- ========= 4 DNS Infrastructure Checks =========
local function check_dns_security()
    local caa_handle = io.popen("dig +short CAA " .. HOST)
    local caa = caa_handle:read("*a"):gsub("\n", " ")
    caa_handle:close()
    log_event("CAA_Policy", (caa ~= ""), (caa ~= "") and "Authorized CAs: " .. caa or "No CAA (Any CA can issue)")
end

-- ======== 5 MTA-STS: Email Transport Privacy Check
local function check_mta_sts()
    local mta_handle = io.popen("dig +short TXT _mta-sts." .. HOST)
    local mta = mta_handle:read("*a")
    mta_handle:close()
    log_event("MTA-STS_Email", (mta:match("v=STSv1") ~= nil), (mta:match("v=STSv1") and "Email encryption enforced" or "No email privacy policy"))
end

-- Execution
print("\n\27[1mDeep Security Audit:\27[0m " .. HOST)
print(string.rep("-", 60))
audit_tls()
scsv_downgrade_audit()
hsts_check()
check_dns_security()
check_mta_sts()
print("\nReport saved to " .. FILENAME)
