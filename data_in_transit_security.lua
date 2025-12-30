#!/usr/bin/env luajit

local socket = require("socket")
local ssl = require("ssl")

local HOST = arg[1]
local CA_FILE = "/etc/ssl/certs/ca-certificates.crt"

if not HOST then
    print("Usage: ./full-privacy-val.lua <domain>")
    os.exit()
end

-- Formatting Helper
local function log_event(category, status, message)
    local color = status and "\27[32m[+]\27[0m" or "\27[31m[!]\27[0m"
    print(string.format("%-22s %s %s", category, color, message))
end

-- ========= 1. TLS Handshake & Downgrade Check =========
local function audit_tls()
    local tcp = socket.tcp()
    tcp:settimeout(5)
    
    if not tcp:connect(HOST, 443) then
        log_event("Connectivity", false, "Port 443 unreachable")
        return
    end

    -- Attempt a modern style TLS 1.2+ handshake
    local params = { mode = "client",
                    protocol = "tlsv1_2", 
                    verify = "none", 
                    options = "all" }

    local tls = ssl.wrap(tcp, params) -- Example: Put mail in Envolope with speciifc encryption seal.
    
    if tls and tls:dohandshake() then
        local cipher = "Unknown" -- initialized variable incase old ssl library is being used
        if tls.getcipherinfo then 
            local info = tls:getcipherinfo() -- :getcipherinfo() is a method call on tls
            cipher = info.name or "Unknown"
        elseif tls.info then
            cipher = tls:info("cipher") or "Unknown"
        end
        
        log_event("TLS_Protocol", true, "Established via " .. cipher)
        
        -- Forward Secrecy check
        local has_pfs = (cipher:match("ECDHE") or cipher:match("DHE")) ~= nil
        log_event("Forward_Secrecy", has_pfs, has_pfs and "PFS supported" or "RSA Key Exchange (No PFS)")        
        
        -- Close the Tls connection or Log event if handshake fails
        tls:close()
        else
        log_event("TLS_Protocol", false, "Handshake failed")
    end
end

-- ========= 2 SCSV Downgrade Check =========
local function scsv_downgrade_audit()
-- Downgrade Attack Check (SCSV)
-- We try to force the server to talk to us in obsolete TLS 1.0
    local tcp2 = socket.tcp()
    tcp2:settimeout(3)
    tcp2:connect(HOST, 443)
    local tls2 = ssl.wrap(tcp2, {mode="client", protocol="tlsv1", verify="none"})
    local hs_ok = tls2 and tls2:dohandshake()
        
    log_event("Downgrade_Attack", not hs_ok, not hs_ok and "Server blocks legacy TLS 1.0" or "Vulnerable: Server accepts TLS 1.0")
        
    if tls2 then 
        tls2:close() 
    end
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
    -- Check if the server at least tries to push you to HTTPS
    local secure_redirect = resp:match("Location: https://") ~= nil

    if hsts then
        local msg = has_preload and "HSTS Enforced (Preload Requested)" or "HSTS Enforced"
        log_event("HSTS_Privacy", true, msg)
    elseif secure_redirect then
        -- This covers cases like Google/Proton where the first hit is a secure redirect
        log_event("HSTS_Privacy", true, "Secure Redirect to HTTPS (HSTS inherited)")
    else
        log_event("HSTS_Privacy", false, "HSTS missing (Insecure)")
    end
end

-- ========= 4 DNS Infrastructure Checks =========
local function check_dns_security()
    -- CAA Record: Only specific CAs can issue certs
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

-- ========= Execution Flow =========
print("\n\27[1mDeep Security & Privacy Audit:\27[0m " .. HOST)
print(string.rep("-", 60))

audit_tls()
scsv_downgrade_audit()
hsts_check()
check_dns_security()
check_mta_sts()

print(string.rep("-", 60) .. "\n")
