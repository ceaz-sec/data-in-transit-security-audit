# Data-in-Transit Security Audit 🛡️

A high-performance LuaJIT utility designed to audit the resilience and privacy of network connections. This tool goes beyond simple SSL checks by analyzing cipher suite intent, DNS-level security policies, and protocol downgrade vulnerability potential.

## Key Features
* **TLS Handshake Analysis:** Identifies ciphers and validates Perfect Forward Secrecy (PFS).
* **Hardware vs. Software Detection:** Recognizes optimizations like ChaCha20 (Mobile) vs. AES-GCM (Hardware Accelerated).
* **SCSV Downgrade Protection:** Actively attempts a protocol downgrade to test server hardening.
* **HSTS & Redirect Logic:** Validates browser-level security headers and HTTPS enforcement.
* **Infrastructure Privacy:** Audits DNS records for CAA (Certificate Authority Authorization) and MTA-STS (Email Transport Security).

## Usage
* **Example Usage:** ./data-in-transit-security-audit.lua <domain>

## Installation
Ensure you have `luajit` and the following libraries installed via LuaRocks:
```bash
luarocks install luasocket
luarocks install luasec

## Real Examples
In the examples directory, concise audit reports can be found for public facing websites. These findings showcase the effectivenss of this utility.
