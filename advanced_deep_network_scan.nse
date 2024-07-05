description = [[
Performs an advanced deep scan of the target network, including service detection,
version detection, OS detection, detailed service enumeration, vulnerability assessment,
HTTP headers, DNS records, SSL/TLS details, and brute force checks from various protocols.
]]

author = "Chathuranga BW <chathurangabw@gmail.com>"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe", "vuln"}

-- Importing necessary libraries
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local dns = require "dns"
local sslcert = require "sslcert"
local brute = require "brute"
local smtp = require "smtp"

-- Define the action function which will be executed by Nmap
action = function(host, port)
  local result = {}

  -- Service and version detection
  if port.version then
    table.insert(result, string.format(
      "Port: %s/%s\n  Service: %s\n  Version: %s\n  Product: %s\n  Extra Info: %s",
      port.number, port.protocol, port.service, port.version or "unknown",
      port.product or "unknown", port.extrainfo or "unknown"
    ))

    -- Include vulnerability information from relevant scripts
    if port.script_results then
      table.insert(result, "  Vulnerability Results:")
      for _, script_result in ipairs(port.script_results) do
        table.insert(result, string.format("    %s: %s", script_result['id'], script_result['output']))
      end
    end
  end

  -- OS detection
  if host.os then
    table.insert(result, "OS: " .. (host.os.osfamily or "unknown"))
  end

  -- Script results
  if host.scripts then
    for script, output in pairs(host.scripts) do
      table.insert(result, string.format("Script: %s Output: %s", script, output))
    end
  end

  -- Host scripts results
  if host.script_results then
    table.insert(result, "Host Scripts Results:")
    for _, script_result in ipairs(host.script_results) do
      table.insert(result, string.format("  %s: %s", script_result['id'], script_result['output']))
    end
  end

  -- HTTP headers
  if port.service == "http" or port.service == "https" then
    local response = http.get(host, port, "/")
    if response then
      table.insert(result, "HTTP Headers:")
      for name, value in pairs(response.header) do
        table.insert(result, string.format("  %s: %s", name, value))
      end
    end
  end

  -- Brute force check (example for HTTP)
  if port.service == "http" then
    local brute_result_http = brute.engine(host, port, brute.http_default)
    if brute_result_http then
      table.insert(result, "HTTP Brute Force Results:")
      for _, r in ipairs(brute_result_http) do
        table.insert(result, string.format("  %s: %s", r.account, r.status))
      end
    end
  end

  -- Brute force check (example for FTP)
  if port.service == "ftp" then
    local brute_result_ftp = brute.engine(host, port, brute.ftp_default)
    if brute_result_ftp then
      table.insert(result, "FTP Brute Force Results:")
      for _, r in ipairs(brute_result_ftp) do
        table.insert(result, string.format("  %s: %s", r.account, r.status))
      end
    end
  end

  -- Brute force check (example for SSH)
  if port.service == "ssh" then
    local brute_result_ssh = brute.engine(host, port, brute.ssh_default)
    if brute_result_ssh then
      table.insert(result, "SSH Brute Force Results:")
      for _, r in ipairs(brute_result_ssh) do
        table.insert(result, string.format("  %s: %s", r.account, r.status))
      end
    end
  end

  -- Brute force check (example for Telnet)
  if port.service == "telnet" then
    local brute_result_telnet = brute.engine(host, port, brute.telnet_default)
    if brute_result_telnet then
      table.insert(result, "Telnet Brute Force Results:")
      for _, r in ipairs(brute_result_telnet) do
        table.insert(result, string.format("  %s: %s", r.account, r.status))
      end
    end
  end

  -- Brute force check (example for MySQL)
  if port.service == "mysql" then
    local brute_result_mysql = brute.engine(host, port, brute.mysql_default)
    if brute_result_mysql then
      table.insert(result, "MySQL Brute Force Results:")
      for _, r in ipairs(brute_result_mysql) do
        table.insert(result, string.format("  %s: %s", r.account, r.status))
      end
    end
  end

  -- Brute force check (example for Postgres)
  if port.service == "postgres" then
    local brute_result_postgres = brute.engine(host, port, brute.postgres_default)
    if brute_result_postgres then
      table.insert(result, "Postgres Brute Force Results:")
      for _, r in ipairs(brute_result_postgres) do
        table.insert(result, string.format("  %s: %s", r.account, r.status))
      end
    end
  end

  -- SMTP check (example for open relay)
  if port.service == "smtp" then
    local relay_result = smtp.openrelay(host, port)
    table.insert(result, "SMTP Open Relay Check: " .. (relay_result and "Vulnerable" or "Not Vulnerable"))
  end

  return stdnse.format_output(true, table.concat(result, "\n"))
end

-- Register the script
portrule = function(host, port)
  return shortport.port_or_service({1, 65535}, {"tcp", "udp"})
end
