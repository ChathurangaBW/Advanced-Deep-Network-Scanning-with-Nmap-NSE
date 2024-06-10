-- Save this file as advanced_deep_network_scan.nse

description = [[
Performs an advanced deep scan of the target network, including service detection,
version detection, OS detection, and detailed service enumeration.
]]

author = "Chathuranga BW <chathurangabw@gmail.com>"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe", "vuln"}

-- Importing necessary libraries
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

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

  return stdnse.format_output(true, table.concat(result, "\n"))
end

-- Register the script
portrule = function(host, port)
  return shortport.port_or_service({1, 65535}, {"tcp", "udp"})
end
