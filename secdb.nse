local http   = require "http"
local json   = require "json"
local string = require "string"
local table  = require "table"
local nmap   = require "nmap"
local stdnse = require "stdnse"

description = [[
For each available CPE (and product) the script prints out known vulns and
correspondent EPSS and CVSS (v4.0, v3.x and 2.0) scores, known exploits
(Exploit DB, Metasploit) and advisories from ZEN SecDB portal (https://secdb.nttzen.cloud).
]]

---
-- @usage
-- nmap -sV --script secdb [--script-args secdb.mincvss=<score>,secdb.url=<url>] <target>
--
-- @args secdb.mincvss  Filters out vulnerabilities with a CVSS score or higher
-- @args secdb.url      Specify SecDB URL (default https://secdb.nttzen.cloud)
--
-- @output
--
-- PORT   STATE SERVICE REASON  VERSION
-- 21/tcp open  ftp     syn-ack vsftpd 2.3.4
-- | secdb: 
-- |   vsftpd 2.3.4: 
-- | 
-- |       Known Vulnerabilities
-- | 
-- |       CVE ID          EPSS    CVSSv4  CVSSv3  CVSSv2  URL
-- |       ------------------------------------------------------------
-- |       CVE-2011-2523   50.35%  -       9.8     10.0    https://secdb.nttzen.cloud/cve/detail/CVE-2011-2523
-- | 
-- |       Known Exploits (*)
-- | 
-- |       Type            ID        
-- |       ------------------------------------------------------------
-- |       Exploit DB      17491           https://secdb.nttzen.cloud/exploit-db/detail/17491
-- |       Exploit DB      49757           https://secdb.nttzen.cloud/exploit-db/detail/49757
-- | 
-- |       (*) based on detected CPE and known CVEs
-- |_
--
-- @xmloutput
-- <table key="vsftpd 2.3.4">
--   <table>
--     <elem key="url">http://localhost:3000/cve/detail/CVE-2011-2523</elem>
--     <elem key="epss">0.50348</elem>
--     <table key="cvss_v2">
--       <elem key="score">10.0</elem>
--       <elem key="severity">HIGH</elem>
--       <elem key="version">2.0</elem>
--       <elem key="vector_string">AV:N/AC:L/Au:N/C:C/I:C/A:C</elem>
--     </table>
--     <table key="exploits">
--       <table>
--         <elem key="cve_id">CVE-2011-2523</elem>
--         <elem key="url">http://localhost:3000/exploit-db/detail/17491</elem>
--         <elem key="id">17491</elem>
--         <elem key="type">Exploit DB</elem>
--       </table>
--       <table>
--         <elem key="cve_id">CVE-2011-2523</elem>
--         <elem key="url">http://localhost:3000/exploit-db/detail/49757</elem>
--         <elem key="id">49757</elem>
--         <elem key="type">Exploit DB</elem>
--       </table>
--     </table>
--     <table key="cvss_v3">
--       <elem key="score">9.8</elem>
--       <elem key="severity">CRITICAL</elem>
--       <elem key="version">3.1</elem>
--       <elem key="vector_string">CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</elem>
--     </table>
--     <table key="advisories"></table>
--     <elem key="id">CVE-2011-2523</elem>
--     <elem key="description">vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.</elem>
--   </table>
-- </table>
--
-- @changelog
-- 2020-02-24 - First release
-- 2022-02-01 - Improved API
-- 2022-02-24 - Improved output
-- 2022-05-04 - Added "exploits"
-- 2022-05-10 - Added "advisories"
-- 2025-02-25 - Added CVSS v4.0 and EPSS support
-- 2025-03-07 - First public release

author     = 'giuseppe DOT diterlizzi AT gmail DOT com'
license    = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe", "external"}


local PLUGIN_VERSION = "25.03.0"
local BASE_URL       = stdnse.get_script_args(SCRIPT_NAME .. '.url') or 'https://secdb.nttzen.cloud'
local MIN_CVSS_SCORE = stdnse.get_script_args(SCRIPT_NAME .. '.mincvss')

local EXTRAINFO_PATTERNS = {
  {
    cpe   = 'cpe:/a:php:php',
    regex = 'PHP/([%d.]+)'
  },
  {
    cpe   = 'cpe:/a:openssl:openssl',
    regex = 'OpenSSL/([%d.]+%w)'
  }
}


portrule = function(host, port)
  local vers=port.version
  return vers ~= nil and vers.version ~= nil
end

local vuln_meta = {
   __tostring = function(self)

    local output = "\n\n\tKnown Vulnerabilities\n\n"
    output = output .. ("\t%-15s\t%-5s\t%-5s\t%-5s\t%-5s\t%s\n"):format("CVE ID", "EPSS", "CVSSv4", "CVSSv3", "CVSSv2", "URL")
    output = output .. "\t------------------------------------------------------------\n"

    local exploits   = {}
    local advisories = {}

    for _, vuln in ipairs(self) do

      local cvss_v4 = vuln.cvss_v4 ~= nil and vuln.cvss_v4.score or "-"
      local cvss_v3 = vuln.cvss_v3 ~= nil and vuln.cvss_v3.score or "-"
      local cvss_v2 = vuln.cvss_v2 ~= nil and vuln.cvss_v2.score or "-"
      local epss    = vuln.epss ~= nil and ("%.2f%%"):format(vuln.epss * 100) or "-"

      output = output .. ("\t%-15s\t%-5s\t%-5s\t%-5s\t%-5s\t%s\n"):format(vuln.id, epss, cvss_v4, cvss_v3, cvss_v2, vuln.url)

      for _, advisory in ipairs(vuln.advisories) do
        advisories[#advisories+1] = advisory
      end

      for _, exploit in ipairs(vuln.exploits) do
        exploits[#exploits+1] = exploit
      end

    end

    if (#exploits > 0) then

      output = output .. "\n\tKnown Exploits (*)\n\n"
      output = output .. ("\t%-10s\t%-10s\n"):format('Type', 'ID')
      output = output .. "\t------------------------------------------------------------\n"

      table.sort(exploits, function(a, b) return a.id < b.id end)

      local _exploits = {}

      for _, exploit in ipairs(exploits) do
        -- Remove duplicate exploits
        if not _exploits[exploit.id] then
          output = output .. ("\t%-10s\t%-10s\t%-15s\n"):format(exploit.type, exploit.id, exploit.url or '')
          _exploits[exploit.id] = 1
        end
      end

    end

    if (#advisories > 0) then

      output = output .. "\n\tKnown Security Advisories (*)\n\n"
      output = output .. ("\t%-20s\t%-10s\t%-15s\n"):format('ID', 'Severity', 'Title')
      output = output .. "\t------------------------------------------------------------\n"

      table.sort(advisories, function(a, b) return a.id < b.id end)

      local _advisories = {}

      for _, advisory in ipairs(advisories) do
        -- Remove duplicate advisories
        if not _advisories[advisory.id] then
          output = output .. ("\t%-20s\t%-10s\t%-15s\n"):format(advisory.id, advisory.severity, advisory.title)
          _advisories[advisory.id] = 1
        end
      end

    end

    if (#advisories > 0 or #exploits > 0) then
      output = output .. "\n\t(*) based on detected CPE and known CVEs\n"
    end

    output = output .. "\n"

    return output
  end,
}

function secdb_api(param)

  local query = {}

  if param.product ~= nil then
    query['cpe_product'] = param.product:gsub(' ', '_'):lower()
    query['cpe_version'] = param.version
  end

  if param.cpe ~= nil then
    query['cpe'] = param.cpe
  end

  if MIN_CVSS_SCORE and tonumber(MIN_CVSS_SCORE) then
    local score = MIN_CVSS_SCORE + 0
    if score > 0 and score <= 10  then
      query['cvss_score'] = { score, 10 }
    end
  end

  local API_URL = ('%s/api/v1/feed/cve?q=%s&fields=title,description,published,modified,metrics,exploits,security_advisories,epss'):format(BASE_URL, json.generate(query):gsub(' ', ''))

  stdnse.print_debug(2, 'SecDB API URL: ' .. API_URL)

  local option = {
    header = {
      ['User-Agent'] = string.format('SecDB NMAP Plugin/%s', PLUGIN_VERSION)
    },
    any_af = true,
    timeout = 30000
  }

  local response = http.get_url(API_URL, option)

  if response.status == nil then
    return
  elseif response.status ~= 200 then
    return
  end

  local status, data = json.parse(response.body)

  if status == true then
    return vuln_output(data)
  end

end

function vuln_output(vulns)

    local output = { }

    for _, vuln in ipairs(vulns) do

      local vulnerability_table = {}

      local exploits   = {}
      local advisories = {}

      local cve = {
        id          = vuln.id,
        title       = vuln.title,
        description = vuln.description,
        epss        = vuln.epss ~= nil and vuln.epss.score or nil,
        url         = ('%s/cve/detail/%s'):format(BASE_URL, vuln.id)
      }

      if vuln.metrics.cvss2 ~= nil then
        cve['cvss_v2'] = {
          version       = 2.0,
          score         = vuln.metrics.cvss2.base_score,
          severity      = vuln.metrics.cvss2.base_severity,
          vector_string = vuln.metrics.cvss2.vector_string,
        }
      end

      if vuln.metrics.cvss3 ~= nil then
        cve['cvss_v3'] = {
          version       = vuln.metrics.cvss3.version,
          score         = vuln.metrics.cvss3.base_score,
          severity      = vuln.metrics.cvss3.base_severity,
          vector_string = vuln.metrics.cvss3.vector_string,
        }
      end

      if vuln.metrics.cvss4 ~= nil then
        cve['cvss_v4'] = {
          version       = 4.0,
          score         = vuln.metrics.cvss4.base_score,
          severity      = vuln.metrics.cvss4.base_severity,
          vector_string = vuln.metrics.cvss4.vector_string,
        }
      end

      vulnerability_table = cve
      vulnerability_table['advisories'] = {}
      vulnerability_table['exploits'] = {}

      for i, exploit in ipairs(vuln.exploits.exploitdb) do

        local url = ('%s/exploit-db/detail/%s'):format(BASE_URL, exploit)

        local exploit_table = {
          cve_id  = vuln.id,
          type    = 'Exploit DB',
          id      = exploit,
          url     = url
        }

        exploits[i] = exploit_table

      end

      for i, exploit in ipairs(vuln.exploits.metasploit) do

        local exploit_table = {
          cve_id  = vuln.id,
          type    = 'Metasploit',
          id      = exploit,
          url     = nil
        }

        exploits[i] = exploit_table

      end

      if #exploits > 0 then
        vulnerability_table['exploits'] = exploits
      end

      for i, security_advisory in ipairs(vuln.security_advisories) do

        local advisory_url = ('%s/security-advisory/%s/%s'):format(BASE_URL, security_advisory.type, security_advisory.id)

        local advisory_table = {
          cve_id   = vuln.id,
          type     = security_advisory.type,
          title    = security_advisory.title,
          id       = security_advisory.id,
          severity = security_advisory.severity,
          url      = advisory_url
        }

        advisories[i] = advisory_table

      end

      if #advisories > 0 then
        vulnerability_table['advisories'] = advisories
      end

      output[#output+1] = vulnerability_table

    end

    setmetatable(output, vuln_meta)

    return output

end

action = function(host, port)

  local output = stdnse.output_table()
  local found  = false

  for i, cpe in ipairs(port.version.cpe) do

    stdnse.print_debug(1, 'Found CPE: ' .. cpe)

    -- CPE cpe:/part:vendor:product:version
    _, count = cpe:gsub(':', '')

    -- Exclude CPE without version (eg. cpe:/o:linux:kernel_linux)
    if count < 4 then
      stdnse.print_debug(1, 'CPE without version... skip')
      goto NEXT_CPE
    end

    local result = secdb_api({ cpe = cpe })

    if (result ~= nil and next(result) ~= nil) then
      output[cpe] = result
      found = true
    end

    ::NEXT_CPE::

  end

  if not found then
    if (port.version.product ~= nil) then

      local product_version = port.version.product .. ' ' .. port.version.version
      stdnse.print_debug(1, 'Found Product and Version: ' .. product_version)

      local product = port.version.product
      local version = port.version.version

      -- TODO Change space in ":" and use cpe string or split in vendor and product ???

      params = { product = product, version = version }

      local result = secdb_api(params)

      if (result ~= nil and next(result) ~= nil) then
        output[product_version] = result
        found = true
      end

    end
  end

  -- Get the version number string (eg. 9.6.0 or later --> 9.6.0)
  if not found then

    local version = string.match(port.version.version, '([%d%.%-%_]+)')
    local product_version = port.version.product .. ' ' .. version
    stdnse.print_debug(1, 'Found Product and Version: ' .. product_version)

    local result  = secdb_api({ product = port.version.product:lower(), version = version })

    if (result ~= nil and next(result) ~= nil) then
      output[product_version] = result
      found = true
    end

  end

  -- Always check extrainfo
  if (port.version.extrainfo ~= nil) then
    for _, item in ipairs(EXTRAINFO_PATTERNS) do

      local version = string.match(port.version.extrainfo, item.regex)

      if (version ~= nil) then

        local cpe = item.cpe .. ':' .. version
        stdnse.print_debug(1, 'Detected extrainfo CPE: ' .. cpe)

        local result = secdb_api({ cpe = cpe })

        if next(result) ~= nil then
          output[cpe] = result
        end

      end

    end
  end

  if (#output > 0) then
    return output
  end

end
