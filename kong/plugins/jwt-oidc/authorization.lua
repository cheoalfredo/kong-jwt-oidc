--[[
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.

***************************************************************************
Copyright (c) 2018 @gt_tech
All rights reserved.

For further information please contact: https://bitbucket.org/gt_tech/

DISCLAIMER OF WARRANTIES:

THE SOFTWARE PROVIDED HEREUNDER IS PROVIDED ON AN "AS IS" BASIS, WITHOUT
ANY WARRANTIES OR REPRESENTATIONS EXPRESS, IMPLIED OR STATUTORY; INCLUDING,
WITHOUT LIMITATION, WARRANTIES OF QUALITY, PERFORMANCE, NONINFRINGEMENT,
MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  NOR ARE THERE ANY
WARRANTIES CREATED BY A COURSE OR DEALING, COURSE OF PERFORMANCE OR TRADE
USAGE.  FURTHERMORE, THERE ARE NO WARRANTIES THAT THE SOFTWARE WILL MEET
YOUR NEEDS OR BE FREE FROM ERRORS, OR THAT THE OPERATION OF THE SOFTWARE
WILL BE UNINTERRUPTED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

@Author: https://bitbucket.org/gt_tech/

--]]
local utils = require("kong.plugins.oidc.utils")


local _M = {

}

_M.__index = openidc

local function trim(s)
  return (string.gsub(s, "^%s*(.-)%s*$", "%1"))
end


local function trimAndUpper(input)
  if input ~= nil then
    return string.upper(trim(input))
  else
    return ""
  end
end

local function split(inputstr, sep)
  if sep == nil then
    return {}
  end
  local t={} ; i=1
  for str in string.gmatch(inputstr, "([^"..sep.."]+)") do
    --ngx.log(ngx.DEBUG, "JwksAwareJwtAccessTokenHandler - splitted value: "..str.." from original string: "..inputstr.." using seperator: "..sep)
    t[i] = trimAndUpper(str)
    i = i + 1
  end
  return t
end

-- Parses the configuration which is expected to be in format: "GET=group1; group2"
local function parse(c)
  local method
  local arr = {}
  local err

  local strValue = split(c, "=")

  if strValue ~= nil and strValue[1] ~= nil then
    method = strValue[1]
    if method == "GET" or method == "PUT" or method == "POST" or method == "DELETE" or method == "PATCH" or method == "OPTIONS" then
      arr = split(strValue[2], ";")
    else
      err = "Invalid authorization rule: " .. c
    end
  end
  return method, arr, err
end

local function do_parse_rules(arr)
  local err
  local az_rules = {}

  ngx.log(ngx.DEBUG, "JwksAwareJwtAccessTokenHandler - starting to parsing authorization rule: "..table.concat(arr, ","))

  if arr then
    for _, c in ipairs(arr) do
      local method, settings, error = parse(c)
      if type(error) == "string" then
        err = "cannot parse '" .. c .. "': " .. error
        break
      else
        if az_rules[method] ~= nil then
          err = "Duplicate rules defined for method: "..method
          break
        else
          ngx.log(ngx.DEBUG, "JwksAwareJwtAccessTokenHandler - Adding settings: ["..table.concat(settings, ",").."] for method: "..method)
          az_rules[method] = settings
        end
      end
    end
  end

  ngx.log(ngx.DEBUG, "JwksAwareJwtAccessTokenHandler - finished parsing authorization rule: "..table.concat(arr, ","))
  
  return err, az_rules
end

function _M.parse_rules(arr)
  return do_parse_rules(arr)
end

-- Validates blacklist per configuration
local function validate_blacklist(http_method, conf, claims) 
  local error, bList = do_parse_rules(conf.blacklist)
  local response_committed = false
  if error ~= nil then
    utils.exit(ngx.HTTP_UNAUTHORIZED, "Configuration error in parsing blacklist rules", 500)
    response_committed = true
    return response_committed
  end

  if claims ~= nil and bList ~= nil and bList[http_method] ~= nil then
    for iuc, uc in pairs(claims) do
      for ic, c in pairs(bList[http_method]) do
        if c == uc then
          local err = "Access denied!. Method: "..http_method..", Incoming Claims: ["..table.concat(claims,",").."]"
          ngx.log(ngx.DEBUG, "JwksAwareJwtAccessTokenHandler - "..err)
          response_committed = true
          utils.exit(ngx.HTTP_UNAUTHORIZED, "Access denied!", ngx.HTTP_UNAUTHORIZED)
        end
      end
    end
  end
  return response_committed
end

-- Validate per whitelist configuration
local function validate_whitelist(http_method, conf, claims)
  local error, cList = do_parse_rules(conf.whitelist)
  if error ~= nil then
    utils.exit(ngx.HTTP_UNAUTHORIZED, "Configuration error in parsing whitelist rules", 500)
    return
  end
  if (conf.whitelist == nil or cList[http_method] == nil) and conf.implicit_authorize then
    ngx.log(ngx.DEBUG, "JwksAwareJwtAccessTokenHandler - No whitelist configured for method"..http_method..", authorizing implicitly per plugin configuration")
    return
  end

  local authorized = false
  
  if claims ~= nil and cList[http_method] ~= nil then
    for iuc, uc in pairs(claims) do
        for ic, c in pairs(cList[http_method]) do
          if c == uc then
            authorized = true
            break
          end
        end
        if authorized then
          break
        end
    end
  end   

  if not authorized then
    local err = "Access denied!. Method: "..http_method..", Incoming Claims: ["..table.concat(claims,",").."]"
    ngx.log(ngx.DEBUG, "JwksAwareJwtAccessTokenHandler - "..err)
    utils.exit(ngx.HTTP_UNAUTHORIZED, "Access denied!", ngx.HTTP_UNAUTHORIZED)
  end
end


-- Main exposed function from this module that performs authorization checks.
-- It's caller responsibility to check if authorization should be checked or not, 
-- this function when invoked will perform authorization.
function _M.validate_authorization(conf, json)
  local raw_claims = json[conf.authorization_claim_name]
  local claims = {}
  if type(raw_claims) == "string" then
    claims[1] = trimAndUpper(raw_claims)
  elseif type(raw_claims) == "array" or type(raw_claims) == "table" then
    claims = raw_claims
    for i, c in pairs(raw_claims) do
      claims[i] = trimAndUpper(c)
    end
  else
    if not conf.implicit_authorize then
      utils.exit(ngx.HTTP_BAD_REQUEST, "Unexpected type of authorization claim: "..type(raw_claims).." using claim name: "..conf.authorization_claim_name, ngx.HTTP_BAD_REQUEST)
    end
    -- implicit else that for implicit_authorization is enabled and hence we just return without checking white/blacklist as there's no claim available to check
    return
  end

  local committed = validate_blacklist(trimAndUpper(ngx.req.get_method()), conf, claims)
  if not committed then
    -- blacklist check didn't fire any response so move to check whitelist
    validate_whitelist(trimAndUpper(ngx.req.get_method()), conf, claims)
  end

end

return _M

