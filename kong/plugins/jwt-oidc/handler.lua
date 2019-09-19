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

local BasePlugin = require "kong.plugins.base_plugin"
local JwksAwareJwtAccessTokenHandler = BasePlugin:extend()
local openidc = require("kong.plugins.jwt-oidc.resty-lib.openidc")
local az = require("kong.plugins.jwt-oidc.authorization")
local utils = require("kong.plugins.oidc.utils")
local filter = require("kong.plugins.oidc.filter")
local singletons = require "kong.singletons"

local cjson = require("cjson")
local get_method = ngx.req.get_method
local req_set_header = ngx.req.set_header
local req_clear_header = ngx.req.clear_header
local next = next

JwksAwareJwtAccessTokenHandler.PRIORITY = 1000


local function extract(config) 
  local jwt
  local err
  local header = ngx.req.get_headers()[config.token_header_name]
  
  if header == nil then
    err = "No token found using header: " .. config.token_header_name
    ngx.log(ngx.ERR, err)
    return nil, err
  end
  
  if header:find(" ") then
    local divider = header:find(' ')
    if string.lower(header:sub(0, divider-1)) == string.lower("Bearer") then
      jwt = header:sub(divider+1)
      if jwt == nil then
        err = "No Bearer token value found from header: " .. config.token_header_name
        ngx.log(ngx.ERR, err)
        return nil, err
      end
    end
  end
  
  if jwt == nil then
    jwt =  header
  end
  
  ngx.log(ngx.DEBUG, "JWT token located using header: " .. config.token_header_name .. ", token length: " .. string.len(jwt))
  return jwt, err
end

local function updateHeaders(config, token)
  req_clear_header(config.token_header_name) -- Clear Original header from request
  ngx.log(ngx.DEBUG, "Setting header: " .. config.upstream_jwt_header_name .. " with validated token")
  req_set_header(config.upstream_jwt_header_name, token)
end

local function validateTokenContents(config, token, json)

--  if not config.auto_discover_issuer then
    if config.expected_issuers and next(config.expected_issuers) ~= nil then
      -- validate issuer
      local validated_issuer = false
      local issuer = json["iss"]

      for i, e in ipairs(config.expected_issuers) do
        if issuer ~= nil and issuer ~= '' and string.lower(e) == string.lower(issuer) then
          validated_issuer = true
          ngx.log(ngx.DEBUG, "Successfully validated issuer: " .. e)
          break
        end
      end

      if not validated_issuer then
        -- issuer validation failed.
        utils.exit(ngx.HTTP_UNAUTHORIZED, "Issuer not expected", ngx.HTTP_UNAUTHORIZED)
      end
    end
--  end


  if config.accepted_audiences and next(config.accepted_audiences) ~= nil then
    -- validate audience
    local validated_audience = false
    local audience = json["aud"]

    for i, e in ipairs(config.accepted_audiences) do
      if audience ~= nil and audience ~= '' and string.lower(e) == string.lower(audience) then
        validated_audience = true
        ngx.log(ngx.DEBUG, "Successfully validated audience: " .. e)
        break
      end
    end

    if not validated_audience then
      -- audience validation failed.
      utils.exit(ngx.HTTP_UNAUTHORIZED, "Audience not accepted", ngx.HTTP_UNAUTHORIZED)
    end
  end

end


local function load_consumer(consumer_id)
  ngx.log(ngx.DEBUG, "JwksAwareJwtAccessTokenHandler Attempting to find consumer: " .. consumer_id)
  local result, err = singletons.dao.consumers:find { id = consumer_id }
  if not result then
    err = "Consumer: " .. consumer_id .. " not found!"
    ngx.log(ngx.ERR, err)
    return nil, err
  end
  return result
end

function JwksAwareJwtAccessTokenHandler:new()
  JwksAwareJwtAccessTokenHandler.super.new(self, "JwksAwareJwtAccessTokenHandler")
end

function JwksAwareJwtAccessTokenHandler:access(config)
  JwksAwareJwtAccessTokenHandler.super.access(self)

  if not config.run_on_preflight and get_method() == "OPTIONS" then
    ngx.log(ngx.DEBUG, "JwksAwareJwtAccessTokenHandler pre-flight request ignored, path: " .. ngx.var.request_uri)
    return
  end

  if ngx.ctx.authenticated_credential and config.anonymous ~= "" then
    -- already authenticated likely by another auth plugin higher in priority.
    return
  end
  
  if filter.shouldProcessRequest(config) then
    handle(config)
  else
    ngx.log(ngx.DEBUG, "JwksAwareJwtAccessTokenHandler ignoring request, path: " .. ngx.var.request_uri)
  end

  ngx.log(ngx.DEBUG, "JwksAwareJwtAccessTokenHandler execution complete for request: " .. ngx.var.request_uri)
end

function handle(config)
  local token, error = extract(config)
  if token == null or error then
    utils.exit(ngx.HTTP_UNAUTHORIZED, error, ngx.HTTP_UNAUTHORIZED)
  else
    local json, err = openidc.jwt_verify(token, config)
    if token == null or err then
      ngx.log(ngx.ERR, "JwksAwareJwtAccessTokenHandler - failed to validate access token")
      utils.exit(ngx.HTTP_UNAUTHORIZED, err, ngx.HTTP_UNAUTHORIZED)
    else
      ngx.log(ngx.DEBUG, "JwksAwareJwtAccessTokenHandler - Successfully validated access token")
      if config.ensure_consumer_present then
        -- consumer presence is required
        ngx.log(ngx.DEBUG, "Consumer presence is required")
        local cid = json[config.consumer_claim_name]
        if cid == nil or cid == '' then
          -- consumer id claim not read
          ngx.log(ngx.ERR, "Consumer ID could not be read using claim: " .. config.consumer_claim_name)
          utils.exit(ngx.HTTP_UNAUTHORIZED, error, ngx.HTTP_UNAUTHORIZED)
        else
          ngx.log(ngx.DEBUG, "Consumer ID: " .. cid .. " read using claim: " .. config.consumer_claim_name)
          local consumer, e = load_consumer(cid)
          if consumer == null or e then
            -- consumer can't be loaded from Kong
            ngx.log(ngx.ERR, "Consumer ID could not be fetched for cid: " .. cid)
            utils.exit(ngx.HTTP_UNAUTHORIZED, error, ngx.HTTP_UNAUTHORIZED)
          else
            --  consumer succesfully loaded from kong
            ngx.ctx.authenticated_consumer = consumer
            ngx.ctx.authenticated_credential = cid
            req_set_header("X-Consumer-Username", cid)
            updateHeaders(config, token)
            validateTokenContents(config, token, json)
            if config.enable_authorization_rules then
              az.validate_authorization(config, json)
            end
          end
        end
      else
        -- consumer presence is not required
        updateHeaders(config, token)
        validateTokenContents(config, token, json)
        if config.enable_authorization_rules then
          az.validate_authorization(config, json)
        end
      end
    end
  end
end

return JwksAwareJwtAccessTokenHandler
