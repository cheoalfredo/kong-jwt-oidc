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
local utils = require "kong.tools.utils"
local Errors = require "kong.db.errors"
local az = require("kong.plugins.jwt-oidc.authorization")

local function check_user(anonymous)
  if anonymous == "" or utils.is_valid_uuid(anonymous) then
    return true
  end

  return false, "the anonymous user must be empty or a valid uuid"
end

local function check_positive(v)
  if v < 0 then
    return false, "should be 0 or greater"
  end

  return true
end


return {
  no_consumer = true,
  fields = {
    token_header_name = {type = "string", required = true, default = "Authorization"},
    discovery = {type = "url", required = true},
    auto_discover_issuer = {type = "boolean", required = false, default = false},
    expected_issuers = {type = "array", required = false, default = {}},
    accepted_audiences = {type = "array", required = false, default = {}},
    ssl_verify = {type = "string", default = "no"},
    jwk_expires_in = {type = "number", required = false, default = 7200, func = check_positive},
    ensure_consumer_present = {type = "boolean", required = false, default = false},
    consumer_claim_name = {type = "string", default = "appid"},
    run_on_preflight = {type = "boolean", required = false, default = false},
    upstream_jwt_header_name = {type = "string", required = true, default = "validated_jwt"},
    accept_none_alg = {type = "boolean", required = false, default = false},
    iat_slack = {type = "number", required = false, default = 120, func = check_positive},
    timeout = {type = "number", required = false, default = 3000, func = check_positive},
    anonymous = {type = "string", default = "", func = check_user},
    filters = { type = "string" },
    enable_authorization_rules = { type = "boolean", required = true, default = false },
    authorization_claim_name = { type = "string", required = "true", default = "roles" },
    implicit_authorize = { type = "boolean", required = true, default = false},
    whitelist = { type = "array", required = true, default = {}},
    blacklist = { type = "array", required = true, default = {}}
  },
  self_check = function(schema, plugin_t, dao, is_update)
    if plugin_t.ensure_consumer_present then
      if plugin_t.consumer_claim_name == nil or plugin_t.consumer_claim_name == '' then
        -- return false, Errors.schema "consumer_claim_name must be defined when ensure_consumer_present is enabled"
        plugin_t.consumer_claim_name = "appid"
      end
    end

    if not is_update then
      if plugin_t.token_header_name == nil or plugin_t.token_header_name == '' then
          return false, Errors.schema "token_header_name must not be blank!"
      end
    end

    if plugin_t.enable_authorization_rules then
      if plugin_t.authorization_claim_name == nil or plugin_t.authorization_claim_name == '' then
        return false, Errors.schema "authorization_claim_name must be defined when enable_authorization_rules is enabled"
      else
        local error, whitelist = az.parse_rules(plugin_t.whitelist)
        if error ~= nil then
          return false, Errors.schema "invalid whitelist for authorization"..error
        else
          --plugin_t.whitelist = whitelist
        end
        error, blacklist = az.parse_rules(plugin_t.blacklist)
        if error ~= nil then
          return false, Errors.schema "invalid blacklist for authorization"..error
        else
          --plugin_t.blacklist = blacklist
        end
      end
    end

    return true
  end
}
