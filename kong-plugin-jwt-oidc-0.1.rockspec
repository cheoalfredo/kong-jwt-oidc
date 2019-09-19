package = "kong-plugin-jwt-oidc"  
version = "0.1"               

supported_platforms = {"linux", "macosx"}
source = {
  url = "http://github.com/Kong/kong-plugin.git",
  tag = "0.1"
}

description = {
  summary = "Kong is a scalable and customizable API Management Layer built on top of Nginx.",
  homepage = "http://getkong.org",
  license = "Apache 2.0"
}

dependencies = {
  "kong-oidc ~> 1.1.0"
}
build = {
  type = "builtin",
  modules = {   
    ["kong.plugins.jwt-oidc.handler"] = "kong/plugins/jwt-oidc/handler.lua",
    ["kong.plugins.jwt-oidc.schema"] = "kong/plugins/jwt-oidc/schema.lua",
	["kong.plugins.jwt-oidc.authorization"] = "kong/plugins/jwt-oidc/authorization.lua",
	["kong.plugins.jwt-oidc.resty-lib.openidc"] = "kong/plugins/jwt-oidc/resty-lib/openidc.lua",
  }
}
