-module(m_auth_service).

-export([
    m_find_value/3
]).

-include("zotonic.hrl").

m_find_value(is_valid_request, #m{ value = undefined }, Context) ->
    Token = z_convert:to_binary( z_context:get_q(token, Context) ),
    mod_auth_service:is_valid_token(Token, Context);
m_find_value(remote_site, #m{ value = undefined }, Context) ->
    m_config:get_value(mod_auth_service, remote_site, Context).
