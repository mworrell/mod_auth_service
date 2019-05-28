%% @author Marc Worrell <marc@worrell.nl>
%% @copyright 2019 Marc Worrell
%% @doc Model for mod_auth_service

%% Copyright 2019 Marc Worrell
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%% 
%%     http://www.apache.org/licenses/LICENSE-2.0
%% 
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

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
