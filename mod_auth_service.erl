%% @author Marc Worrell <marc@worrell.nl>
%% @copyright 2019 Marc Worrell
%% @doc Simple single signon for small projects.

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


% In the following "SITE" is pre-configured, together with an API secret.

% 1. SITE requests token from us (API call)
% 2. Redirect with token in the url to our page
% 3. If valid token: ensure user logged on
% 4. If logged on: show button to redirect to SITE
% 5. If button clicked: redirect to SITE (success url, no extras)
% 6. SITE checks with us using token in their session and fetches credentials

-module(mod_auth_service).

-mod_title("Auth Service").
-mod_description("Sign on service for adding Zotonic authentication to a pre-configured other site.").
-mod_schema(1).
-mod_dependes([ acl, mod_content_groups ]).

-behaviour(gen_server).

-export([
    event/2,

    request_token/2,
    is_valid_token/2,
    lookup_token/2,
    exchange_token/2,

    pid_observe_logon_actions/4,

    manage_schema/2
]).

%% gen_server exports
-export([start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).


%% gen_server state record
-record(state, {
        site :: atom(),
        tokens = #{} :: map()
    }).

-define(PERIODIC_CLEANUP, 60000).       % 1 minute
-define(RETAIN_PERIOD_SECS, 600).       % 10 minutes

-include("zotonic.hrl").

event(#postback{ message = {auth_service_logon_done, [ {request_token, Token} ]} }, Context) ->
    UserId = z_acl:user(Context),
    Token1 = z_convert:to_binary(Token),
    case UserId of
        undefined ->
            z_render:wire({redirect, [ {back, true} ]}, Context);
        _ when is_integer(UserId) ->
            case lookup_token(Token1, Context) of
                {ok, {UserId, TokenProps}} ->
                    {accept_url, AcceptUrl} = proplists:lookup(accept_url, TokenProps),
                    case AcceptUrl of
                        <<"http://", _/binary>> ->
                            z_render:wire({redirect, [ {location, AcceptUrl} ]}, Context);
                        <<"https://", _/binary>> ->
                            z_render:wire({redirect, [ {location, AcceptUrl} ]}, Context)
                    end;
                {error, _} = Error ->
                    lager:info("Token ~p error ~p", [ Token1, Error ]),
                    z_render:wire({redirect, [ {back, true} ]}, Context)
            end
    end.

is_valid_token(Token, Context) ->
    case gen_server:call( name(Context), {is_valid_token, Token}) of
        {ok, IsValid} -> IsValid;
        {error, _} -> false
    end.

-spec request_token( proplists:proplist(), z:context() ) -> {ok, binary()}.
request_token(TokenProps, Context) ->
    gen_server:call( name(Context), {request_token, TokenProps}).

-spec exchange_token( binary(), z:context() ) -> {ok, {m_rsc:resource_id(), proplists:proplist()}} | {error, nouser|notfound}.
exchange_token(Token, Context) when is_binary(Token) ->
    gen_server:call( name(Context), {exchange_token, Token} ).

-spec lookup_token( binary(), z:context() ) -> {ok, {m_rsc:resource_id(), proplists:proplist()}} | {error, nouser|notfound}.
lookup_token(Token, Context) when is_binary(Token) ->
    gen_server:call( name(Context), {lookup_token, Token} ).


pid_observe_logon_actions(Pid, #logon_actions{ args = [ {auth_service_logon, Token} ]}, Actions, Context) ->
    z:info("User ~p authenticated using ~p from ~s",
           [
                z_acl:user(Context),
                m_identity:get_username(Context),
                m_req:get(peer, Context)
           ],
           [ {module, ?MODULE} ],
           Context),
    Token1 = z_convert:to_binary(Token),
    ok = gen_server:call( Pid, {set_token_user, Token1, z_acl:user(Context)}),
    [
        {redirect, [ {dispatch, auth_service_logon_done}, {token, Token1} ]}
    ] ++ Actions;
pid_observe_logon_actions(_Pid, #logon_actions{ args = _ }, Actions, _Context) ->
    Actions.


manage_schema(_, _Context) ->
    #datamodel{
        resources=[
            {auth_service_content_group, content_group, [
                {title, {trans, [{en, <<"Remote Users">>}, {nl, <<"Externe Gebruikers">>}]}}
            ]}
        ]
    }.

%%====================================================================
%% API
%%====================================================================
%% @spec start_link(Args) -> {ok,Pid} | ignore | {error,Error}
%% @doc Starts the server, ensure the request secret is set.
start_link(Args) when is_list(Args) ->
    {context, Context} = proplists:lookup(context, Args),
    _ = controller_auth_service:config_secret(Context),
    gen_server:start_link({local, name(Context)}, ?MODULE, Args, []).

%%====================================================================
%% gen_server callbacks
%%====================================================================

%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore               |
%%                     {stop, Reason}
%% @doc Initiates the server.
init(Args) when is_list(Args) ->
    {context, Context} = proplists:lookup(context, Args),
    Site = z_context:site(Context),
    lager:md([
        {site, Site},
        {module, ?MODULE}
      ]),
    timer:send_after(?PERIODIC_CLEANUP, cleanup),
    {ok, #state{ site = Site, tokens = #{} }}.

handle_call({request_token, TokenProps}, _From, #state{ tokens = Ts } = State) ->
    Token = new_token(),
    Ts1 = Ts#{
        Token => {undefined, TokenProps, z_datetime:timestamp()}
    },
    {reply, {ok, Token}, State#state{ tokens = Ts1 }};

handle_call({is_valid_token, Token}, _From, #state{ tokens = Ts } = State) ->
    {reply, {ok, maps:is_key(Token, Ts)}, State};

handle_call({exchange_token, Token}, _From, #state{ tokens = Ts } = State) ->
    case maps:find(Token, Ts) of
        {ok, {undefined, _Props, _Timestamp}} ->
            Ts1 = maps:remove(Token, Ts),
            {reply, {error, nouser}, State#state{ tokens = Ts1 }};
        {ok, {UserId, Props, _Timestamp}} ->
            Ts1 = maps:remove(Token, Ts),
            {reply, {ok, {UserId, Props}}, State#state{ tokens = Ts1 }};
        error ->
            {reply, {error, notfound}, State}
    end;

handle_call({set_token_user, Token, UserId}, _From, #state{ tokens = Ts } = State) ->
    case maps:find(Token, Ts) of
        {ok, {undefined, Props, Timestamp}} ->
            Ts1 = Ts#{ Token => {UserId, Props, Timestamp} },
            {reply, ok, State#state{ tokens = Ts1 }};
        {ok, {UserId, _Props, _Timestamp}} ->
            {reply, ok, State};
        {ok, {_OtherUserId, _Props, _Timestamp}} ->
            {reply, {error, user}, State};
        error ->
            {reply, {error, notfound}, State}
    end;

handle_call({lookup_token, Token}, _From, #state{ tokens = Ts } = State) ->
    case maps:find(Token, Ts) of
        {ok, {undefined, _Props, _Ts}} ->
            {reply, {error, nouser}, State};
        {ok, {UserId, Props, _Ts}} ->
            {reply, {ok, {UserId, Props}}, State};
        error ->
            {reply, {error, notfound}, State}
    end;

handle_call(Message, _From, State) ->
    {stop, {unknown_call, Message}, State}.

handle_cast(Message, State) ->
    {stop, {unknown_cast, Message}, State}.

handle_info(cleanup, #state{ tokens = Ts } = State) ->
    Old = z_datetime:timestamp() - ?RETAIN_PERIOD_SECS,
    Ts1 = maps:filter( fun(_Key, {_UserId, _Props, T}) -> T >= Old end, Ts ),
    timer:send_after(?PERIODIC_CLEANUP, cleanup),
    {noreply, State#state{ tokens = Ts1 }};

handle_info(Info, State) ->
    lager:warning("[mod_auth_service] unknown info message ~p", [Info]),
    {noreply, State}.

%% @spec terminate(Reason, State) -> void()
%% @doc This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any necessary
%% cleaning up. When it returns, the gen_server terminates with Reason.
%% The return value is ignored.
terminate(_Reason, _State) ->
    ok.

%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @doc Convert process state when code is changed
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%%====================================================================
%% Internal functions
%%====================================================================

name(Context) ->
    z_utils:name_for_host(?MODULE, Context).


new_token() ->
    z_convert:to_binary( z_ids:id(32) ).

