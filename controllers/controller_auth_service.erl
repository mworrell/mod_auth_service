%% @author Marc Worrell <marc@worrell.nl>
%% @copyright 2019 Marc Worrell <marc@worrell.nl>
%% @doc Token handling for mod_auth_service.

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

-module(controller_auth_service).

-author("Marc Worrell <marc@worrell.nl>").

-export([
    init/1,
    service_available/2,
    allowed_methods/2,
    forbidden/2,
    content_types_provided/2,
    process_post/2,

    config_secret/1
]).

-include_lib("controller_webmachine_helper.hrl").
-include_lib("zotonic.hrl").

init(DispatchArgs) ->
    {ok, DispatchArgs}.

service_available(ReqData, DispatchArgs) when is_list(DispatchArgs) ->
    Context = z_context:new_request(ReqData, DispatchArgs, ?MODULE),
    {true, ReqData, Context}.

allowed_methods(ReqData, Context) ->
    {['POST'], ReqData, Context}.

forbidden(ReqData, Context) ->
    Context1 = ?WM_REQ(ReqData, Context),
    Context2 = z_context:ensure_qs(Context1),
    Signature = z_context:get_q("signature", Context2),
    Nonce = z_context:get_q("nonce", Context2),
    {IsSigOk, Context3} = check_sig(Signature, Nonce, config_secret(Context2), Context2),
    ?WM_REPLY(not IsSigOk, Context3).

content_types_provided(ReqData, Context) ->
    {[ {"application/json", process_post} ], ReqData, Context}.

process_post(ReqData, Context) ->
    Context1 = ?WM_REQ(ReqData, Context),
    Cmd = z_context:get(cmd, Context1),
    Result = case Cmd of
        'request-token' ->
            TokenProps = [
                {accept_url, z_convert:to_binary( z_context:get_q(accept_url, Context) )}
            ],
            {ok, Token} = mod_auth_service:request_token(TokenProps, Context1),
            RedirectUrl = z_context:abs_url(
                z_dispatcher:url_for(auth_service_logon, [ {token, Token} ], Context),
                Context),
            {ok, [
                {status, ok},
                {token, Token},
                {redirect_url, RedirectUrl}
            ]};
        'exchange-token' ->
            Token = z_context:get_q("token", Context1),
            exchange_token(Token, Context1);
        'sync-users' ->
            {Body, _Req1} = wrq:req_body(ReqData),
            Users = mochijson2:decode(Body),
            sync_users(Users, Context1)
    end,
    case Result of
        {ok, Props} ->
            post_return(encode(Props), Context1);
        {error, _} = Error ->
            lager:info("[mod_auth_service] ~p with error ~p", [Cmd, Error]),
            post_return(encode([ {status, error} ]), Context1)
    end.

post_return(Data, Context) ->
    {x, RD, Context1} = ?WM_REPLY(x, Context),
    RD1 = wrq:append_to_resp_body(Data, RD),
    {true, RD1, Context1}.

encode(Props) ->
    z_convert:to_binary( mochijson2:encode( Props ) ).

config_secret(Context) ->
    case m_config:get_value(mod_auth_service, request_secret, Context) of
        undefined -> set_secret(Context);
        <<>> -> set_secret(Context);
        S when is_binary(S) -> S
    end.

set_secret(Context) ->
    S = z_ids:id(32),
    m_config:set_value(mod_auth_service, request_secret, S, Context),
    S.

exchange_token(Token, Context) ->
    Token1 = z_convert:to_binary(Token, Context),
    case mod_auth_service:exchange_token(Token1, Context) of
        {ok, {UserId, AuthRequestProps}} when is_integer(UserId) ->
            RemoteId = case m_identity:get_rsc_by_type(UserId, auth_service_remote_id, Context) of
                [] ->
                    null;
                [ Idn | _ ] ->
                    z_convert:to_integer( proplists:get_value(key, Idn) )
            end,
            {ok, [
                {status, <<"ok">>},
                {resource_id, UserId},
                {id, RemoteId},
                {username, map_undefined( m_identity:get_username(UserId, z_acl:sudo(Context)) )},
                {email, map_undefined( m_rsc:p_no_acl(UserId, email, Context) )},
                {name_first, map_undefined( m_rsc:p_no_acl(UserId, name_first, Context) )},
                {name_surname, map_undefined( m_rsc:p_no_acl(UserId, name_surname, Context) )}
                | AuthRequestProps
            ]};
        {error, _} = Error ->
            Error
    end.

sync_users(Users, Context) ->
    lager:info("Syncing remote users starting: ~p accounts", [length(Users)]),
    ContextSudo = z_acl:sudo(Context),
    CurrentUsers = find_all_users(ContextSudo),
    LocalUserIds = lists:map(
        fun(User) ->
            sync_user(User, ContextSudo)
        end,
        Users),
    Deleted = CurrentUsers -- LocalUserIds,
    New = LocalUserIds -- CurrentUsers,
    lists:foreach(
        fun(DelUserId) ->
            m_rsc:delete(DelUserId, ContextSudo)
        end,
        Deleted),
    lager:info("Syncing remote users done: ~p inserted, ~p deleted", [length(New), length(Deleted)]),
    {ok, [ {status, ok}, {insert, length(New)}, {delete, length(Deleted)} ]}.

sync_user({struct, UserProps}, Context) ->
    RemoteId = proplists:get_value(<<"id">>, UserProps),
    Email = proplists:get_value(<<"email">>, UserProps),
    NameFirst = proplists:get_value(<<"name_first">>, UserProps),
    NameSurname = proplists:get_value(<<"name_surname">>, UserProps),
    IsEnabled = z_convert:to_bool( proplists:get_value(<<"is_enabled">>, UserProps) ),
    RscProps = [
        {is_published, IsEnabled},
        {visible_for, 1},
        {category, person},
        {content_group, auth_service_content_group},
        {email, Email},
        {title, <<NameFirst/binary, " ", NameSurname/binary>>},
        {name_first, NameFirst},
        {name_surname, NameSurname},
        {seo_noindex, true},
        {seo_title, <<>>},
        {custom_slug, true},
        {slug, <<>>}
    ],
    RemoteIdBin = z_convert:to_binary( RemoteId ),
    case find_user(RemoteId, Context) of
        {ok, LocalId} ->
            {ok, _} = m_rsc:update(LocalId, RscProps, Context),
            case m_identity:set_username(LocalId, Email, Context) of
                ok ->
                    LocalId;
                {error, eexist} ->
                    lager:warning("Remote service updating duplicate account for '~s' (ignored external id ~s, local id ~p)",
                                 [ Email, RemoteIdBin, LocalId ]),
                    LocalId;
                {error, Reason} ->
                    lager:warning("Remote service updating ~p error for account for '~s' (ignored external id ~s, local id ~p)",
                                 [ Reason, Email, RemoteIdBin, LocalId ]),
                    LocalId
            end;
        {error, notfound} ->
            {ok, LocalId} = m_rsc:insert(RscProps, Context),
            m_identity:insert(LocalId, auth_service_remote_id, RemoteIdBin, Context),
            RandomPassword = z_ids:id(),
            case m_identity:set_username_pw(LocalId, Email, RandomPassword, Context) of
                ok ->
                    LocalId;
                {error, eexist} ->
                    lager:warning("Remote service inserting duplicate account for '~s' (ignored external id ~s, local id ~p)",
                                 [ Email, RemoteIdBin, LocalId ]),
                    LocalId
            end
    end.

find_user(RemoteId, Context) ->
    RemoteIdBin = z_convert:to_binary( RemoteId ),
    case m_identity:lookup_by_type_and_key(auth_service_remote_id, RemoteIdBin, Context) of
        undefined ->
            {error, notfound};
        Idn ->
            {rsc_id, RscId} = proplists:lookup(rsc_id, Idn),
            {ok, RscId}
    end.

find_all_users(Context) ->
    All = z_db:q("select distinct rsc_id from identity where type = 'auth_service_remote_id'", Context),
    [ Id || {Id} <- All ].

map_undefined(undefined) -> null;
map_undefined(V) -> V.

check_sig(Signature, Nonce, Secret, Context) ->
    NonceB = z_convert:to_binary(Nonce),
    SecretB = z_convert:to_binary(Secret),
    Req = z_context:get_reqdata(Context),
    {Data, Context1} = case wrq:get_req_header_lc("content-type", Req) of
        "application/x-www-form-urlencoded" ++ _ ->
            Args = z_context:get_q_all_noz(Context),
            {join_args( lists:sort(Args), <<>> ), Context};
        "multipart/form-data" ++ _ ->
            Args = z_context:get_q_all_noz(Context),
            {join_args( lists:sort(Args), <<>> ), Context};
        "application/json" ->
            {Body, Req1} = wrq:req_body( Req ),
            {Body, z_context:set_reqdata(Req1, Context)}
    end,
    Cmd = z_convert:to_binary( z_context:get(cmd, Context) ),
    Data1 = <<Cmd/binary, "::", Data/binary, $:, NonceB/binary>>,
    {eq( sig(Data1, SecretB), z_convert:to_binary(Signature)), Context1}.

sig( Data, Key ) ->
    z_string:to_lower( iolist_to_binary( z_utils:hex_encode( crypto:hmac(sha256, Key, Data) ) ) ).

eq(A, B) ->
    A1 = z_convert:to_binary(A),
    B1 = z_convert:to_binary(B),
    eq1(A1, B1, true).

join_args([], Acc) ->
    Acc;
join_args([ {"signature", _} | As ], Acc) ->
    join_args(As, Acc);
join_args([ {"nonce", _} | As ], Acc) ->
    join_args(As, Acc);
join_args([ {Name, Value} | As ], Acc) ->
    NameB = z_convert:to_binary(Name),
    ValueB = z_convert:to_binary(Value),
    Acc1 = <<Acc/binary, NameB/binary, $=, ValueB/binary, $:>>,
    join_args(As, Acc1).


%% @doc Compare for equality in consistent time.
eq1(<<>>, <<>>, Eq) -> Eq;
eq1(<<>>, _, _Eq) -> false;
eq1(_, <<>>, _Eq) -> false;
eq1(<<A,RA/binary>>, <<B,RB/binary>>, Eq) ->
    eq1(RA, RB, A =:= B andalso Eq).
