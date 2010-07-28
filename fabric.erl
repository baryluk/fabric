-module(fabric).

-export([start_server/0, start_client/1]).
-export([start_server/2, start_client/3]).
%-export([start_snd_rewrite/1]).
%-export([start_rcv_rewrite/1]).
-export([send/2]).
%-export([send_bin/2]).

% for code update and hibernate
-export([code_update/2]).
-export([proxy_code_update/2]).

% call to update code of fabric
-export([update/0]).

% server section

start_server() ->
	start_server(20404, "secret").

start_server(Port, Secret) ->
	Master = self(),
	Pid = spawn(fun() -> start_raw_server(Port, Secret, Master) end),
	receive
		{Pid, Status} ->
			Status
		after 10000 ->
			throw(timeout)
	end.

start_raw_server(Port, Secret, Master) ->
	case gen_tcp:listen(Port, [binary,
	        {nodelay, true}, {packet, 4},
	        {reuseaddr, true}, {active, true}]) of
		{ok, Listen} ->
			Master ! {self(), ok},
			New = start_accept(Listen, Secret),
			New;
		Error ->
			Master ! {self(), Error}
	end.

% TODO: multiple clients allowed to connect to single server
% TODO: support forwarding and rewriting of pids on two different clients
% TODO: support multiple servers (i.e. on separate machines) also to cooperate
% TODO: mapping must be consistent and distributed, for example, to support
%       loops from at least 3 machines.
% TODO: make [safe] work completly - change registered_names() to strings
%       also on failure do not crash server

start_accept(Listen, Secret) ->
	case gen_tcp:accept(Listen) of
		{ok, Socket} ->
			register(fabric, self()),
			inet:setopts(Socket, [binary,
			       {packet, 4},
			       {nodelay, true},
			       {active, once}]),
			spawn(fun() -> start_accept(Listen, Secret) end),
			server_child_loop0(Socket, Secret)
	end.

server_child_loop0(Socket, Secret) ->
	io:format("Entering server main loop~n"),
	% perform authentification and establish encryption channel
	receive
		{tcp, Socket, Bin1} ->
			{hello, Name} = _H = binary_to_term(Bin1, [safe]),
%			io:format("~p~n", [_H]),
			{Challenge, _Verificator} = fabric_auth:make_challenge(Name, Secret),
			C = {challenge, Challenge},
			ok = gen_tcp:send(Socket, term_to_binary(C)),
%			io:format("~p~n", [C]),
			inet:setopts(Socket, [{active, once}]),
			receive
				{tcp, Socket, Bin2} ->
					{response, Response} = _R = binary_to_term(Bin2, [safe]),
%					io:format("~p~n", [_R]),
					case fabric_auth:is_response_correct(Challenge, Name, Response, Secret) of
						true ->
							ok = gen_tcp:send(Socket, term_to_binary({auth, success})),
							inet:setopts(Socket, [{active, once}]),
							enter_loop(Socket);
						false ->
							ok = gen_tcp:send(Socket, term_to_binary({auth, failed})),
							gen_tcp:close(Socket),
							bad_secret
					end;
				{tcp_error, Socket, Reason2} ->
					{error, Reason2};
				{tcp_close, Socket} ->
					closed
			end;
		{tcp_error, Socket, Reason1} ->
			{error, Reason1};
		{tcp_close, Socket} ->
			closed
	end.

% client section

start_client(Host) ->
	start_client(Host, 20404, "secret").

start_client(Host, Port, Secret) ->
	Master = self(),
	Pid = spawn_link(fun() -> start_raw_client(Host, Port, Secret, Master) end),
	receive
		{Pid, Status} ->
			Status
		after 10000 ->
			throw(timeout)
	end.

start_raw_client(Host, Port, Secret, Master) ->
	case gen_tcp:connect(Host, Port, [binary,
	          {nodelay, true},
	          {packet, 4},
	          {reuseaddr, true},
	          {active, once}]) of
		{ok, Socket} ->
			register(fabric, self()),
			Master ! {self(), ok},
			New = client_loop0(Socket, Secret),
			New;
		Error ->
			Master ! {self(), Error}
	end.

client_loop0(Socket, Secret) ->
	io:format("Entering client main loop~n"),
	% perform authentification and establish encryption channel
	Name = "localhost",
	ok = gen_tcp:send(Socket, term_to_binary({hello, Name})),
	receive
		{tcp, Socket, Bin1} ->
			{challenge, Challenge} = _B1 = binary_to_term(Bin1, [safe]),
%			io:format("~p~n", [_B1]),
			Response = fabric_auth:make_response(Challenge, Name, Secret),
			R = {response, Response},
			ok = gen_tcp:send(Socket, term_to_binary(R)),
%			io:format("~p~n", [R]),
			inet:setopts(Socket, [{active, once}]),
			receive
				{tcp, Socket, Bin2} ->
					AuthR = binary_to_term(Bin2, [safe]),
%					io:format("~p~n", [AuthR]),
					case AuthR of
						{auth, success} ->
							inet:setopts(Socket, [{active, once}]),
							enter_loop(Socket);
						{auth, failed} ->
							gen_tcp:close(Socket),
							auth_failed
					end;
				{tcp_error, Socket, Reason2} ->
					{error, Reason2};
				{tcp_close, Socket} ->
					closed
			end;
		{tcp_error, Socket, Reason1} ->
			{error, Reason1};
		{tcp_close, Socket} ->
			closed
	end.



% common loop

enter_loop(Socket) ->
	Proxies = gb_trees:empty(),
	process_flag(trap_exit, true),
	inet:setopts(Socket, [{active, once}]),
	loop(Socket, Proxies).

loop(Socket, Proxies) ->
	receive
		{tcp, Socket, Bin} ->
			% it will be properly packed/unpacked due {packet,4}
			Term = binary_to_term(Bin, []), % safe - is too much - atoms will not work
%			io:format("Received: ~p~n", [Term]),
			case Term of
				%{n, Token, Id} ->
				%	loop(Socket, Proxies2);
				{r, _Token1, _RegName, Id} ->
					FabricPid = self(),
					% lists:member(RegName, allowed_registered_names())
					create_new_proxy(Id, FabricPid),
					inet:setopts(Socket, [{active, once}]),
					loop(Socket, Proxies);
				{m, _To, _Msg} ->
					rcv_process(Term),
					inet:setopts(Socket, [{active, once}]),
					loop(Socket, Proxies);
				{'DEAD', {pr, Id}, Info} ->
					Pid = rcv_rewrite_pid_remote(Id),
%					io:format("Remote process Id=~p dead - stoping proxy ~p wth reason ~p~n", [Id, Pid, Info]),
					What = case Info of
						noproc -> {return, normal};
						_ -> {exit, Info}
					end,
					Pid ! {'$__fabric_proxy_control.e66a73', node(), "", What},
					erase({id_to_pid1, {pr, Id}}),
					erase({pid_to_id1, Id}),
					inet:setopts(Socket, [{active, once}]),
					loop(Socket, Proxies)
			end;
		{send, _From, Dest, Term} -> % used directly by fabric:send/2
			Bin = encode_send(Dest, Term),
			ok = gen_tcp:send(Socket, Bin),
			loop(Socket, Proxies);
		%{send_bin, _From, _Dest, Bin} -> % used directly by fabric:send_bin/2
		%   % similar to send but performs Pid->Id translation out of the fabric process
		%	gen_tcp:send(Socket, Bin),
		%	loop(Socket, Proxies);
		{forward, ProxyPid, _ProxyToken, Term} ->  % used by proxy
%			io:format("Sending: ~p to ~p~n", [Term, ProxyPid]),
			Bin = encode_send(ProxyPid, Term),
			ok = gen_tcp:send(Socket, Bin),
			loop(Socket, Proxies);
		{rpc_call, From, Ref, Call} ->
			case Call of
					{whereis, Name} ->
						Result = undefined,
						fabric_rpc_reply(From, Ref, Result),
						loop(Socket, Proxies);
					{info, Pid} ->
						%Result = {local,browser,unknown,[registeredas]},
						%Result = {local,server,unknown,[registeredas]},
						%Result = {proxy_for_remote,server,[ip,port,latency,version]},
						%Result = {proxy_for_remote,browser,[ip,port,latency,version]},
						%   for proxies request also statistics (number of messages)
						Result = undefined,
						fabric_rpc_reply(From, Ref, Result),
						loop(Socket, Proxies);
					close ->
						ok = gen_tcp:close(Socket),
						fabric_rpc_reply(From, Ref, ok),
						exit(crash);
					code_update ->
						io:format("Reentering loop using fqdn for code update~n"),
						fabric_rpc_reply(From, Ref, ok),
						?MODULE:code_update(Socket, Proxies);
					%{map_request, From, Dest} when is_pid(Dest) ->
					%	From ! {map_result, self(), Dest, snd_rewrite_pid(Dest)},
					%	loop(Socket, Proxies);
					%{proxy_remote_registered, Name} when is_atom(Name) ->
					%	
					%	loop(Socket, Proxies);
					%{get_proxies, From} ->
					%	ProxiesList = gb_trees:to_list(Proxies),
					%	From ! {proxies, ProxiesList},
					%	loop(Socket, Proxies);
					_ ->
						undefined, % just make client timeout with exception
						loop(Socket, Proxies);
			end;
		{'EXIT', Pid, Why} ->
			io:format("Received exit signal 'EXIT' ~p ~p~n", [Pid, Why]),
			% remove from dictionary
			% propagate signal to the remote side if needed (link or monitor)
			loop(Socket, Proxies);
		{'DOWN', MonitorRef, process, Pid, Info} ->
%			io:format("Received monitor message 'DOWN' ~p ~p~n", [Pid, Info]),
			% it can be one of our proxy processes or one of 
			case get({monitor, MonitorRef}) of
				{local, Id1} ->
%					io:format(" - local process Id=~p~n", [Id1]),
					{pl, _Id2} = snd_rewrite_pid(Pid),
					Meta = {'DEAD', {pr, Id1}, Info},
					inet:setopts(Socket, [{active, once}]),
					ok = gen_tcp:send(Socket, term_to_binary(Meta)),
					loop(Socket, Proxies);
				{remote, Id1} ->
%					io:format(" - remote process Id=~p~n", [Id1]),
					loop(Socket, Proxies);
				undefined ->
					throw(unknown_monitor)
			end;
		{tcp_error, Socket, Reason} ->
			io:format("Connection error~n", []),
			exit({error, Reason});
		{tcp_closed, Socket} ->
			io:format("Connection closed~n", []),
			exit(connection_closed);
		Other ->
			io:format("Unknown message received: ~p~n", [Other]),
			loop(Socket, Proxies)
	end.

code_update(Socket, Proxies) ->
	% TODO: propagete code_update message to all child proxy processes
	loop(Socket, Proxies).

update() ->
	fabric_rpc(code_update).

stop() ->
	fabric_rpc(stop).

% procesing

rcv_process({m, Dest, Payload}) ->
	rcv_process(Dest, start_rcv_rewrite(Payload)).

rcv_rewrite_pid_local(DestProcessMapId) when is_integer(DestProcessMapId) ->
	case get({id_to_pid1, {pl,DestProcessMapId}}) of
		{local, Pid} when is_pid(Pid) ->
			Pid;
		undefined ->
			throw(no_such_process_map_id)
	end.

rcv_rewrite_pid_remote(DestProcessMapId) when is_integer(DestProcessMapId) ->
	case get({id_to_pid1, {pr,DestProcessMapId}}) of
		{remote, Pid} when is_pid(Pid) ->
			Pid;
		undefined ->
			throw(no_such_process_map_id)
	end.


rcv_process(DestProcessMapId, Msg) when is_integer(DestProcessMapId) ->
	case rcv_rewrite_pid_local(DestProcessMapId) of
		Pid when is_pid(Pid) ->
%			io:format("Doing: ~p ! ~p~n", [Pid, Msg]),
			Pid ! Msg;
		_ ->
			Msg
	end;
rcv_process({RegName, Node} = NR, Msg) when is_atom(Node), is_atom(RegName) ->
	catch (NR ! Msg);
rcv_process(RegName, Msg) when is_atom(RegName) ->
%	io:format("Doing: ~p ! ~p~n", [RegName, Msg]),
	case lists:member(RegName, allowed_registered_names()) of
		true ->
			catch (RegName ! Msg);
		false ->
			void
	end.


% encoding functions

start_rcv_rewrite(Msg) ->
	rcv_rewrite(Msg).


rcv_rewrite(N) when is_integer(N); is_float(N) ->
	N;
rcv_rewrite(A) when is_atom(A) ->
	A;
rcv_rewrite([H|T]) ->
	% TODO: tail-recursion
	[rcv_rewrite(H)|rcv_rewrite(T)];
rcv_rewrite({t, Tuple}) when is_tuple(Tuple) ->
	list_to_tuple([ rcv_rewrite(E) || E <- tuple_to_list(Tuple) ]);
rcv_rewrite({pl, ProcessMapId}) when is_integer(ProcessMapId) ->
	case get({id_to_pid1, {pl,ProcessMapId}}) of
		% yes, it is swaped remote<->local
		{local, RealPid} when is_pid(RealPid) ->
			RealPid;
		undefined ->
			spawn(fun() -> dummy_dead_process end);
		Other ->
			io:format("Other1: ~p -> ~p~n", [{pl, ProcessMapId}, Other]),
			throw(something_wrong1)
	end;
rcv_rewrite({pr, ProcessMapId}) when is_integer(ProcessMapId) ->
	case get({id_to_pid1, {pr,ProcessMapId}}) of
		% yes, it is swaped remote<->local
		{remote, ProxyPid} when is_pid(ProxyPid) ->
			ProxyPid;
		undefined ->
			FabricPid = self(),
			ProxyPid = create_new_proxy(ProcessMapId, FabricPid),
			ProxyPid;
		Other ->
			io:format("Other2: ~p -> ~p~n", [{pr, ProcessMapId}, Other]),
			throw(something_wrong2)
	end;
rcv_rewrite({f, _A, {}}) ->
	%fun() -> ok end,
	throw(fun_mapping_not_implemented_yet);
rcv_rewrite([]) ->
	[];
rcv_rewrite({r, RefId}) ->
	binary_to_term(RefId);
rcv_rewrite(B) when is_binary(B) ->
	B.

start_snd_rewrite(Msg) ->
	Term = snd_rewrite(Msg),
%	io:format("snd pre-encoded msg: ~p~n", [Msg]),
%	io:format("snd post-encoded msg: ~p~n", [Term]),
	Term.


snd_rewrite(N) when is_integer(N); is_float(N) ->
	N;
snd_rewrite(A) when is_atom(A) ->
	A;
snd_rewrite([H|T]) ->
	% TODO: tail-recursion
	[snd_rewrite(H)|snd_rewrite(T)];
snd_rewrite(Tuple) when is_tuple(Tuple) ->
	{t, list_to_tuple([ snd_rewrite(E) || E <- tuple_to_list(Tuple) ])};
snd_rewrite(Pid) when is_pid(Pid) ->
	WId = case snd_rewrite_pid(Pid) of
		% swap
		{pl, Id} -> {pr, Id};
		{pr, Id} -> {pl, Id}
	end,
	% we can use pid_to_list, instead of integer, but we will still need dictionary for security reasons,
	% to be sure that remote side, do not 
	WId;
snd_rewrite(Fun) when is_function(Fun) ->
	{arity, A} = erlang:fun_info(Fun, arity),
	{f, A, Fun};
snd_rewrite([]) ->
	[];
snd_rewrite(Ref) when is_reference(Ref) ->
	RefId = term_to_binary(Ref),
	{r, RefId};
snd_rewrite(B) when is_binary(B) ->
	B.


% Note: process dictionary isn't very good solution here
% there are two kind of process which we rewrite on sending here:
%   - our side   - this are mapped to Ids that will map back to original processes
%   - their side (including destination) - this are mapped so 
snd_rewrite_pid(Pid) when is_pid(Pid) ->
	case get({pid_to_id1, Pid}) of
		 % pr<->pl is swaped, as pr will be remote on receving side
		{local, ProcessMapId} when is_integer(ProcessMapId) ->
			{pl, ProcessMapId};
		{remote, ProcessMapId} when is_integer(ProcessMapId) ->
			{pr, ProcessMapId};

		undefined ->
			MonitorRef = erlang:monitor(process, Pid),

			NewId = case get(pid1_next_id) of
				undefined -> 1;
				NextId -> NextId
			end,
			WId = {pl, NewId},
			% it is always 'local', as 'remote' ones are always added
			% to dictionary on creation, so cannot be undefined
			put({monitor, MonitorRef}, {local, NewId}),
			put({pid_to_id1, Pid}, {local, NewId}),
			put({id_to_pid1, WId}, {local, Pid}),
			% TODO: monitor process Pid
			put(pid1_next_id, NewId+1),
			WId
	end.

%snd_rewrite_pid_(Pid) when is_pid(Pid) ->
%	fabric ! {map_request, self(), Pid},
%	receive
%		{map_result, _From, Pid, Id} ->
%			Id
%	end.

encode_send(To, Msg) ->
	Payload = start_snd_rewrite(Msg),
	ToId = case To of
		{Node, RegName} when is_atom(Node), is_atom(RegName) ->
			To;
		RegName when is_atom(RegName) ->
			To;
		Pid when is_pid(Pid) ->
			{pr, Id} = snd_rewrite_pid(Pid),
			Id
	end,
	Term = {m, ToId, Payload},
	Bin = term_to_binary(Term, [{minor_version, 1}, compressed]),
	Bin.

% basic primtives

%send_bin(To, Msg) ->
%	Bin = encode_send(To, Msg),
%	fabric ! {send_bin, self(), To, Bin},
%	ok.

send(To, Msg) ->
	fabric ! {send, self(), To, Msg},
	ok.

fabric_rpc(Call) ->
	Ref = make_ref(),
	%Ref = erlang:monitor(process, fabric),
	fabric ! {rpc, self(), Ref, Call},
	fabric_rpc_rcv_loop(Ref, 10000).

fabric_rpc_rcv_loop(Ref, Timeout) ->
	receive
		{rpc, Ref, Result} ->
			%erlang:demonitor(Ref, [flush]),
			Result;
		%{'DOWN', Ref, _, _, Info} ->
		%	throw ({crashed,Info});
		{rpc, _, _OldResult} ->
			% TODO: we should update Timeout here to be smaller now
			fabric_rpc_rcv_loop(Ref, Timeout)
		after Timeout ->
			throw (timeout)
	end.


%proxies() ->
%	fabric ! {get_proxies, self()},
%	receive
%		{proxies, L} ->
%			L
%	end.

% other things to proxy: spawn_* on different node, link/1, unlink/1, monitor/2

create_new_proxy(Id, FabricPid) ->
	Token2 = "",
	{ProxyPid, MonitorRef} = spawn_opt(fun() -> enter_proxy_loop(FabricPid, Token2) end, [link, monitor]),
%	io:format("Created proxy process ProxyPid=~p , MonitoRef=~p for remote process Id=~p in FabricPid=~p~n", [ProxyPid, MonitorRef, Id, FabricPid]),
	put({monitor, MonitorRef}, {remote, Id}),
	put({pid_to_id1, ProxyPid}, {remote, Id}),
	put({id_to_pid1, {pr, Id}}, {remote, ProxyPid}),
	ProxyPid.


% proxy loop

enter_proxy_loop(FabricPid, Token) when is_pid(FabricPid) ->
	%process_flag(trap_exit, true),
	proxy_loop(FabricPid, Token).

proxy_loop(FabricPid, Token) ->
	receive
		{'$__fabric_proxy_control.e66a73', Node, Token, What} when Node =:= node() ->
			case What of
				{send, To, Msg} ->
					% this isn't really very usefull,
					% as fabric can send Msg to To directly.
					To ! Msg,
					proxy_loop(FabricPid, Token);
				{exit, Reason} ->
					exit(Reason);
				{'throw', T} ->
					throw(T);
				{return, R} ->
					R;
				{code_update, NewFabricPid, NewToken} ->
					% this can be usefull not only on code change,
					% but also in case of recconect, where
					% we still want to have proxies to be alive (as it can be referenced by some local processes)
					% but new Fabric process was started
					io:format("Reentering proxy_loop using fqdn for code update~n"),
					?MODULE:proxy_code_update(NewFabricPid, NewToken)
			end;
		Msg ->
%			io:format("Proxy ~p received ~p - forwarding~n", [self(), Msg]),
			FabricPid ! {forward, self(), Token, Msg},
			proxy_loop(FabricPid, Token)
		after 1100 ->
			erlang:hibernate(?MODULE, proxy_code_update, [FabricPid, Token])
	end.

proxy_code_update(FabricPid, Token) ->
	proxy_loop(FabricPid, Token).

% return list of atoms which can be used as a destinations of registered send
% important becuase many registered processes are very sensitive, like supervisors,
% init, net_kernel, rpc, file_server, mnesia, etc.
%
% Be aware that clients still can send message to them if they obtain
% pid explicitly in some message.
allowed_registered_names() ->
	[fabric_rpc, simple_server].


remote_whereis(Name) when is_atom(Name) ->
	fabric_rpc({whereis,Name}).

info(Pid) when is_atom(Pid) ->
	fabric_rpc({info,Pid}).
