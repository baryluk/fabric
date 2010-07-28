-module(fabric_example).

% Copyright: Witold Baryluk, 2010
% License: Public Domain

% testing
-export([start/0, start/1, loop/1]).

start() ->
	start(simple_server).

start(Name) ->
	Pid = spawn(fun() -> loop(Name) end),
	register(Name, Pid),
	Pid.

loop(Name) ->
	receive
		{From, Msg} = M ->
			io:format("fabric_example ~p received msg ~p  - ponging~n", [Name, M]),
			From ! {pong, self(), Msg};
		Other ->
			io:format("fabric_example ~p received other msg ~p~n", [Name, Other])
	end,
	?MODULE:loop(Name).
