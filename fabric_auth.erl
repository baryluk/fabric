-module(fabric_auth).

% Copyright: Witold Baryluk, 2010
% License: Public Domain

% for auth
-export([make_challenge/2, make_response/3, is_response_correct/4]).

% auth - simple authentification (based slightly on Joe's lib_chan_auth)

random_string(N) ->
	random_seed(),
	random_string(N, []).

random_string(0, D) -> D;
random_string(N, D) ->
	random_string(N-1, [random:uniform(26)-1+$a | D]).

random_seed() ->
	{_,_,X1} = erlang:now(),
	X = X1 + 1,
	{H,M,S} = time(),
	put(random_seed, {H*X rem 32767, M*X rem 32767, S*X rem 32767}).


shex(0) -> $0;
shex(1) -> $1;
shex(2) -> $2;
shex(3) -> $3;
shex(4) -> $4;
shex(5) -> $5;
shex(6) -> $6;
shex(7) -> $7;
shex(8) -> $8;
shex(9) -> $9;
shex(10) -> $a;
shex(11) -> $b;
shex(12) -> $c;
shex(13) -> $d;
shex(14) -> $e;
shex(15) -> $f.

dhex(D) when D < 256 ->
	[shex(D div 16), shex(D rem 16) ].

md5(X) ->
	MBin = erlang:md5(X),
	{MBin, lists:flatten([ dhex(D) || D <- binary_to_list(MBin) ])}.

make_challenge(_Name, _Secret) ->
	{_Md5_Bin, Md5_Hex} = md5(random_string(32)),
	{Md5_Hex, void}.

make_response(Challenge, _Name, Secret) ->
	{_Md5_Bin, Md5_Hex} = md5(Challenge ++ Secret),
	Md5_Hex.

is_response_correct(Challenge, Name, Response, Secret) when length(Challenge) > 20, length(Response) > 20 ->
	ValidResponse = make_response(Challenge, Name, Secret),
%	io:format("~p~n", [{valid_response, ValidResponse}]),
	case Response of
		ValidResponse -> true;
		_ -> false
	end.
