mtype = { req, grant, deny, release, taken, rtp };

chan aToB = [32] of { mtype, byte };
chan bToA = [32] of { mtype, byte };

proctype machineA (byte myId; bool originator; bool makeReq)
{
  byte inId;

start_stop:
  do
    :: (originator == true) ->
      aToB!grant(myId);
      goto has_perm
    :: (originator == false) ->
      if
        :: (makeReq == true) ->
          aToB!req(myId);
          goto pend_req
        :: (makeReq == false) ->
          if
            :: bToA?taken(inId) ->
              goto no_perm
            :: bToA?grant(inId) ->
              goto no_perm
            :: bToA?rtp(inId) ->
              goto no_perm
            :: timeout ->
              goto silence
          fi
      fi
  od;
pend_req:
  do
    :: bToA?rtp(inId) ->
      skip
    :: bToA?deny(inId) ->
      goto no_perm
    :: bToA?grant(inId) ->
      if
        :: (inId == myId) ->
          goto has_perm
        :: (inId != myId) ->
          skip
      fi
    :: bToA?taken(inId)
      skip
    :: timeout ->
      if
        :: (true) ->
          skip
        :: (true) ->
          aToB!release(myId);
          goto silence
        :: (true) -> /* Expiry: T201 */
            aToB!req(myId)
        :: (true) -> /* T201 exired N times */
          aToB!taken(myId);
          goto has_perm
      fi
  od;
silence:
  do
    :: bToA?rtp(inId) ->
      goto no_perm
    :: bToA?grant(inId) ->
      goto no_perm
    :: bToA?taken(inId) ->
      goto no_perm
    :: timeout ->
      if
        :: (true) ->
          skip
        :: (true) ->
          aToB!req(myId);
          goto pend_req
      fi
  od;
has_perm:
  do
    :: (true) ->
      aToB!rtp(myId)
    :: bToA?req(inId) ->
      aToB!deny(inId)
    :: bToA?release(inId) ->
      skip
    :: (true) ->
      aToB!release(myId);
      goto silence
  od;
no_perm:
  do
    :: bToA?release(inId) ->
      goto silence
    :: bToA?grant(inId) ->
      skip
    :: bToA?rtp(inId)
      skip
    :: timeout ->
      if
        :: (true) -> /* Expiry: T203 */
          goto silence
        :: (true) ->
          skip
        :: (true) ->
          aToB!req(myId);
          goto pend_req
      fi
  od;
}

init { run machineA (1, false, true) }

