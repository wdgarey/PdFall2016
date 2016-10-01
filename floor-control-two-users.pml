mtype = { req, grant, deny, release, taken, rtp };

chan aToB =  of { mtype, byte };
chan bToA =  of { mtype, byte };

proctype machineA (byte myId; bool originator; bool makeReq)
{
  byte inId;

start_stop:
  printf ("%d entered start-stop\n", myId);
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
            :: bToA??taken(inId) ->
              goto no_perm
            :: bToA??grant(inId) ->
              goto no_perm
            :: bToA??rtp(inId) ->
              goto no_perm
            :: timeout ->
              goto silence
          fi
      fi
  od;
pend_req:
  printf ("%d entered pending request\n", myId);
  do
    :: bToA??rtp(inId) ->
      skip
    :: bToA??deny(inId) ->
      goto no_perm
    :: bToA??grant(inId) ->
      if
        :: (inId == myId) ->
          goto has_perm
        :: (inId != myId) ->
          skip
      fi
    :: bToA??taken(inId)
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
  printf ("%d entered silence\n", myId);
  do
    :: bToA??rtp(inId) ->
      goto no_perm
    :: bToA??grant(inId) ->
      goto no_perm
    :: bToA??taken(inId) ->
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
  printf ("%d entered has permission\n", myId);
  do
    :: (true) ->
      aToB!rtp(myId)
    :: bToA??req(inId) ->
      aToB!deny(inId)
    :: bToA??release(inId) ->
      skip
    :: (true) ->
      aToB!release(myId);
      goto silence
  od;
no_perm:
  printf ("%d entered has no permission\n", myId);
  do
    :: bToA??release(inId) ->
      goto silence
    :: bToA??grant(inId) ->
      skip
    :: bToA??rtp(inId)
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

proctype machineB (byte myId; bool originator; bool makeReq)
{
  byte inId;

start_stop:
  printf ("%d entered start-stop\n", myId);
  do
    :: (originator == true) ->
      bToA!grant(myId);
      goto has_perm
    :: (originator == false) ->
      if
        :: (makeReq == true) ->
          bToA!req(myId);
          goto pend_req
        :: (makeReq == false) ->
          if
            :: aToB??taken(inId) ->
              goto no_perm
            :: aToB??grant(inId) ->
              goto no_perm
            :: aToB??rtp(inId) ->
              goto no_perm
            :: timeout ->
              goto silence
          fi
      fi
  od;
pend_req:
  printf ("%d entered pending request\n", myId);
  do
    :: aToB??rtp(inId) ->
      skip
    :: aToB??deny(inId) ->
      goto no_perm
    :: aToB??grant(inId) ->
      if
        :: (inId == myId) ->
          goto has_perm
        :: (inId != myId) ->
          skip
      fi
    :: aToB??taken(inId)
      skip
    :: timeout ->
      if
        :: (true) ->
          skip
        :: (true) ->
          bToA!release(myId);
          goto silence
        :: (true) -> /* Expiry: T201 */
            bToA!req(myId)
        :: (true) -> /* T201 exired N times */
          bToA!taken(myId);
          goto has_perm
      fi
  od;
silence:
  printf ("%d entered silence\n", myId);
  do
    :: aToB??rtp(inId) ->
      goto no_perm
    :: aToB??grant(inId) ->
      goto no_perm
    :: aToB??taken(inId) ->
      goto no_perm
    :: timeout ->
      if
        :: (true) ->
          skip
        :: (true) ->
          bToA!req(myId);
          goto pend_req
      fi
  od;
has_perm:
  printf ("%d entered has permission\n", myId);
  do
    :: (true) ->
      bToA!rtp(myId)
    :: aToB??req(inId) ->
      bToA!deny(inId)
    :: aToB??release(inId) ->
      skip
    :: (true) ->
      bToA!release(myId);
      goto silence
  od;
no_perm:
  printf ("%d entered has no permission\n", myId);
  do
    :: aToB??release(inId) ->
      goto silence
    :: aToB??grant(inId) ->
      skip
    :: aToB??rtp(inId)
      skip
    :: timeout ->
      if
        :: (true) -> /* Expiry: T203 */
          goto silence
        :: (true) ->
          skip
        :: (true) ->
          bToA!req(myId);
          goto pend_req
      fi
  od;
}

init
{
  run machineA (1, true, false);
  run machineB (2, false, false)
}

