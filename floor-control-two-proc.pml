mtype = { req, grant, deny, release, taken, rtp };

chan aToB = [0]  of { mtype, byte };
chan bToA =  [0] of { mtype, byte };

proctype machineA (byte myId; bool originator; bool makeReq)
{
  byte inId;
  byte c201;
  byte c203;

start_stop:
  printf ("%d entered start-stop\n", myId);
  if
    :: (originator == true) ->
      aToB!grant(myId);
      goto has_perm;
    :: (originator == false) ->
      if
        :: (makeReq == true) ->
          aToB!req(myId);
          goto pend_req;
        :: (makeReq == false) ->
          if
            :: bToA?taken(inId) ->
              goto no_perm;
            :: bToA?grant(inId) ->
              goto no_perm;
            :: bToA?rtp(inId) ->
              goto no_perm;
            :: timeout ->
              goto silence;
          fi;
      fi;
  fi;
pend_req:
  printf ("%d entered pending request\n", myId);
  c201 = 1;
  do
    :: bToA?rtp(inId) ->
      c201 = 1;
    :: bToA?deny(inId) ->
      if
        :: (inId == myId) ->
          goto no_perm;
        :: (inId != myId) ->
          skip;
      fi
    :: bToA?grant(inId) ->
      if
        :: (inId == myId) ->
          goto has_perm;
        :: (inId != myId) ->
          c201 = 1;
      fi
    :: bToA?taken(inId)
      c201 = 1;
    :: bToA?req(inId) ->
      skip; // Ignore
    :: bToA?release(inId) ->
      skip; // Ignore
    :: aToB!release(myId);
      goto silence
    :: (c201 < 3) -> /* Expiry: T201 */
        aToB!req(myId);
        c201 = c201 + 1;
    :: (c201 == 3) -> /* T201 exired N times */
      aToB!taken(myId);
      goto has_perm;
  od;
silence:
  printf ("%d entered silence\n", myId);
  do
    :: bToA?rtp(inId) ->
      goto no_perm;
    :: bToA?grant(inId) ->
      goto no_perm;
    :: bToA?taken(inId) ->
      goto no_perm;
    :: bToA?req(inId) ->
      skip; /* Ignore message. */
    :: bToA?deny(inId) ->
      skip; /* Ignore message. */
    :: bToA?release(inId) ->
      skip; /* Ignore message. */
    :: skip;/* Ignore message. */
    :: aToB!req(myId);
      goto pend_req;
  od;
has_perm:
  printf ("%d entered has permission\n", myId);
  do
    :: aToB!rtp(myId);
    :: bToA?req(inId) ->
      aToB!deny(inId);
    :: bToA?release(inId) ->
      skip; /* Remove from queue. */
    :: aToB!release(myId);
      goto silence;
    :: bToA?grant(inId) ->
      assert (false); /* No one else should have the floor. */
    :: bToA?deny(inId) ->
      assert (false); /* No one else should have the floor. */
    :: bToA?taken(inId) ->
      assert (false); /* No one else should have the floor. */
    :: bToA?rtp(inId) ->
      assert (false); /* No one else should have the floor. */
  od;
no_perm:
  printf ("%d entered has no permission\n", myId);
  c203 = 1;
  do
    :: bToA?release(inId) ->
      goto silence;
    :: bToA?grant(inId) ->
      c203 = 1;
    :: bToA?rtp(inId)
      c203 = 1;
    :: (c203 == 3) ->
      goto silence;
    :: c203 = c203 + 1;
    :: aToB!req(myId);
      goto pend_req;
    :: bToA?req(inId) ->
      skip;
    :: bToA?deny(inId) ->
      skip;
    :: bToA?taken(inId) ->
      skip;
  od;
}

proctype machineB (byte myId; bool originator; bool makeReq)
{
  byte inId;
  byte c201;
  byte c203;

start_stop:
  printf ("%d entered start-stop\n", myId);
  if
    :: (originator == true) ->
      bToA!grant(myId);
      goto has_perm;
    :: (originator == false) ->
      if
        :: (makeReq == true) ->
          bToA!req(myId);
          goto pend_req;
        :: (makeReq == false) ->
          if
            :: aToB?taken(inId) ->
              goto no_perm;
            :: aToB?grant(inId) ->
              goto no_perm;
            :: aToB?rtp(inId) ->
              goto no_perm;
            :: timeout ->
              goto silence;
          fi
      fi
  fi;
pend_req:
  printf ("%d entered pending request\n", myId);
  c201 = 1;
  do
    :: aToB?rtp(inId) ->
      c201 = 1;
    :: aToB?deny(inId) ->
      if
        :: (inId == myId) ->
          goto no_perm;
        :: (inId != myId) ->
          skip;
      fi
    :: aToB?grant(inId) ->
      if
        :: (inId == myId) ->
          goto has_perm;
        :: (inId != myId) ->
          c201 = 1;
      fi;
    :: aToB?taken(inId)
      c201 = 1;
    :: aToB?req(inId) ->
      skip; // Ignore
    :: aToB?release(inId) ->
      skip; // Ignore
    :: bToA!release(myId);
      goto silence;
    :: (c201 < 3) -> /* Expiry: T201 */
      bToA!req(myId);
      c201 = c201 + 1;
    :: (c201 == 3) -> /* T201 exired N times */
      bToA!taken(myId);
      goto has_perm;
  od;
silence:
  printf ("%d entered silence\n", myId);
  do
    :: aToB?rtp(inId) ->
      goto no_perm;
    :: aToB?grant(inId) ->
      goto no_perm;
    :: aToB?taken(inId) ->
      goto no_perm;
    :: aToB?req(inId) ->
      skip; /* Ignore message. */
    :: aToB?deny(inId) ->
      skip; /* Ignore message. */
    :: aToB?release(inId) ->
      skip; /* Ignore message. */
    :: skip;
    :: bToA!req(myId);
      goto pend_req;
  od;
has_perm:
  printf ("%d entered has permission\n", myId);
  do
    :: bToA!rtp(myId);
    :: aToB?req(inId) ->
      bToA!deny(inId);
    :: aToB?release(inId) ->
      skip; /* Remove from queue. */
    :: bToA!release(myId);
      goto silence;
    :: aToB?grant(inId) ->
      assert (false); /* No one else should have the floor. */
    :: aToB?deny(inId) ->
      assert (false); /* No one else should have the floor. */
    :: aToB?taken(inId) ->
      assert (false); /* No one else should have the floor. */
    :: aToB?rtp(inId) ->
      assert (false); /* No one else should have the floor. */
  od;
no_perm:
  printf ("%d entered has no permission\n", myId);
  c203 = 1;
  do
    :: aToB?release(inId) ->
      goto silence;
    :: aToB?grant(inId) ->
      c203 = 1;
    :: aToB?rtp(inId)
      c203 = 1;
    :: (c203 == 3) ->
      goto silence;
    :: c203 = c203 + 1;
    :: bToA!req(myId);
      goto pend_req;
    :: aToB?req(inId) ->
      skip;
    :: aToB?deny(inId) ->
      skip;
    :: aToB?taken(inId) ->
      skip;
  od;
}

init
{
  run machineA (1, true, false);
  run machineB (2, false, false)
}

