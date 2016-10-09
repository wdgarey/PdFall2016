mtype = { req, grant, deny, release, taken, rtp };

int N = 2;
chan channels[N] = [0] of { mtype, byte };

proctype machine (byte myId; bool originator; bool makeReq)
{
  byte inId;
  byte c201;
  byte c203;
  byte theirId = 1 - myId;

start_stop:
  printf ("%d entered start-stop\n", myId);
  if
    :: (originator == true) ->
      channels[theirId]!grant(myId);
      goto has_perm;
    :: (originator == false) ->
      if
        :: (makeReq == true) ->
          channels[theirId]!req(myId);
          goto pend_req;
        :: (makeReq == false) ->
          if
            :: channels[myId]?taken(inId) ->
              goto no_perm;
            :: channels[myId]?grant(inId) ->
              goto no_perm;
            :: channels[myId]?rtp(inId) ->
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
    :: channels[myId]?rtp(inId) ->
      c201 = 1;
    :: channels[myId]?deny(inId) ->
      if
        :: (inId == myId) ->
          goto no_perm;
        :: (inId != myId) ->
          skip;
      fi
    :: channels[myId]?grant(inId) ->
      if
        :: (inId == myId) ->
          goto has_perm;
        :: (inId != myId) ->
          c201 = 1;
      fi
    :: channels[myId]?taken(inId)
      c201 = 1;
    :: channels[myId]?req(inId) ->
      skip; // Ignore
    :: channels[myId]?release(inId) ->
      skip; // Ignore
    :: channels[theirId]!release(myId);
      goto silence
    :: (c201 < 3) -> /* Expiry: T201 */
        c201 = c201 + 1;
        channels[theirId]!req(myId);
    :: (c201 >= 3) -> /* T201 exired N times */
      channels[theirId]!taken(myId);
      goto has_perm;
  od;
silence:
  printf ("%d entered silence\n", myId);
  do
    :: channels[myId]?rtp(inId) ->
      goto no_perm;
    :: channels[myId]?grant(inId) ->
      goto no_perm;
    :: channels[myId]?taken(inId) ->
      goto no_perm;
    :: channels[myId]?req(inId) ->
      skip; /* Ignore message. */
    :: channels[myId]?deny(inId) ->
      skip; /* Ignore message. */
    :: channels[myId]?release(inId) ->
      skip; /* Ignore message. */
    :: skip;
    :: channels[theirId]!req(myId);
      goto pend_req;
  od;
has_perm:
  printf ("%d entered has permission\n", myId);
  do
    :: channels[theirId]!rtp(myId);
    :: channels[myId]?req(inId) ->
      channels[theirId]!deny(inId);
    :: channels[myId]?release(inId) ->
      skip; /* Remove from queue. */
    :: channels[theirId]!release(myId);
      goto silence;
    :: channels[myId]?grant(inId) ->
      assert (false); /* No one else should have the floor. */
    :: channels[myId]?deny(inId) ->
      assert (false); /* No one else should have the floor. */
    :: channels[myId]?taken(inId) ->
      assert (false); /* No one else should have the floor. */
    :: channels[myId]?rtp(inId) ->
      assert (false); /* No one else should have the floor. */
  od;
no_perm:
  printf ("%d entered has no permission\n", myId);
  c203 = 1;
  do
    :: channels[myId]?release(inId) ->
      goto silence;
    :: channels[myId]?grant(inId) ->
      c203 = 1;
    :: channels[myId]?rtp(inId)
      c203 = 1;
    :: channels[theirId]!req(myId);
      goto pend_req;
    :: channels[myId]?req(inId) ->
      skip;
    :: channels[myId]?deny(inId) ->
      skip;
    :: channels[myId]?taken(inId) ->
      skip;
    :: (c203 >= 3) ->
      goto silence;
    :: (c203 < 3) ->
      c203 = c203 + 1;
  od;
}


init
{
  run machine (0, true, false);
  run machine (1, false, false);
}

