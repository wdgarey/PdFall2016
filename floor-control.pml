mtype = { req, grant, deny, release, taken, rtp };

int N = 2;
chan channels[N] = [3] of { mtype, byte };

proctype machine (byte myId)
{
  byte inId;
  byte theirId = 1 - myId;

start_stop:
  printf ("%d entered start-stop\n", myId);
  if
    :: channels[theirId]!grant(myId) ->
      goto has_perm;
    :: channels[theirId]!req(myId) ->
      goto pend_req;
    :: channels[myId]?taken(inId) ->
      goto no_perm;
    :: channels[myId]?grant(inId) ->
      goto no_perm;
    :: channels[myId]?rtp(inId) ->
      goto no_perm;
    :: timeout ->
      goto silence;
  fi;
pend_req:
  printf ("%d entered pending request\n", myId);
  do
    :: channels[myId]?rtp(inId) ->
      skip;
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
          skip;
      fi
    :: channels[myId]?taken(inId) ->
      skip;
    :: channels[myId]?req(inId) ->
      skip; // Ignore
    :: channels[myId]?release(inId) ->
      skip; // Ignore
    :: channels[theirId]!release(myId);
      goto silence
    :: channels[theirId]!req(myId) ->
      skip;
    :: channels[theirId]!taken(myId) ->
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
  do
    :: channels[myId]?release(inId) ->
      goto silence;
    :: channels[myId]?grant(inId) ->
      skip;
    :: channels[myId]?rtp(inId)
      skip;
    :: channels[theirId]!req(myId);
      goto pend_req;
    :: channels[myId]?req(inId) ->
      skip;
    :: channels[myId]?deny(inId) ->
      skip;
    :: channels[myId]?taken(inId) ->
      skip;
    :: true ->
      goto silence;
  od;
}

init
{
  run machine (0);
  run machine (1);
}

