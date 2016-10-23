mtype = { req, grant, deny, release, taken, rtp };

int N = 2;
int callTime = 0;
int callLimit = 50;
chan channels[N] = [3] of { mtype, byte };

proctype call ()
{
  do
    :: (callTime < callLimit) ->
      callTime = callTime + 1
    :: (callTime >= callLimit) ->
      break;
  od;
  printf ("Call terminated\n");
}

proctype machine (byte myId)
{
  byte inId;
  byte theirId = 1 - myId;

start_stop:
  printf ("%d entered 'Start-Stop'\n", myId);
  if
    :: (callTime < callLimit) ->
      skip;
    :: (callTime >= callLimit) ->
      goto done;
  fi;
  do
    :: (myId == 0) ->
      channels[theirId]!grant(myId);
      goto has_perm; /* Call originator */
    :: goto silence;
    :: channels[theirId]!req(myId) ->
      goto pend_req; /* PTT button pushed */
    :: channels[myId]?taken(inId) ->
      goto no_perm;
    :: channels[myId]?grant(inId) ->
      goto no_perm;
    :: channels[myId]?rtp(inId) ->
      goto no_perm;
    :: channels[myId]?req ->
      skip /* Ignore message */
    :: channels[myId]?deny ->
      skip /* Ignore message */
    :: channels[myId]?release ->
      skip /* Ignore message */
  od;
silence:
  printf ("%d entered 'O: silence'\n", myId);
  do
    :: channels[theirId]!req(myId);
      goto pend_req; /* PTT button pushed */
    :: channels[myId]?rtp(inId) ->
      goto no_perm;
    :: channels[myId]?grant(inId) ->
      goto no_perm;
    :: channels[myId]?taken(inId) ->
      goto no_perm;
    :: channels[myId]?req(inId) ->
      skip; /* Ignore message */
    :: channels[myId]?deny(inId) ->
      skip; /* Ignore message */
    :: channels[myId]?release(inId) ->
      skip; /* Ignore message */
    :: (callTime >= callLimit) -> 
      goto start_stop; /* Call terminated */
  od;
no_perm:
  printf ("%d entered 'O: has no permission'\n", myId);
  do
    :: channels[theirId]!req(myId);
      goto pend_req; /* PTT button pushed */
    :: channels[myId]?release(inId) ->
      goto silence;
    :: goto silence; /* Timer T203 expired */
    :: channels[myId]?grant(inId) ->
      skip;
    :: channels[myId]?rtp(inId) ->
      skip;
    :: channels[myId]?req(inId) ->
      skip; /* Ignore message */
    :: channels[myId]?deny(inId) ->
      skip; /* Ignore message */
    :: channels[myId]?taken(inId) ->
      skip; /* Ignore message */
    :: (callTime >= callLimit) -> 
      goto start_stop; /* Call terminated */
  od;
has_perm:
  printf ("%d entered 'O: has permission'\n", myId);
  channels[theirId]!rtp(myId);
  do
    :: channels[theirId]!rtp(myId);
    :: channels[myId]?release(inId) ->
      skip; /* Ignore message */
    :: channels[myId]?req(inId) ->
      if
        :: channels[theirId]!deny(inId);
        :: channels[theirId]!grant(inId);
          goto pend_grant;
      fi
    :: channels[theirId]!release(myId);
      goto silence; /* PTT button released */
    :: channels[myId]?grant(inId) ->
      assert (false); /* Implies multiple arbitrators */
    :: channels[myId]?deny(inId) ->
      assert (false); /* Implies multiple arbitrators */
    :: channels[myId]?taken(inId) ->
      assert (false); /* Implies multiple arbitrators */
    :: channels[myId]?rtp(inId) ->
      assert (false); /* Implies multiple arbitrators */
    :: (callTime >= callLimit) -> 
      goto start_stop; /* Call terminated */
  od;
pend_req:
  printf ("%d entered 'O: pending request'\n", myId);
  do
    :: channels[myId]?rtp(inId) ->
      skip;
    :: channels[myId]?deny(inId) ->
      if
        :: (inId == myId) ->
          goto no_perm;
        :: (inId != myId) ->
          skip;
      fi;
    :: channels[theirId]!release(myId);
      goto silence; /* PTT button released */
    :: channels[theirId]!taken(myId) ->
      goto has_perm; /* T201 expired N times */
    :: channels[myId]?grant(inId) ->
      if
        :: (inId == myId) ->
          goto has_perm;
        :: (inId != myId) ->
          skip;
      fi;
    :: channels[theirId]!req(myId) ->
      skip; /* T201 expired */
    :: channels[myId]?taken(inId) ->
      skip;
    :: channels[myId]?req(inId) ->
      skip; /* Ignore message */ 
    :: channels[myId]?release(inId) ->
      skip; /* Ignore message */
    :: (callTime >= callLimit) -> 
      goto start_stop; /* Call terminated */
  od;
pend_grant:
  printf ("%d entered 'O: pending granted'\n", myId);
  do
    :: channels[myId]?rtp(inId) ->
      goto no_perm; /* Floor passed */
    :: channels[theirId]!grant(theirId); /* T205 expired */
    :: channels[theirId]!release(myId) ->
      goto silence; /* T205 expired N times */
    :: channels[myId]?release(inId) ->
      skip; /* Ignore message */
    :: channels[myId]?req(inId) ->
      channels[theirId]!deny(inId);
    :: channels[myId]?deny(inId) ->
      assert (false); /* Implies multiple arbitrators */
    :: channels[myId]?grant(inId) ->
      assert (false); /* Implies multiple arbitrators */
    :: channels[myId]?taken(inId) ->
      assert (false); /* Implies multiple arbitrators */
    :: (callTime >= callLimit) -> 
      goto start_stop; /* Call terminated */
  od;
done:
  skip;
}

init
{
  run call ();
  run machine (0);
  run machine (1);
}

