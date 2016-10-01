mtype = { req, grant, deny, release, taken, rtp };

chan aToB = [32] of { mtype, byte };
chan bToA = [32] of { mtype, byte );

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
          /* Start: T230 */
          /* Start: T201 */
          aToB!req(myId);
          goto pend_req
        :: (makeReq == false) ->
          if
            :: bToA?taken(inId) ->
              /* Start: T230 */
              /* Notify: floor taken */
              /* Start: T203 */
              goto no_perm
            :: bToA?grant(inId) ->
              /* Start: T230 */
              /* Notify: floor taken */
              /* Start: T203 */
              goto no_perm
            :: bToA?rtp(inId) ->
              /* Start: T230 */
              /* Notify: floor taken */
              /* Start: T203 */
              goto no_perm
            :: else ->
              /* Start timer: T230 */
              goto silence
          fi
      fi
  od;
pend_req:
  do
    :: bToA?rtp(inId) ->
      /* Reset: C201 */
      /* Restart: T230 */
      /* Restart: T203 */
      skip
    :: bToA?deny(inId) ->
      /* Stop: T201 */
      /* Notify: floor deny */
      goto no_perm
    :: bToA?granted(inId) ->
      if
        :: (inId == myId) ->
          /* Stop: T203 */
          /* Stop: T201 */
          /* Stop: T230 */
          /* Notify: floor granted */
          goto has_perm
        :: (inId != myId) ->
          /* Reset: C201 */
          /* Restart: T203 */
          /* Restart: T201 */
          /* Notify: floor taken */
          skip
      fi
    :: bToA?taken(inId)
      /* Reset: C201 */
      /* Restart: T201 */
      skip
    :: else ->
      if
        :: (true) ->
          skip
        :: (true) ->
          /* Stop: T201 */
          aToB!release(myId);
          goto silence
        :: (true -> /* Expiry: T201 */
            /* Restart: T201 */
            aToB!req(myId)
        :: (true) -> /* T201 exired N times */
          /* Stop: T203 */
          /* Stop: T230 */
          aToB!taken(myId);
          goto has_perm
      fi
  od;
silence:
  do
    :: bToA?rtp(inId) ->
      /* Restart: T230 */
      /* Restart: T203 */
      goto no_perm
    :: bToA?grant(inId) ->
      /* Notify: floor taken */
      /* Start: T203 */
      goto no_perm
    :: bToA?taken(inId) ->
      /* Notify: floor taken */
      /* Start: T203 */
      goto no_perm
    :: else
      if
        :: (true) ->
          skip
        :: (true) ->
          /* Start: T201 */
          aToB!req(myId);
          goto pend_req
      fi
  od;
has_perm:
  do
    :: (true) ->
      aToB!rtp(id)
    :: bToA?req(inId) ->
      aToB!deny(inId)
    :: bToA?release(inId ->
      skip
    :: (true) ->
      /* Start: T230 */
      aToB!release(myId);
      goto silence
  od;
no_perm:
  do
    :: bToA?release(inId) ->
      /* Stop: T203 */
      /* Notify: floor idle */
      goto silence
    :: bToA?grant(inId) ->
      /* Restart: T203 */
      /* Notify: floor taken */
      skip
    :: bToA?rtp(inId)
      /* Restart: T230 */
      /* Restart: T203 */
      skip
    :: else ->
      fi
        :: (true) -> /* Expiry: T203 */
          /* Notify: floor idle */
          goto silence
        :: (true) ->
          skip
        :: (true) ->
          /* Start: T201 */
          aToB!req(myId);
          goto pend_req
      fi
  od;
}
