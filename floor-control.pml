mtype = { req, grant, deny, release, taken, rtp };

chan c = [32] of { byte; byte };

proctype machine (byte myId; bool originator; bool makeReq)
{
  byte inId;

start_stop:
  do
    :: (originator == true) ->
      c!grant(myId);
      goto has_perm
    :: (originator == false) ->
      if
        :: (makeReq == true) ->
          /* Start: T230 */
          /* Start: T201 */
          c!req(myId);
          goto pend_req
        :: (makeReq == false) ->
          if
            :: c?taken(inId) ->
              /* Start: T230 */
              /* Notify: floor taken */
              /* Start: T203 */
              goto no_perm
            :: c?grant(inId) ->
              /* Start: T230 */
              /* Notify: floor taken */
              /* Start: T203 */
              goto no_perm
            :: c?rtp(inId) ->
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
silence:
  do
    :: c?rtp(inId) ->
      /* Restart: T230 */
      /* Restart: T203 */
      goto no_perm
    :: c?grant(inId) ->
      /* Notify: floor taken */
      /* Start: T203 */
      goto no_perm
    :: c?taken(inId) ->
      /* Notify: floor taken */
      /* Start: T203 */
      goto no_perm
    :: else
      if
        :: (true) ->
          skip
        :: (true) ->
          /* Start: T201 */
          c!req(myId);
          goto pend_req
      fi
  od;
has_perm:
  do
    :: (true) ->
      c!rtp(id)
    :: c?req(inId) ->
      c!deny(inId)
    :: (true) ->
      /* Start: T230 */
      c!release(myId);
      goto silence
  od;
no_perm:
  do
    :: c?release(inId) ->
      /* Stop: T203 */
      /* Notify: floor idle */
      goto silence
    :: c?grant(inId) ->
      /* Restart: T203 */
      /* Notify: floor taken */
      skip
    :: c?rtp(inId)
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
          c!req(myId);
          goto pend_req
      fi
  od;
pend_granted:
}
