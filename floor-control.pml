mtype = { req, grant, deny, release, taken, qreq, qinfo, rtp };

chan c = [32] of { byte; byte };

proctype machine (byte id; bool originator; bool makeReq)
{
  byte inId;

start_stop:
  do
    :: (originator == true) ->
      c!grant(id);
      goto has_perm
    :: (originator == false) ->
      if
        :: (makeReq == true) ->
          /* Start T230 */
          /* Start T201 */
          c!req(id);
          goto pend_req
        :: (makeReq == false) ->
          if
            :: c?taken(inId) ->
              /* Start T230 */
              /* Notification: floor taken */
              /* Start T203 */
              goto no_perm
            :: c?grant(inId) ->
              /* Start T230 */
              /* Notification: floor taken */
              /* Start T203 */
              goto no_perm
            :: c?rtp(inId) ->
              /* Start T230 */
              /* Notification: floor taken */
              /* Start T203 */
              goto no_perm
            :: else ->
              /* Start timer T230 */
              goto silence
          fi
      fi
  od;
pend_req:
queued:
silence:
has_perm:
no_perm:
pend_granted:
}
