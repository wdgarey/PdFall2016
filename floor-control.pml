mtype = { req, grant, deny, release, taken, qreq, qinfo };

proctype machine (byte id; bool originator)
{
start_stop:
  do
    :: (originator == true) -> goto has_perm
  od;
pend_req:
queued:
silence:
has_perm:
no_perm:
pend_granted:
}
