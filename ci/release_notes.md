# Improvements

- New `--debug` flag for emitting debugging messages, prefixed by
  `DEBUG> `, to standard error.  Extra-useful for debugging weird
  consul data corruption issues (for real).

- If strongbox detects duplicate service records in consul, there
  is something wrong with the raft data (at least in the case we
  ran into).  This leads to an inability to build a coherent
  picture of the vault(s) seal status(es).  Strongbox now errors
  out when this happens, to save you your sanity.

  (Of course, fixing the underlying corruption in raft data may
  cause more sanity loss; YMMV)
