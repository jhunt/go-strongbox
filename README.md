strongbox
=========

Strongbox is a small add-on for [Vault][vault] and [safe][safe]
that aims to make it easier for safe to reason about the
reachability of backend Vault nodes, given their seal-status,
without having to expose something like consul to the outside
world.

The API
-------

The API is dead simple.

### GET /strongbox

```
{
  "https://10.244.4.2": "unsealed",
  "https://10.244.4.3": "sealed",
  "https://10.244.4.4": "sealed"
}
```

That's it.  That's all there is too it.  In a nutshell,
`strongbox` takes the specifications _from_ the consul, and
delivers them _to_ the safe CLI.

Configuration is likewise simple:

```
strongbox \
  --bind   0.0.0.0:8180 \
  --consul https://127.0.0.1:8500 \
  --no-verify \
  --ca-cert /path/to/ca.pem
```

[vault]: https://vaultproject.io
[safe]:  https://github.com/starkandwayne/safe
