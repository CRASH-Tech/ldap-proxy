# ldap-proxy

A lightweight LDAP proxy written in Go. It sits in front of an upstream LDAP
server, transparently forwarding **bind** and **search** requests while adding:

- **Query rewriting** — rewrites `sudo`-style group lookups so that existing
  LDAP/`sudo-ldap` clients work against a standard directory (see
  [Query rewriting](#query-rewriting)).
- **Response caching** — caches search results for a configurable TTL to reduce
  load on the upstream server (see [Caching](#caching)).
- **Bind caching / connection reuse** — keeps authenticated upstream
  connections alive and reuses them across client connections, so repeat logins
  with the same credentials skip the upstream dial+bind (see
  [Bind caching](#bind-caching)).
- **Connection pooling** — reuses a bounded pool of upstream connections keyed
  per client connection.
- **Rate limiting & abuse protection** — per-IP request rate limiting and a
  per-IP concurrent-connection cap.
- **Optional TLS** (LDAPS) termination.

## How it works

```
LDAP client ──▶ ldap-proxy ──▶ upstream LDAP server
                   │
                   ├─ per-IP rate limit / connection cap
                   ├─ session pool (bounded, LRU-evicted)
                   ├─ query rewriting (sudoUser → member)
                   ├─ bind cache + authenticated connection pool (TTL)
                   └─ search response cache (TTL)
```

For each incoming client connection the proxy uses (and reuses) a connection to
the upstream server. Bind requests reuse a pooled authenticated connection when
one is available for the same credentials, otherwise they are forwarded and the
resulting connection is pooled. Search requests are optionally rewritten, served
from cache when possible, and otherwise forwarded upstream (the result is then
cached).

> **Note:** The proxy always issues the upstream search with
> `ScopeWholeSubtree`, regardless of the scope requested by the client.

## Configuration

All configuration is supplied via environment variables. **Required** variables
must be set or the process exits on startup.

| Variable           | Required | Default | Description |
| ------------------ | :------: | ------- | ----------- |
| `LDAP_SERVER`      | ✅       | —       | Upstream LDAP server address, `host:port` (e.g. `ldap.example.com:389`). |
| `LISTEN`           | ✅       | —       | Address the proxy listens on, `host:port` (e.g. `0.0.0.0:389`). |
| `USERS_DN`         | ✅       | —       | Base DN for users, used when rewriting `sudoUser` filters (e.g. `ou=users,dc=example,dc=com`). |
| `USE_TLS`          |          | `false` | Serve LDAPS (TLS). When `true`, `CERT_FILE` and `CERT_KEY_FILE` are required. |
| `CERT_FILE`        |          | —       | Path to the TLS certificate (PEM). Used only when `USE_TLS=true`. |
| `CERT_KEY_FILE`    |          | —       | Path to the TLS private key (PEM). Used only when `USE_TLS=true`. |
| `MAX_SESSIONS`     |          | `100`   | Maximum number of pooled upstream connections. The oldest is evicted (LRU) when the limit is reached. |
| `MAX_CONNS_PER_IP` |          | `10`    | Maximum concurrent client connections from a single IP. |
| `MAX_RPS_PER_IP`   |          | `1`     | Maximum requests per second per IP (token-bucket, burst = this value). |
| `CONN_TIMEOUT`     |          | `60s`   | Client connection deadline, as a Go duration (e.g. `30s`, `2m`). |
| `CACHE_TTL`        |          | `5m`    | TTL for both the search response cache and the bind cache / connection pool, as a Go duration. Set to `0` to disable caching and connection reuse. |

Duration values use Go's [`time.ParseDuration`](https://pkg.go.dev/time#ParseDuration)
syntax (`300ms`, `10s`, `5m`, `1h`, …). A **unit is required**: a bare number is
interpreted as a whole number of **seconds** (so `CACHE_TTL=1` means `1s`), and
a value that is neither a valid duration nor an integer makes the proxy exit on
startup rather than silently falling back to the default.

### Caching

Search responses are cached in memory to reduce load on the upstream server.

- The TTL is controlled by `CACHE_TTL` (default **5 minutes**).
- Set `CACHE_TTL=0` to **disable** caching entirely.
- The cache key is derived from the **bound DN**, base DN, the (rewritten)
  filter, the requested scope, and the requested attribute set (attribute order
  does not matter). Including the bound DN ensures results are never shared
  between different authenticated identities.
- Expired entries are evicted lazily on access and by a background janitor, so
  the cache does not grow without bound.

The cache key is derived only from the query (base DN, rewritten filter, scope
and requested attributes) and is **not** scoped to the bound identity, so
identical queries from different clients share a cache entry. This assumes the
queried attributes are readable independently of who is bound, which holds for
this proxy's use cases (e.g. group/sudo lookups).

Cache hits are logged as `P: Search CACHE HIT: ...`.

### Bind caching

To reduce the cost of authentication-heavy workloads — where clients open a new
connection, bind and search on nearly every operation — the proxy keeps a pool
of **already-authenticated upstream connections**, keyed by credentials:

- When a client binds, a pooled connection for the **same credentials** is
  reused if available, skipping the upstream dial+bind entirely. On close, the
  authenticated connection is returned to the pool instead of being torn down.
- Reuse is bounded by `CACHE_TTL` measured from the moment the connection was
  **actually authenticated** against the upstream. This timestamp is preserved
  across reuse and never refreshed, so a connection is retired — and the client
  re-validated upstream on its next login — at most `CACHE_TTL` after its real
  bind, **even under constant load**. Connections past the TTL are never reused
  and are closed by the background janitor. Setting `CACHE_TTL=0` disables this
  along with response caching, restoring the original dial+bind-per-request
  behaviour.
- Credentials are keyed by a salted-in SHA-256 of the bind DN **and** password,
  so a pooled connection is only ever reused by a client that presents the exact
  same credentials — reuse never bypasses authentication. Passwords are not
  stored in plaintext and are never logged.
- Up to `MAX_CONNS_PER_IP` idle connections are pooled per distinct credential.

Because reused connections were already validated by the upstream, a password
that changes upstream may keep being accepted for up to `CACHE_TTL`. Lower or
zero `CACHE_TTL` if that staleness window is unacceptable in your environment.

Bind cache hits are logged as `P: Bind CACHE HIT ...`.

### Query rewriting

When a search filter contains both `objectClass=group` and `sudoUser=<name>`,
each `sudoUser=<name>` term is rewritten to
`member=cn=<name>,${USERS_DN}`. This lets `sudo`'s LDAP integration resolve a
user's sudo rules via standard group membership.

Example (`USERS_DN=ou=users,dc=example,dc=com`):

```
(&(objectClass=group)(sudoUser=jdoe))
        ⇓
(&(objectClass=group)(member=cn=jdoe,ou=users,dc=example,dc=com))
```

## Running

### Docker

```sh
docker run -d --name ldap-proxy \
  -p 389:389 \
  -e LDAP_SERVER=ldap.example.com:389 \
  -e LISTEN=0.0.0.0:389 \
  -e USERS_DN=ou=users,dc=example,dc=com \
  -e CACHE_TTL=5m \
  crashntech/ldap-proxy:latest
```

Images are published to Docker Hub as `crashntech/ldap-proxy` on each GitHub
release.

### From source

```sh
go build -o ldap-proxy .

LDAP_SERVER=ldap.example.com:389 \
LISTEN=0.0.0.0:389 \
USERS_DN=ou=users,dc=example,dc=com \
./ldap-proxy
```

Requires Go 1.23+.

## Development

```sh
go build ./...   # build
go test ./...    # run tests
go vet ./...     # static checks
```

## Project layout

| Path                    | Description |
| ----------------------- | ----------- |
| `main.go`               | Entry point: loads config and starts the proxy. |
| `cmd/config/config.go`  | Environment-variable configuration loading. |
| `cmd/proxy/proxy.go`    | LDAP server setup and lifecycle. |
| `cmd/proxy/handlers.go` | Bind/Search/Close handlers, session pool, rate limiting. |
| `cmd/proxy/cache.go`    | In-memory TTL cache for search responses. |
| `cmd/proxy/bindcache.go`| Authenticated upstream connection pool (bind reuse). |

## License

See [LICENSE](LICENSE).
