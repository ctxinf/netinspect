
## HTTP API reference

Use the dashboard origin printed by this session, without external network probes.

- GET /api/session: session metadata, statistics, storage budget and version.
- GET /api/items: paginated combined TCP/DNS records. Query parameters include
  page, size, status, q, sort and direction; consult dashboard behavior
  for accepted values. Use /api/connections and /api/dns for raw snapshots.
- GET /api/connections: TCP connection snapshot.
- GET /api/dns: DNS query snapshot (availability depends on capture mode).
- POST /api/shutdown: requires Authorization: Bearer <TOKEN>.

Example: `curl --silent <DASHBOARD_URL>/api/connections`

## Reproducible invocations

`netinspect run --mode observe --open-browser=false --keep-alive 5m -- python app.py`
`netinspect run --mode preload --memory-mb 64 --open-browser=false -- curl -I https://example.com`
`sudo netinspect run --mode netns --user <USER> --open-browser=false -- <command>`

Keep command arguments as separate argv entries. Avoid reconstructing untrusted
commands as shell strings. Do not guess a session URL or reuse an old control token.
