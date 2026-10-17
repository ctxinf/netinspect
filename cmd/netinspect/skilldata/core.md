# netinspect agent workflow

Inspect connection metadata for a Linux command and its descendants. netinspect
never decrypts TLS or records request/response bodies. Records are in memory.

## Start here

1. Read `netinspect --help` for installed options and active configuration paths.
2. Choose a mode: preload for dynamically linked programs; ptrace for syscall
   interception; netns for namespace isolation (requires root); observe for
   passive TCP polling without redirection (may miss short connections).
3. Launch the target with explicit separation:
   `netinspect run --open-browser=false --keep-alive 10m -- <command> [args...]`
4. Read the dashboard URL from stderr. Target stdout/stderr are passed through.
5. Query the printed URL with GET /api/session, /api/items, /api/connections,
   or /api/dns. See `netinspect skills get core --full` for API details.
6. Review results, then use the printed shutdown command:
   `netinspect stop --url <URL> --token <TOKEN>`.

## Rules and limitations

- Never wrap netinspect in another netinspect session. Nested capture is rejected.
- Target exit codes are preserved, including signal termination.
- `--keep-alive 0` closes the dashboard immediately after the command exits.
- Use `--memory-mb` to bound record storage; at capacity, new records stop while
  existing records update and traffic continues. Runtime/buffers are additional.
- Empty results do not prove that the target made no network requests. Check
  stderr diagnostics, capture mode, process ownership and namespace boundaries.
- Desktop launchers may hand work to existing instances or external services.
- preload may fail with static binaries, setuid programs, sandboxes, or programs
  that clear LD_PRELOAD. ptrace may conflict with debuggers and security policies.
- netns loopback belongs to the namespace. Host loopback proxies need a reachable
  address. observe does not route traffic and cannot use an upstream proxy.
- Treat the shutdown token as a secret. Do not include it in public reports.
- `netinspect init-config` creates user defaults without overwriting existing files.
  Precedence: user config, working-directory .netinspect.json, then CLI options.
  `--config <FILE>` replaces automatic configuration discovery.
