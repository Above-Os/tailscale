# tailscale-ffi

Windows C-shared library (FFI) for Tailscale/LarePass, used by other languages or native apps to call into the client.

## Build (Windows, amd64, cgo)

```batch
set GOOS=windows
set GOARCH=amd64
set CGO_ENABLED=1
go build -v -buildmode=c-shared -o tailscale-ffi.dll ./cmd/tailscale-ffi
```

This produces `tailscale-ffi.dll` and `tailscale-ffi.h`. The package is Windows + CGO only; building elsewhere (or with `CGO_ENABLED=0`) fails on purpose.

## Exported C API

| Symbol                                                    | Purpose                                                                                      |
| --------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `RunWithArgs(argstr *char)`                               | Run CLI; `argstr` is space-separated args (no `tailscale` prefix); empty string on success, else error message. |
| `SetExitNode(ipStr *char)`                                | Set exit node IP; empty string clears.                                                       |
| `SetExitNodeAllowLANAccess(allow bool)`                   | Enable or disable exit node LAN access.                                                      |
| `WatchIPN(initial bool, callback Callback)`               | Subscribe to IPN notifications; callback receives JSON (copied during callback; freed in Go). |
| `FreeCString(s *char)`                                    | Free a string returned by exports that use `*C.char` (call after copying in the host).        |
| `StartVpnAsync` / `LogoutAsync` / `TailscalePingAsync`    | Async VPN/ping; `StartVpnAsync` always uses `--force-reauth` semantics (see `startVpn`). Dropped queued `start` jobs get `done("cancelled")`. |
| `SetCookie(cookiestr *char)`                              | Set dev store key `Cookie` (for control auth).                                               |
| `GetPrefs()`                                              | Return current prefs as JSON string.                                                         |
| `GetStatus()`                                             | Return current status as JSON string.                                                        |
| `GetNetcheck()`                                           | Run netcheck and return report as JSON.                                                      |
| `TailscalePing(ipStr *char, timeout int)`                 | Ping a Tailscale IP; timeout in seconds; returns JSON result.                                |

The client uses `paths.DefaultTailscaledSocket()` so it talks to the same daemon (LarePass pipe) as the rest of the build.

### CString memory

- **Callbacks** (`WatchIPN`, async `done`): Go copies JSON/error into a temporary `C.CString`, invokes the callback, then `free`s it. The host must treat the pointer as valid only inside the callback.
- **Return values** (`GetPrefs`, `SetExitNode`, `errorCString`, etc.): allocated with `C.CString`; the caller must free after copy. With ffi-rs, use `ffi-cstring.js` (`External` → `wrapPointer` → `restorePointer` → `FreeCString`).
