# Frida + Objection Integration Plan

Both tools target the same iOS runtime; we treat them as complementary:

- **Frida** for surgical hooks (one class, one method, custom JS, custom message protocol back to our store).
- **Objection** for fast, idiomatic recon (env, plist, frameworks, keychain, pinning surface) — wraps Frida under the hood, but gives us proven commands without writing JS.

We use both. Objection runs first during Bootstrap for breadth. Frida runs throughout for depth. They emit into the same `runs/<id>/frida_events.jsonl` (Objection wraps its output into the same schema).

## Frida side

### Connection model

Jailbroken-first: `frida-server` over USB. We use `frida.get_usb_device()` and `frida.spawn(bundle_id, gating=True)` so the planner can install hooks before any user code runs.

Non-JB Gadget paths exist as stubs in `frida_layer/non_jb/` but aren't part of the default flow.

### Hook library — `frida_layer/hooks/`

Each hook is a self-contained `.js` file. They share a common message envelope:

```js
function emit(event) {
  send({
    kind: 'frida.event',
    ts: Date.now() / 1000,
    pid: Process.id,
    cls: event.cls,
    method: event.method,
    args: event.args,
    ret: event.ret,
    thread_id: event.thread_id || (Process.getCurrentThreadId && Process.getCurrentThreadId()),
    stack: event.stack || []
  });
}
```

The Python runner pumps these messages straight into `FridaEvent` rows.

| Hook | Targets | Emits |
|---|---|---|
| `url_session_tracer.js` | `NSURLSession`, `NSURLSessionDataTask`, `WKWebView`, `NSURLConnection` (legacy) | request URL, headers, body preview, response status, body preview |
| `ssl_pinning_bypass.js` | `SecTrustEvaluate`, `SecTrustEvaluateWithError`, AFNetworking pinning, TrustKit, `NSURLSession:didReceiveChallenge:` | each bypassed callsite logged as `event.kind = "pinning_bypass"` |
| `keychain_dump.js` | `SecItemCopyMatching` + bulk dump on attach | every keychain entry the app could read |
| `jailbreak_bypass.js` | `fileExistsAtPath:`, `canOpenURL:`, `fork`, `sysctl`, common detection routines | each bypassed check |
| `commoncrypto_tracer.js` | `CCHmac*`, `CCCryptorCreate`, `CCCryptorUpdate`, `CCCryptorFinal` | algo, key (preview), input preview, output preview — for signature inference in `finder.py` |
| `cffi_arg_tracer.js` | configurable list of `(class, method)` — populated by `auto_hook.py` | every call with serialized args |
| `wkwebview_js_tracer.js` | `WKWebView.evaluateJavaScript:` | the JS being executed |
| `pasteboard_tracer.js` | `UIPasteboard.generalPasteboard` reads/writes | data + types |
| `biometrics_tracer.js` | `LAContext.evaluatePolicy:` | policy + reply |

### Auto-hook decision logic — `frida_layer/auto_hook.py`

On attach:

1. Enumerate `ObjC.classes` via a meta-hook.
2. Check for marker classes:
   - `URLSession*` / `NSURLSession` → load `url_session_tracer.js`.
   - `AFHTTPSessionManager` → load `ssl_pinning_bypass.js`'s AFNetworking branch.
   - `WKWebView` → load `wkwebview_js_tracer.js`.
   - `LAContext` → load `biometrics_tracer.js`.
   - Anything matching `*Pinning*` / `*Cert*Validator*` → bias toward SSL pinning bypass.
3. Load defaults that always apply: `ssl_pinning_bypass`, `jailbreak_bypass`, `commoncrypto_tracer`.
4. Operator overrides via `--hooks ...` or `--no-hooks ssl_pinning_bypass`.

### Runner — `frida_layer/runner.py`

```python
class FridaRunner:
    def __init__(self, store: EventStore, device: frida.core.Device, target: str): ...
    async def spawn_and_attach(self) -> None: ...
    def load_hook(self, hook_path: Path, source_replacements: dict[str, Any] | None = None) -> None: ...
    async def stream_events(self) -> AsyncIterator[FridaEvent]: ...
    async def stop(self) -> None: ...
```

Message-pump loop: `session.on("message", ...)` puts events on an `asyncio.Queue`. The consumer side writes to `frida_events.jsonl` and pushes into the `Correlator`.

## Objection side

### Why scripted Objection, not interactive

Interactive `objection explore` is good for humans but bad for autonomy: no machine-readable output, no determinism. We script it via `objection --commands-file` (or pipe). Each `.objection` script is a list of commands; we capture stdout, parse it.

### Scripts — `objection_layer/scripts/`

| Script | Commands | Output |
|---|---|---|
| `recon.objection` | `env`, `ios info binary`, `ios plist cat Info.plist`, `ios hooking list classes`, `ios hooking list class_methods`, `ios bundles list_frameworks` | `artifacts/recon.json` |
| `ssl_pinning_check.objection` | `ios sslpinning disable` (logs detected pinning), `ios hooking watch class SecTrust*` | `artifacts/pinning_surface.json` |
| `keychain_dump.objection` | `ios keychain dump`, `ios keychain dump --json` | `artifacts/keychain.json` |
| `jailbreak_detection.objection` | `ios jailbreak disable` + watch fileExists / canOpenURL | `artifacts/jb_detection_surface.json` |
| `userdefaults_dump.objection` | `ios nsuserdefaults get` | `artifacts/userdefaults.json` |
| `filesystem_walk.objection` | `ios filesystem ls /var/mobile/Containers/Data/Application/...` | `artifacts/filesystem.json` |
| `cookies_dump.objection` | `ios cookies get --json` | `artifacts/cookies.json` |

### Runner — `objection_layer/runner.py`

```python
class ObjectionRunner:
    def __init__(self, store: EventStore, device_id: str | None, target: str): ...
    def run_script(self, script_path: Path) -> ObjectionResult: ...
    def parse_recon(self, stdout: str) -> dict: ...     # per-script parser
    def parse_keychain(self, stdout: str) -> list[dict]: ...
    # etc.
```

`ObjectionResult` carries `{returncode, stdout, stderr, parsed, artifacts_written}`. Each script's parser knows the expected output shape.

## Overlap with Frida hooks — what Objection avoids reimplementing

| Capability | Frida hook | Objection command | Default choice |
|---|---|---|---|
| SSL pinning bypass | `ssl_pinning_bypass.js` | `ios sslpinning disable` | Run Objection first (gets the easy cases). Frida hook stays loaded for the obscure ones. |
| Keychain dump | `keychain_dump.js` | `ios keychain dump --json` | Objection. JSON output is already structured. |
| Jailbreak bypass | `jailbreak_bypass.js` | `ios jailbreak disable` | Both — Objection's is broad, Frida's is configurable per app. |
| Class enumeration | meta-hook | `ios hooking list classes` | Objection (one shot, predictable output). |
| Method tracing | `cffi_arg_tracer.js` | `ios hooking watch class X` | Depends. Objection for ad-hoc, Frida hook for sustained tracing into the store. |

The planner chooses based on `state.phase`:
- `bootstrap`: Objection recon scripts.
- `passive`: Frida hooks streaming.
- `mapping`: Objection ad-hoc commands invoked via `ObjectionRunner` when the planner has a specific question.
- `active`/`exploit`: mostly Frida (specific class/method tracing for signature inference).

## Failure modes and recoveries

| Failure | Detection | Recovery |
|---|---|---|
| `frida-server` not running on device | `frida.get_usb_device().enumerate_processes()` raises | `openrecon doctor` prints install instructions; planner aborts engagement |
| Target crashes on attach | session detached signal | retry with `--no-spawn` (attach to running instance) or with `gating=False` |
| Hook script error | `message.type == "error"` in Frida message pump | log to `runs/<id>/errors.jsonl`, continue without that hook |
| Objection command times out | subprocess wall-time exceeds 30s | mark script as failed in artifacts, continue with next |
| Device disconnects mid-engagement | `frida.Device.lost` callback | planner pauses, retries device acquisition; if 3 retries fail, write partial findings and exit |
