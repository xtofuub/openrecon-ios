// Shared helpers loaded by every hook via `eval(readFile(...))` or copy-paste.
// Frida JS has no module system, so we keep this small.

function openreconEmit(event) {
  send({
    kind: 'frida.event',
    ts: Date.now() / 1000,
    pid: Process.id,
    cls: event.cls || '?',
    method: event.method || '?',
    args: event.args || [],
    ret: event.ret || null,
    thread_id: event.thread_id || (Process.getCurrentThreadId ? Process.getCurrentThreadId() : 0),
    stack: event.stack || [],
    hook_source: event.hook_source,
    extra: event.extra || {}
  });
}

function openreconPreview(value, maxLen) {
  maxLen = maxLen || 256;
  try {
    if (value === null || value === undefined) return null;
    if (typeof value === 'string') return value.slice(0, maxLen);
    if (typeof value === 'number' || typeof value === 'boolean') return String(value);
    if (value.isNull && value.isNull()) return null;
    var s;
    try { s = '' + value; } catch (_) { s = '[unconvertible]'; }
    return s.slice(0, maxLen);
  } catch (e) {
    return '[preview-error]';
  }
}

function openreconHash(value) {
  // SHA-256 via NSData → CommonCrypto. Returns hex.
  try {
    var bytes;
    if (typeof value === 'string') {
      bytes = Memory.allocUtf8String(value);
    } else if (value && value.isKindOfClass_ && value.isKindOfClass_(ObjC.classes.NSData)) {
      bytes = value.bytes();
    } else {
      return null;
    }
    // skip; expensive on hot path — defer hashing to Python side
    return null;
  } catch (e) {
    return null;
  }
}

function openreconStack(threshold) {
  threshold = threshold || 32;
  try {
    var bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
      .slice(0, threshold)
      .map(DebugSymbol.fromAddress)
      .map(function (s) { return String(s); });
    return bt;
  } catch (e) {
    return [];
  }
}
