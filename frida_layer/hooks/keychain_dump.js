// keychain_dump.js — enumerate keychain entries on attach and on each
// SecItemCopyMatching call. Emits one event per entry.

(function () {
  function emit(extra) {
    send({
      kind: 'frida.event',
      ts: Date.now() / 1000,
      pid: Process.id,
      cls: 'Security',
      method: 'SecItemCopyMatching',
      args: [],
      ret: null,
      thread_id: Process.getCurrentThreadId ? Process.getCurrentThreadId() : 0,
      stack: [],
      hook_source: 'keychain_dump.js',
      extra: extra
    });
  }

  if (ObjC.available) {
    var SecItemCopyMatching = Module.findExportByName('Security', 'SecItemCopyMatching');
    if (SecItemCopyMatching) {
      Interceptor.attach(SecItemCopyMatching, {
        onLeave: function (retval) {
          emit({ kind: 'keychain_query', status: retval.toInt32() });
        }
      });
    }
  }
})();
