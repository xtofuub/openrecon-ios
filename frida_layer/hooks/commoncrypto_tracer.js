// commoncrypto_tracer.js — log every CCHmac / CCCryptor call.
// Enables the HookedCryptoAsSignature finder rule to infer client-side signing.

(function () {
  function preview(p, len, max) {
    max = max || 256;
    try {
      var n = Math.min(len, max);
      return hexdump(p, { length: n, ansi: false });
    } catch (e) { return null; }
  }

  function emit(method, extra) {
    send({
      kind: 'frida.event',
      ts: Date.now() / 1000,
      pid: Process.id,
      cls: 'CommonCrypto',
      method: method,
      args: [],
      ret: null,
      thread_id: Process.getCurrentThreadId ? Process.getCurrentThreadId() : 0,
      stack: [],
      hook_source: 'commoncrypto_tracer.js',
      extra: extra
    });
  }

  ['CCHmac', 'CCHmacInit', 'CCHmacUpdate', 'CCHmacFinal'].forEach(function (sym) {
    try {
      var addr = Module.findExportByName('libcommonCrypto.dylib', sym) ||
                 Module.findExportByName('libSystem.B.dylib', sym);
      if (!addr) return;
      Interceptor.attach(addr, {
        onEnter: function (args) {
          this.sym = sym;
          if (sym === 'CCHmac') {
            // (algorithm, key, keyLength, data, dataLength, macOut)
            var keyLen = args[2].toInt32();
            var dataLen = args[4].toInt32();
            this.extra = {
              algo: args[0].toInt32(),
              key_preview: preview(args[1], keyLen, 64),
              data_preview: preview(args[3], dataLen, 256),
              data_len: dataLen,
              mac_out: args[5]
            };
          }
        },
        onLeave: function () {
          if (this.sym === 'CCHmac' && this.extra && this.extra.mac_out) {
            this.extra.mac_preview = preview(this.extra.mac_out, 32, 64);
          }
          emit(this.sym, this.extra || {});
        }
      });
    } catch (e) {}
  });
})();
