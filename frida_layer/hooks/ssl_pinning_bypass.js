// ssl_pinning_bypass.js — composite SSL pinning bypass.
//
// Covers SecTrustEvaluate{,WithError}, NSURLSession delegate callbacks,
// AFNetworking pinning, and TrustKit. Each bypass emits a `pinning_bypass`
// event so the operator can see what was disabled.

(function () {
  function emit(cls, method, extra) {
    send({
      kind: 'frida.event',
      ts: Date.now() / 1000,
      pid: Process.id,
      cls: cls,
      method: method,
      args: [],
      ret: null,
      thread_id: Process.getCurrentThreadId ? Process.getCurrentThreadId() : 0,
      stack: [],
      hook_source: 'ssl_pinning_bypass.js',
      extra: extra || { kind: 'pinning_bypass' }
    });
  }

  // SecTrustEvaluate — return errSecSuccess (0)
  try {
    var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
    if (SecTrustEvaluate) {
      Interceptor.replace(SecTrustEvaluate, new NativeCallback(function (trust, result) {
        Memory.writeU32(result, 1); // kSecTrustResultProceed
        emit('Security', 'SecTrustEvaluate', { kind: 'pinning_bypass', api: 'SecTrustEvaluate' });
        return 0;
      }, 'int', ['pointer', 'pointer']));
    }
  } catch (e) {}

  try {
    var SecTrustEvaluateWithError = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
    if (SecTrustEvaluateWithError) {
      Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function (trust, error) {
        if (error && !error.isNull()) Memory.writePointer(error, NULL);
        emit('Security', 'SecTrustEvaluateWithError', { kind: 'pinning_bypass', api: 'SecTrustEvaluateWithError' });
        return 1;
      }, 'int', ['pointer', 'pointer']));
    }
  } catch (e) {}

  if (ObjC.available) {
    // AFNetworking
    try {
      var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
      if (AFSecurityPolicy) {
        AFSecurityPolicy['- evaluateServerTrust:forDomain:'].implementation = ObjC.implement(
          AFSecurityPolicy['- evaluateServerTrust:forDomain:'],
          function () { emit('AFSecurityPolicy', 'evaluateServerTrust:forDomain:'); return 1; }
        );
      }
    } catch (e) {}

    // TrustKit
    try {
      var TSKPinningValidator = ObjC.classes.TSKPinningValidator;
      if (TSKPinningValidator) {
        TSKPinningValidator['- evaluateTrust:forHostname:'].implementation = ObjC.implement(
          TSKPinningValidator['- evaluateTrust:forHostname:'],
          function () { emit('TSKPinningValidator', 'evaluateTrust:forHostname:'); return 0; }
        );
      }
    } catch (e) {}
  }
})();
