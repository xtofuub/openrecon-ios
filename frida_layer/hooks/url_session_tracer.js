// url_session_tracer.js — trace NSURLSession / NSURLConnection / WKWebView requests.
// Emits a frida.event per request and per response. Pairs are stitched on the
// Python side by url_session correlation in agent/finder.py.

(function () {
  function emit(event) {
    event.hook_source = 'url_session_tracer.js';
    send({
      kind: 'frida.event',
      ts: Date.now() / 1000,
      pid: Process.id,
      cls: event.cls || '?',
      method: event.method || '?',
      args: event.args || [],
      ret: event.ret || null,
      thread_id: Process.getCurrentThreadId ? Process.getCurrentThreadId() : 0,
      stack: event.stack || [],
      hook_source: event.hook_source,
      extra: event.extra || {}
    });
  }

  function preview(v, max) {
    max = max || 256;
    if (v === null || v === undefined) return null;
    try { return ('' + v).slice(0, max); } catch (_) { return '[err]'; }
  }

  if (ObjC.available) {
    try {
      var NSURLSession = ObjC.classes.NSURLSession;
      if (NSURLSession) {
        ['dataTaskWithRequest:', 'dataTaskWithRequest:completionHandler:', 'uploadTaskWithRequest:fromData:'].forEach(function (sel) {
          try {
            Interceptor.attach(NSURLSession['- ' + sel].implementation, {
              onEnter: function (args) {
                var request = new ObjC.Object(args[2]);
                var url = request.URL ? request.URL().absoluteString().toString() : null;
                var method = request.HTTPMethod ? request.HTTPMethod().toString() : null;
                var headers = {};
                try {
                  var h = request.allHTTPHeaderFields();
                  if (h) {
                    var keys = h.allKeys();
                    var n = keys.count();
                    for (var i = 0; i < n; i++) {
                      var k = keys.objectAtIndex_(i);
                      headers[k.toString()] = h.objectForKey_(k).toString();
                    }
                  }
                } catch (_) {}
                emit({
                  cls: 'NSURLSession',
                  method: sel,
                  args: [
                    { type: 'NSURLRequest', repr: '<NSURLRequest>', preview: preview(url) },
                    { type: 'NSString', repr: method || '?', preview: method }
                  ],
                  extra: { url: url, method: method, headers: headers }
                });
              }
            });
          } catch (e) {}
        });
      }
    } catch (e) {}

    try {
      var WKWebView = ObjC.classes.WKWebView;
      if (WKWebView) {
        Interceptor.attach(WKWebView['- loadRequest:'].implementation, {
          onEnter: function (args) {
            var req = new ObjC.Object(args[2]);
            var url = req.URL ? req.URL().absoluteString().toString() : null;
            emit({
              cls: 'WKWebView',
              method: 'loadRequest:',
              args: [{ type: 'NSURLRequest', repr: '<req>', preview: preview(url) }],
              extra: { url: url }
            });
          }
        });
      }
    } catch (e) {}
  }
})();
