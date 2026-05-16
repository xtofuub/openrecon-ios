/**
 * nshttpcookiestorage_tracer.js — Stream cookie reads and writes.
 *
 * On load emits all cookies currently in the shared storage.
 * Then hooks all write operations so you see cookies added, modified,
 * or deleted in real time.
 *
 * Hooks:
 *   -[NSHTTPCookieStorage sharedHTTPCookieStorage]  (triggers initial dump)
 *   -[NSHTTPCookieStorage setCookie:]               new or updated cookie
 *   -[NSHTTPCookieStorage deleteCookie:]            cookie removed
 *   -[NSHTTPCookieStorage cookiesForURL:]           reads (per-URL lookup)
 */

(function () {
  'use strict';

  var dumped = false;

  function parseCookie(cookieObj) {
    var out = {};
    var fields = ['name', 'value', 'domain', 'path', 'isSecure', 'isHTTPOnly',
                  'expiresDate', 'sessionOnly'];
    fields.forEach(function (f) {
      try {
        var method = cookieObj[f === 'name' ? '- name' :
                              f === 'value' ? '- value' :
                              f === 'domain' ? '- domain' :
                              f === 'path' ? '- path' :
                              f === 'isSecure' ? '- isSecure' :
                              f === 'isHTTPOnly' ? '- isHTTPOnly' :
                              f === 'expiresDate' ? '- expiresDate' :
                              '- ' + f];
        if (method) {
          var v = cookieObj[f]();
          out[f] = v ? v.toString() : null;
        } else {
          // simpler name-based access for some builds
          var sel = '- ' + f;
          if (cookieObj[sel]) out[f] = cookieObj[sel]().toString();
        }
      } catch (_) {}
    });
    // Fallback: just use description
    if (!out.name) {
      try { out._raw = cookieObj.toString(); } catch (_) {}
    }
    return out;
  }

  function emit(op, cookie) {
    send({
      kind: 'frida.event',
      ts: Date.now() / 1000,
      pid: Process.id,
      cls: 'NSHTTPCookieStorage',
      method: op,
      args: [{ type: 'NSHTTPCookie', repr: String(cookie.name), preview: String(cookie.name) }],
      ret: null,
      thread_id: Process.getCurrentThreadId ? Process.getCurrentThreadId() : 0,
      stack: [],
      hook_source: 'nshttpcookiestorage_tracer.js',
      extra: { op: op, cookie: cookie }
    });
  }

  function dumpAll(storage) {
    try {
      var cookies = storage.cookies();
      if (!cookies) return;
      var count = cookies.count();
      for (var i = 0; i < count; i++) {
        var c = new ObjC.Object(cookies.objectAtIndex_(i));
        emit('dump', parseCookie(c));
      }
    } catch (_) {}
  }

  if (!ObjC.available) return;

  var NSHTTPCookieStorage = ObjC.classes.NSHTTPCookieStorage;
  if (!NSHTTPCookieStorage) return;

  // Dump on first shared access
  try {
    Interceptor.attach(NSHTTPCookieStorage['+ sharedHTTPCookieStorage'].implementation, {
      onLeave: function (retval) {
        if (dumped || !retval || retval.isNull()) return;
        dumped = true;
        dumpAll(new ObjC.Object(retval));
      }
    });
  } catch (_) {}

  // setCookie:
  try {
    if (NSHTTPCookieStorage['- setCookie:']) {
      Interceptor.attach(NSHTTPCookieStorage['- setCookie:'].implementation, {
        onEnter: function (args) {
          try {
            emit('set', parseCookie(new ObjC.Object(args[2])));
          } catch (_) {}
        }
      });
    }
  } catch (_) {}

  // deleteCookie:
  try {
    if (NSHTTPCookieStorage['- deleteCookie:']) {
      Interceptor.attach(NSHTTPCookieStorage['- deleteCookie:'].implementation, {
        onEnter: function (args) {
          try {
            emit('delete', parseCookie(new ObjC.Object(args[2])));
          } catch (_) {}
        }
      });
    }
  } catch (_) {}

  // cookiesForURL: (read per-URL — log for correlation)
  try {
    if (NSHTTPCookieStorage['- cookiesForURL:']) {
      Interceptor.attach(NSHTTPCookieStorage['- cookiesForURL:'].implementation, {
        onEnter: function (args) {
          try {
            this.url = new ObjC.Object(args[2]).absoluteString().toString();
          } catch (_) {}
        },
        onLeave: function (retval) {
          try {
            if (!retval || retval.isNull()) return;
            var arr = new ObjC.Object(retval);
            var count = arr.count();
            for (var i = 0; i < count; i++) {
              var c = parseCookie(new ObjC.Object(arr.objectAtIndex_(i)));
              c._forURL = this.url;
              emit('read', c);
            }
          } catch (_) {}
        }
      });
    }
  } catch (_) {}
})();
