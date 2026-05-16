/**
 * nsuserdefaults_tracer.js — Stream NSUserDefaults reads and writes.
 *
 * Intercepts:
 *   -[NSUserDefaults objectForKey:]         reads (and typed variants)
 *   -[NSUserDefaults setObject:forKey:]     writes
 *   -[NSUserDefaults removeObjectForKey:]   deletes
 *   +[NSUserDefaults standardUserDefaults]  initial access (triggers a one-shot dump)
 *
 * On first access the hook emits a full dump of all existing keys.
 * Subsequent events are per-call so you see exactly what the app reads/writes
 * and when.
 */

(function () {
  'use strict';

  var dumped = false;

  function emit(method, key, value) {
    send({
      kind: 'frida.event',
      ts: Date.now() / 1000,
      pid: Process.id,
      cls: 'NSUserDefaults',
      method: method,
      args: [
        { type: 'NSString', repr: key, preview: key.slice(0, 256) },
        { type: 'NSObject', repr: String(value), preview: String(value).slice(0, 512) }
      ],
      ret: null,
      thread_id: Process.getCurrentThreadId ? Process.getCurrentThreadId() : 0,
      stack: [],
      hook_source: 'nsuserdefaults_tracer.js',
      extra: { key: key, value: value, op: method }
    });
  }

  function dumpAll(defaults) {
    try {
      var dict = defaults.dictionaryRepresentation();
      var keys = dict.allKeys();
      var out = {};
      for (var i = 0; i < keys.count(); i++) {
        var k = keys.objectAtIndex_(i);
        var v = dict.objectForKey_(k);
        var ks = k.toString();
        var vs = '';
        try { vs = v.toString(); } catch (_) { vs = '<non-string>'; }
        out[ks] = vs;
      }
      send({
        kind: 'frida.event',
        ts: Date.now() / 1000,
        pid: Process.id,
        cls: 'NSUserDefaults',
        method: 'DUMP',
        args: [],
        ret: null,
        thread_id: Process.getCurrentThreadId ? Process.getCurrentThreadId() : 0,
        stack: [],
        hook_source: 'nsuserdefaults_tracer.js',
        extra: { op: 'dump', entries: out, count: Object.keys(out).length }
      });
    } catch (_) {}
  }

  if (!ObjC.available) return;

  var NSUserDefaults = ObjC.classes.NSUserDefaults;
  if (!NSUserDefaults) return;

  // Initial dump on first standardUserDefaults access
  try {
    Interceptor.attach(NSUserDefaults['+ standardUserDefaults'].implementation, {
      onLeave: function (retval) {
        if (dumped || !retval || retval.isNull()) return;
        dumped = true;
        dumpAll(new ObjC.Object(retval));
      }
    });
  } catch (_) {}

  // Reads
  ['- objectForKey:', '- stringForKey:', '- boolForKey:', '- integerForKey:',
   '- floatForKey:', '- doubleForKey:', '- arrayForKey:', '- dictionaryForKey:',
   '- dataForKey:', '- URLForKey:'].forEach(function (sel) {
    try {
      if (!NSUserDefaults[sel]) return;
      Interceptor.attach(NSUserDefaults[sel].implementation, {
        onEnter: function (args) {
          try { this.key = new ObjC.Object(args[2]).toString(); } catch (_) { this.key = '?'; }
        },
        onLeave: function (retval) {
          try {
            var val = retval && !retval.isNull() ? new ObjC.Object(retval) : null;
            var vs = val ? (function () { try { return val.toString(); } catch (_) { return '<value>'; } })() : '<nil>';
            emit(sel, this.key || '?', vs);
          } catch (_) {}
        }
      });
    } catch (_) {}
  });

  // Writes
  ['- setObject:forKey:', '- setBool:forKey:', '- setInteger:forKey:',
   '- setFloat:forKey:', '- setDouble:forKey:', '- setURL:forKey:'].forEach(function (sel) {
    try {
      if (!NSUserDefaults[sel]) return;
      Interceptor.attach(NSUserDefaults[sel].implementation, {
        onEnter: function (args) {
          try {
            var val = new ObjC.Object(args[2]);
            var key = new ObjC.Object(args[3]).toString();
            var vs = '';
            try { vs = val.toString(); } catch (_) { vs = '<value>'; }
            emit(sel, key, vs);
          } catch (_) {}
        }
      });
    } catch (_) {}
  });

  // Deletes
  try {
    if (NSUserDefaults['- removeObjectForKey:']) {
      Interceptor.attach(NSUserDefaults['- removeObjectForKey:'].implementation, {
        onEnter: function (args) {
          try {
            var key = new ObjC.Object(args[2]).toString();
            emit('- removeObjectForKey:', key, '<deleted>');
          } catch (_) {}
        }
      });
    }
  } catch (_) {}
})();
