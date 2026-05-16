/**
 * keychain_full_dump.js — Enumerate and stream all keychain items on attach.
 *
 * On load, queries four keychain item classes via SecItemCopyMatching and emits
 * every entry the app's entitlements allow it to read. Also hooks future
 * SecItemAdd / SecItemUpdate / SecItemDelete so you see writes live.
 *
 * Requires the app to have appropriate keychain-access-groups entitlements.
 * On a jailbroken device with ldid/entitlement tricks this reads everything.
 *
 * Item classes queried:
 *   kSecClassGenericPassword   — arbitrary secret blobs
 *   kSecClassInternetPassword  — URL + credentials
 *   kSecClassCertificate       — DER-encoded certs
 *   kSecClassKey               — symmetric / asymmetric keys
 */

(function () {
  'use strict';

  function hexStr(bytes) {
    if (!bytes) return null;
    return Array.prototype.map.call(
      new Uint8Array(bytes),
      function (b) { return ('0' + b.toString(16)).slice(-2); }
    ).join('');
  }

  function emitItem(op, itemClass, attributes) {
    send({
      kind: 'frida.event',
      ts: Date.now() / 1000,
      pid: Process.id,
      cls: 'Keychain',
      method: op,
      args: [],
      ret: null,
      thread_id: Process.getCurrentThreadId ? Process.getCurrentThreadId() : 0,
      stack: [],
      hook_source: 'keychain_full_dump.js',
      extra: { op: op, item_class: itemClass, attributes: attributes }
    });
  }

  function nsStringOrNull(obj) {
    try { return obj && !obj.isNull() ? new ObjC.Object(obj).toString() : null; } catch (_) { return null; }
  }

  function nsDataOrNull(obj) {
    try {
      if (!obj || obj.isNull()) return null;
      var d = new ObjC.Object(obj);
      var len = d.length();
      if (len === 0 || len > 4096) return null;
      return hexStr(d.bytes().readByteArray(len));
    } catch (_) { return null; }
  }

  // ── Full dump on attach ───────────────────────────────────────────────────

  function dumpClass(className) {
    try {
      var NSD = ObjC.classes.NSMutableDictionary.alloc().init();
      NSD.setObject_forKey_(ObjC.classes.NSString.stringWithString_(className), 'class');
      NSD.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(true), 'r_attributes');
      NSD.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(true), 'r_data');
      NSD.setObject_forKey_(ObjC.classes.NSString.stringWithString_('all'), 'm_Limit');

      var resultRef = Memory.alloc(Process.pointerSize);
      Memory.writePointer(resultRef, NULL);

      var SecItemCopyMatching = Module.findExportByName('Security', 'SecItemCopyMatching');
      if (!SecItemCopyMatching) return;

      var fn = new NativeFunction(SecItemCopyMatching, 'int', ['pointer', 'pointer']);
      var status = fn(NSD.handle, resultRef);

      if (status !== 0) return;

      var resultPtr = Memory.readPointer(resultRef);
      if (resultPtr.isNull()) return;

      var result = new ObjC.Object(resultPtr);
      var items = className === 'cert' || className === 'key'
        ? result
        : result;

      // result is NSArray of NSDictionary
      var count = result.count ? result.count() : 0;
      for (var i = 0; i < count; i++) {
        var item = result.objectAtIndex_(i);
        var attrs = {};
        try {
          var keys = item.allKeys();
          for (var j = 0; j < keys.count(); j++) {
            var k = keys.objectAtIndex_(j).toString();
            var v = item.objectForKey_(keys.objectAtIndex_(j));
            try {
              var cls = v.className ? v.className().toString() : '';
              if (cls === '__NSCFString' || cls === 'NSTaggedPointerString') {
                attrs[k] = v.toString();
              } else if (cls === 'NSConcreteData' || cls === '__NSCFData') {
                attrs[k] = nsDataOrNull(v);
              } else {
                attrs[k] = v.toString();
              }
            } catch (_) { attrs[k] = '<unreadable>'; }
          }
        } catch (_) {}
        emitItem('dump', className, attrs);
      }
    } catch (_) {}
  }

  if (!ObjC.available) return;

  // Defer dump until first SecItemCopyMatching fires (app is running).
  var dumped = false;
  var SecItemCopyMatchingAddr = Module.findExportByName('Security', 'SecItemCopyMatching');
  if (SecItemCopyMatchingAddr) {
    Interceptor.attach(SecItemCopyMatchingAddr, {
      onEnter: function () {
        if (dumped) return;
        dumped = true;
        ['genp', 'inet', 'cert', 'keys'].forEach(dumpClass);
      }
    });
  }

  // ── Live hooks for write operations ────────────────────────────────────────

  function hookSecurity(name, op) {
    var addr = Module.findExportByName('Security', name);
    if (!addr) return;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        try {
          var query = new ObjC.Object(args[0]);
          var attrs = {};
          var keys = query.allKeys();
          for (var i = 0; i < keys.count(); i++) {
            var k = keys.objectAtIndex_(i).toString();
            try { attrs[k] = query.objectForKey_(keys.objectAtIndex_(i)).toString(); } catch (_) {}
          }
          emitItem(op, attrs['class'] || '?', attrs);
        } catch (_) {}
      }
    });
  }

  hookSecurity('SecItemAdd', 'add');
  hookSecurity('SecItemUpdate', 'update');
  hookSecurity('SecItemDelete', 'delete');
})();
