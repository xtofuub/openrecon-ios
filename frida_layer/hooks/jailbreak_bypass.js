// jailbreak_bypass.js — neutralize common iOS jailbreak detection.

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
      hook_source: 'jailbreak_bypass.js',
      extra: extra || { kind: 'jailbreak_bypass' }
    });
  }

  var jbPaths = [
    '/Applications/Cydia.app',
    '/Library/MobileSubstrate/MobileSubstrate.dylib',
    '/bin/bash',
    '/usr/sbin/sshd',
    '/etc/apt',
    '/private/var/lib/apt',
    '/private/var/stash'
  ];

  if (ObjC.available) {
    var NSFileManager = ObjC.classes.NSFileManager;
    if (NSFileManager) {
      Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
        onEnter: function (args) {
          this.path = new ObjC.Object(args[2]).toString();
        },
        onLeave: function (retval) {
          if (this.path && jbPaths.indexOf(this.path) !== -1) {
            retval.replace(0);
            emit('NSFileManager', 'fileExistsAtPath:', { kind: 'jailbreak_bypass', path: this.path });
          }
        }
      });
    }

    var UIApp = ObjC.classes.UIApplication;
    if (UIApp) {
      Interceptor.attach(UIApp['- canOpenURL:'].implementation, {
        onEnter: function (args) {
          this.url = new ObjC.Object(args[2]).toString();
        },
        onLeave: function (retval) {
          if (this.url && this.url.indexOf('cydia://') === 0) {
            retval.replace(0);
            emit('UIApplication', 'canOpenURL:', { kind: 'jailbreak_bypass', url: this.url });
          }
        }
      });
    }
  }

  // fork — Apple apps never call fork(); detection apps do
  try {
    var fork = Module.findExportByName(null, 'fork');
    if (fork) {
      Interceptor.replace(fork, new NativeCallback(function () {
        emit('libsystem_kernel.dylib', 'fork');
        return -1;
      }, 'int', []));
    }
  } catch (e) {}
})();
