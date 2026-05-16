/**
 * binary_dump.js — FairPlay-aware Mach-O dumper (frida-ios-dump style).
 *
 * iOS apps from the App Store are FairPlay-encrypted. The encrypted segment
 * is decrypted by the kernel into memory at launch. This script:
 *
 *   1. Locates the main module via Process.enumerateModules().
 *   2. Reads the on-disk Mach-O header to discover its load commands.
 *   3. For each LC_ENCRYPTION_INFO[_64] with cryptid != 0:
 *        • reads the *decrypted* bytes from the corresponding memory range
 *          (where the kernel has placed them)
 *        • splices them over the encrypted bytes in our buffer
 *        • patches cryptid to 0 so r2/IDA/otool see a clean binary
 *   4. Streams the resulting buffer back to Python in fixed-size chunks
 *      via send() + arraybuffer payload.
 *
 * The Python receiver assembles ``runs/<run_id>/artifacts/app.macho``.
 *
 * Invocation: load this script with a `{{chunk_size}}` placeholder
 * (defaulted to 1 MB). The script auto-starts and signals completion
 * via a final ``kind: 'binary_dump.done'`` event.
 */

(function () {
  'use strict';

  var CHUNK_SIZE = {{chunk_size}};
  if (typeof CHUNK_SIZE !== 'number' || CHUNK_SIZE <= 0) CHUNK_SIZE = 1024 * 1024;

  // Load command constants we care about.
  var LC_SEGMENT     = 0x01;
  var LC_SEGMENT_64  = 0x19;
  var LC_ENCRYPTION_INFO    = 0x21;
  var LC_ENCRYPTION_INFO_64 = 0x2C;

  // Mach-O magics.
  var MH_MAGIC_64 = 0xfeedfacf;
  var MH_CIGAM_64 = 0xcffaedfe;
  var MH_MAGIC    = 0xfeedface;
  var MH_CIGAM    = 0xcefaedfe;

  function emit(kind, payload, data) {
    try {
      send({
        kind: 'frida.event',
        ts: Date.now() / 1000,
        pid: Process.id,
        cls: 'BinaryDump',
        method: kind,
        args: [],
        ret: null,
        thread_id: Process.getCurrentThreadId ? Process.getCurrentThreadId() : 0,
        stack: [],
        hook_source: 'binary_dump.js',
        extra: payload
      }, data);
    } catch (_) {}
  }

  function fail(reason) {
    emit('binary_dump.error', { error: reason });
  }

  try {
    var modules = Process.enumerateModules();
    if (!modules || modules.length === 0) { fail('no modules loaded'); return; }
    var main = modules[0];
    // Heuristic: skip system frameworks; main is usually first but on some
    // iOS versions dyld is at index 0. Pick the first module whose path
    // contains '/Application' or matches the app bundle.
    for (var i = 0; i < modules.length; i++) {
      var p = modules[i].path || '';
      if (p.indexOf('.app/') !== -1 || p.indexOf('/Application') !== -1) {
        main = modules[i];
        break;
      }
    }

    emit('binary_dump.start', {
      name: main.name,
      path: main.path,
      base: main.base.toString(),
      size: main.size
    });

    // Read the on-disk binary into memory via Frida's File API. The size
    // matches the live module's mapping (segments + headers); for FairPlay
    // we only need the encrypted segment replaced.
    var file = new File(main.path, 'rb');
    if (!file) { fail('could not open ' + main.path); return; }
    file.seek(0);
    // Read whole file. iOS app binaries are typically tens of MB; this fits
    // in process memory comfortably.
    var fileData = file.readBytes(0);   // null/0 -> read to EOF in frida 16+
    file.close();
    if (!fileData) { fail('readBytes returned empty'); return; }

    var buf = new Uint8Array(fileData);

    // Parse the header.
    var headerPtr = main.base;
    var magic = headerPtr.readU32();
    var is64 = (magic === MH_MAGIC_64 || magic === MH_CIGAM_64);
    if (!is64 && magic !== MH_MAGIC && magic !== MH_CIGAM) {
      fail('unsupported magic 0x' + magic.toString(16));
      return;
    }
    var ncmds = headerPtr.add(16).readU32();
    var sizeofcmds = headerPtr.add(20).readU32();
    var headerSize = is64 ? 32 : 28;

    var cmdPtr = headerPtr.add(headerSize);
    var fileCmdOff = headerSize;  // byte offset within fileData

    var patched = 0;
    for (var c = 0; c < ncmds; c++) {
      var cmd = cmdPtr.readU32();
      var cmdsize = cmdPtr.add(4).readU32();

      if (cmd === LC_ENCRYPTION_INFO_64 || cmd === LC_ENCRYPTION_INFO) {
        // struct encryption_info_command{,_64}:
        //   uint32_t cmd, cmdsize;
        //   uint32_t cryptoff, cryptsize, cryptid;
        //   [+ uint32_t pad for _64]
        var cryptoff  = cmdPtr.add(8).readU32();
        var cryptsize = cmdPtr.add(12).readU32();
        var cryptid   = cmdPtr.add(16).readU32();
        if (cryptid !== 0 && cryptsize > 0) {
          // Decrypted bytes live at main.base + cryptoff in memory.
          var src = main.base.add(cryptoff);
          var liveBytes = src.readByteArray(cryptsize);
          var liveView = new Uint8Array(liveBytes);
          // Splice over encrypted bytes in our file buffer.
          if (cryptoff + cryptsize <= buf.byteLength) {
            buf.set(liveView, cryptoff);
            // Patch cryptid → 0 in the buffer header copy too.
            var cryptidFileOff = fileCmdOff + 16;
            buf[cryptidFileOff]     = 0;
            buf[cryptidFileOff + 1] = 0;
            buf[cryptidFileOff + 2] = 0;
            buf[cryptidFileOff + 3] = 0;
            patched++;
            emit('binary_dump.decrypted', {
              cryptoff: cryptoff,
              cryptsize: cryptsize
            });
          }
        }
      }

      cmdPtr = cmdPtr.add(cmdsize);
      fileCmdOff += cmdsize;
    }

    // Stream in chunks. send() supports an optional ArrayBuffer second arg.
    var total = buf.byteLength;
    var seq = 0;
    for (var off = 0; off < total; off += CHUNK_SIZE) {
      var end = Math.min(off + CHUNK_SIZE, total);
      var slice = buf.slice(off, end);
      emit('binary_dump.chunk', {
        seq: seq,
        offset: off,
        size: slice.byteLength,
        total: total
      }, slice.buffer);
      seq++;
    }
    emit('binary_dump.done', {
      name: main.name,
      path: main.path,
      total_bytes: total,
      patched_encryption_segments: patched,
      chunks: seq
    });
  } catch (e) {
    fail('exception: ' + e.message);
  }
})();
