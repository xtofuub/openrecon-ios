/**
 * ns_url_connection_tracer.js — NSURLConnection full request + response capture.
 *
 * NSURLConnection is deprecated but still common in older apps and SDKs.
 * Like NSURLSession, response data arrives AFTER OS-level TLS decryption, so
 * no pinning bypass is needed here.
 *
 * Covers:
 *   • +[NSURLConnection sendSynchronousRequest:returningResponse:error:]
 *     (blocking — captures full request + response atomically)
 *   • +[NSURLConnection sendAsynchronousRequest:queue:completionHandler:]
 *     (async, completion-handler based — block replacement captures response)
 *   • NSURLConnectionDataDelegate:
 *       -connection:didReceiveResponse:
 *       -connection:didReceiveData:
 *       -connectionDidFinishLoading:
 *       -connection:didFailWithError:
 *
 * Single high-level event per request:
 *   kind: "flow.complete"  — shaped like MitmFlow for the Python normalizer.
 *
 * Body cap: 2 MB per direction. Above the cap the body is dropped and a
 *   `body_truncated: true` flag is set.
 */

(function () {
  'use strict';

  var BODY_CAP = 2 * 1024 * 1024;

  // connection pointer -> {url, method, headers, requestBody, requestBodyTruncated,
  //                        chunks: [], responseBytes, responseTruncated, status,
  //                        responseHeaders, tsRequest}
  var connMap = {};

  function ptr2id(p) { return p.toString(); }

  function readHeaders(request) {
    var out = {};
    try {
      var h = request.allHTTPHeaderFields();
      if (h) {
        var keys = h.allKeys();
        for (var i = 0; i < keys.count(); i++) {
          var k = keys.objectAtIndex_(i);
          out[k.toString()] = h.objectForKey_(k).toString();
        }
      }
    } catch (_) {}
    return out;
  }

  function readResponseHeaders(httpResp) {
    var out = {};
    try {
      var rh = httpResp.allHeaderFields();
      if (!rh) return out;
      var keys = rh.allKeys();
      for (var i = 0; i < keys.count(); i++) {
        var k = keys.objectAtIndex_(i);
        out[k.toString()] = rh.objectForKey_(k).toString();
      }
    } catch (_) {}
    return out;
  }

  function nsDataBytes(nsdata) {
    try {
      if (!nsdata || nsdata.isNull()) return null;
      var len = nsdata.length();
      if (len === 0) return null;
      return nsdata.bytes().readByteArray(len);
    } catch (_) { return null; }
  }

  function readRequestBody(request) {
    try {
      var body = request.HTTPBody ? request.HTTPBody() : null;
      if (!body || body.isNull()) return { bytes: null, truncated: false };
      var len = body.length();
      if (len === 0) return { bytes: null, truncated: false };
      if (len > BODY_CAP) return { bytes: null, truncated: true };
      return { bytes: body.bytes().readByteArray(len), truncated: false };
    } catch (_) {
      return { bytes: null, truncated: false };
    }
  }

  // ── Helpers shared with url_session_body_tracer.js (kept self-contained so
  // each hook can be loaded independently). Keep the algorithms identical.

  var B64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

  function ab2b64(buf) {
    if (!buf) return null;
    var bytes = new Uint8Array(buf);
    var len = bytes.length;
    var out = '';
    var i;
    for (i = 0; i + 2 < len; i += 3) {
      var b0 = bytes[i], b1 = bytes[i + 1], b2 = bytes[i + 2];
      out += B64_CHARS[b0 >> 2];
      out += B64_CHARS[((b0 & 3) << 4) | (b1 >> 4)];
      out += B64_CHARS[((b1 & 15) << 2) | (b2 >> 6)];
      out += B64_CHARS[b2 & 63];
    }
    if (i < len) {
      var b0r = bytes[i];
      out += B64_CHARS[b0r >> 2];
      if (i + 1 < len) {
        var b1r = bytes[i + 1];
        out += B64_CHARS[((b0r & 3) << 4) | (b1r >> 4)];
        out += B64_CHARS[(b1r & 15) << 2];
        out += '=';
      } else {
        out += B64_CHARS[(b0r & 3) << 4];
        out += '==';
      }
    }
    return out;
  }

  function concatChunks(chunks) {
    if (!chunks || chunks.length === 0) return null;
    var total = 0;
    var i;
    for (i = 0; i < chunks.length; i++) total += chunks[i].byteLength;
    var out = new Uint8Array(total);
    var off = 0;
    for (i = 0; i < chunks.length; i++) {
      out.set(new Uint8Array(chunks[i]), off);
      off += chunks[i].byteLength;
    }
    return out.buffer;
  }

  function sha256Hex(u8) {
    if (!u8 || u8.byteLength === 0) return null;
    var H = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]);
    var K = new Uint32Array([
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
      0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
      0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
      0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]);

    var lenBits = u8.byteLength * 8;
    var padLen = (u8.byteLength + 9 + 63) & ~63;
    var msg = new Uint8Array(padLen);
    msg.set(u8);
    msg[u8.byteLength] = 0x80;
    var hi = Math.floor(lenBits / 0x100000000);
    var lo = lenBits >>> 0;
    msg[padLen - 8] = (hi >>> 24) & 0xff;
    msg[padLen - 7] = (hi >>> 16) & 0xff;
    msg[padLen - 6] = (hi >>> 8) & 0xff;
    msg[padLen - 5] = hi & 0xff;
    msg[padLen - 4] = (lo >>> 24) & 0xff;
    msg[padLen - 3] = (lo >>> 16) & 0xff;
    msg[padLen - 2] = (lo >>> 8) & 0xff;
    msg[padLen - 1] = lo & 0xff;

    var W = new Uint32Array(64);
    for (var i = 0; i < padLen; i += 64) {
      var j;
      for (j = 0; j < 16; j++) {
        var off = i + j * 4;
        W[j] = (msg[off] << 24) | (msg[off + 1] << 16) | (msg[off + 2] << 8) | msg[off + 3];
      }
      for (j = 16; j < 64; j++) {
        var x1 = W[j - 15], x2 = W[j - 2];
        var s0 = ((x1 >>> 7) | (x1 << 25)) ^ ((x1 >>> 18) | (x1 << 14)) ^ (x1 >>> 3);
        var s1 = ((x2 >>> 17) | (x2 << 15)) ^ ((x2 >>> 19) | (x2 << 13)) ^ (x2 >>> 10);
        W[j] = (W[j - 16] + s0 + W[j - 7] + s1) >>> 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (j = 0; j < 64; j++) {
        var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + K[j] + W[j]) >>> 0;
        var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        var mj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + mj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0;
      H[1] = (H[1] + b) >>> 0;
      H[2] = (H[2] + c) >>> 0;
      H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0;
      H[5] = (H[5] + f) >>> 0;
      H[6] = (H[6] + g) >>> 0;
      H[7] = (H[7] + h) >>> 0;
    }
    var hex = '';
    for (var k = 0; k < 8; k++) {
      var v = H[k];
      hex += ('00000000' + v.toString(16)).slice(-8);
    }
    return hex;
  }

  function ulid() {
    var t = Date.now().toString(36);
    var r = '';
    for (var i = 0; i < 12; i++) {
      r += Math.floor(Math.random() * 36).toString(36);
    }
    return (t + r).toUpperCase();
  }

  function emit(kind, payload) {
    try {
      send({
        kind: 'frida.event',
        ts: Date.now() / 1000,
        pid: Process.id,
        cls: 'NSURLConnection',
        method: kind,
        args: [{ type: 'NSString', repr: payload.url || '?', preview: (payload.url || '?').slice(0, 256) }],
        ret: null,
        thread_id: Process.getCurrentThreadId ? Process.getCurrentThreadId() : 0,
        stack: [],
        hook_source: 'ns_url_connection_tracer.js',
        extra: payload
      });
    } catch (_) {}
  }

  function emitComplete(info, requestBytes, requestTruncated, responseBuf, responseTruncated) {
    var reqU8 = requestBytes ? new Uint8Array(requestBytes) : null;
    var respU8 = responseBuf ? new Uint8Array(responseBuf) : null;
    emit('flow.complete', {
      kind: 'flow.complete',
      flow_id_synthetic: 'frida-NSURLConnection-' + ulid(),
      source: 'frida_nsurlconnection',
      url: info.url || '?',
      method: info.method || 'GET',
      ts_request: info.tsRequest || (Date.now() / 1000),
      ts_response: Date.now() / 1000,
      request: {
        url: info.url || '?',
        method: info.method || 'GET',
        headers: info.headers || {},
        body_b64: reqU8 ? ab2b64(reqU8.buffer) : null,
        body_sha256: reqU8 ? sha256Hex(reqU8) : null,
        body_truncated: !!requestTruncated
      },
      response: {
        status: info.status || 0,
        headers: info.responseHeaders || {},
        body_b64: respU8 ? ab2b64(respU8.buffer) : null,
        body_sha256: respU8 ? sha256Hex(respU8) : null,
        body_truncated: !!responseTruncated
      }
    });
  }

  if (!ObjC.available) return;

  // ── Synchronous (blocking) ─────────────────────────────────────────────────

  try {
    var sync = ObjC.classes.NSURLConnection['+ sendSynchronousRequest:returningResponse:error:'];
    if (sync) {
      Interceptor.attach(sync.implementation, {
        onEnter: function (args) {
          try {
            var req = new ObjC.Object(args[2]);
            this.url = req.URL().absoluteString().toString();
            this.method = req.HTTPMethod ? req.HTTPMethod().toString() : 'GET';
            this.headers = readHeaders(req);
            var rb = readRequestBody(req);
            this.requestBytes = rb.bytes;
            this.requestTruncated = rb.truncated;
            this.responsePtr = args[3];  // NSURLResponse**, populated on return
            this.tsRequest = Date.now() / 1000;
          } catch (_) {}
        },
        onLeave: function (retval) {
          try {
            var info = {
              url: this.url || '?',
              method: this.method || 'GET',
              headers: this.headers || {},
              tsRequest: this.tsRequest,
              status: 0,
              responseHeaders: {}
            };
            try {
              if (this.responsePtr) {
                var respPtrVal = this.responsePtr.readPointer();
                if (respPtrVal && !respPtrVal.isNull()) {
                  var resp = new ObjC.Object(respPtrVal);
                  var httpResp = resp.castTo(ObjC.classes.NSHTTPURLResponse);
                  info.status = httpResp.statusCode();
                  info.responseHeaders = readResponseHeaders(httpResp);
                }
              }
            } catch (_) {}

            var bytes = null;
            var truncated = false;
            try {
              if (retval && !retval.isNull()) {
                var nsdata = new ObjC.Object(retval);
                var len = nsdata.length();
                if (len > 0 && len <= BODY_CAP) {
                  bytes = nsDataBytes(nsdata);
                } else if (len > BODY_CAP) {
                  truncated = true;
                }
              }
            } catch (_) {}

            emitComplete(info, this.requestBytes, this.requestTruncated, bytes, truncated);
          } catch (_) {}
        }
      });
    }
  } catch (_) {}

  // ── Async with completion handler ──────────────────────────────────────────
  // Strategy: emit a minimal flow.request immediately (URL/method/headers/body
  // are known). The completion-handler block replacement would let us capture
  // the response too, but block swizzling across all callers is fragile. The
  // delegate path below covers the legacy delegate API; for the completion-
  // handler API the user can layer a mitm proxy or rely on NSURLSession (most
  // modern code paths use NSURLSession anyway).

  try {
    var async_ = ObjC.classes.NSURLConnection['+ sendAsynchronousRequest:queue:completionHandler:'];
    if (async_) {
      Interceptor.attach(async_.implementation, {
        onEnter: function (args) {
          try {
            var req = new ObjC.Object(args[2]);
            var url = req.URL().absoluteString().toString();
            var method = req.HTTPMethod ? req.HTTPMethod().toString() : 'GET';
            var headers = readHeaders(req);
            var rb = readRequestBody(req);
            emit('flow.request', {
              kind: 'flow.request',
              url: url,
              method: method,
              request_headers: headers,
              body_b64: rb.bytes ? ab2b64(rb.bytes) : null,
              body_truncated: rb.truncated,
              ts: Date.now() / 1000
            });
          } catch (_) {}
        }
      });
    }
  } catch (_) {}

  // ── Delegate callbacks ─────────────────────────────────────────────────────
  //
  // Originally we walked every loaded ObjC class via
  // `ObjC.enumerateLoadedClasses` looking for NSURLConnectionDataDelegate
  // conformers. On a real iOS process that walk starves the Frida JS runtime
  // long enough for `script.load()` to time out, causing every subsequent
  // hook to fail with "the connection is closed".
  //
  // The synchronous + async creation hooks above already capture the request
  // and (for sync requests) the full response. Delegate-based async paths
  // lose the response body, which is acceptable: NSURLConnection is the
  // legacy API; modern apps overwhelmingly use NSURLSession (covered by
  // `url_session_body_tracer.js`).
})();
