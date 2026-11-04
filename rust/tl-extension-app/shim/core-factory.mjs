// Loads tl_extension_wasm.wasm (raw ABI, see rust/tl-extension-app/wasm/src/lib.rs) and
// exposes one synchronous function, call(request) -> response, over JSON.
//
// Storage and entropy are injected so the same code runs in the popup (localStorage,
// crypto.getRandomValues) and in a Node test (an in-memory Storage).

const MAX_VALUE = 1 << 20;
const STORE_IO_ERROR = 0x7fffffff; // length larger than MAX_VALUE: the module treats it as an I/O error

/**
 * @param {object} opts
 * @param {Response|Promise<Response>|ArrayBuffer|Uint8Array} opts.wasm
 * @param {{getItem(k:string):string|null,setItem(k:string,v:string):void,removeItem(k:string):void,key(i:number):string|null,length:number}} opts.storage
 * @param {{getRandomValues(a:Uint8Array):Uint8Array}} opts.crypto
 * @param {() => number} [opts.nowSeconds]
 */
export async function createCore({ wasm, storage, crypto, nowSeconds }) {
  const enc = new TextEncoder();
  const dec = new TextDecoder('utf-8', { fatal: true });
  let exports_ = null;
  const mem = () => new Uint8Array(exports_.memory.buffer);
  const readStr = (ptr, len) => dec.decode(mem().subarray(ptr, ptr + len));

  const storeGet = (kp, kl, out, cap) => {
    try {
      const v = storage.getItem(readStr(kp, kl));
      if (v === null || v === undefined) return -1;
      const bytes = enc.encode(v);
      if (bytes.length <= cap) mem().set(bytes, out);
      return bytes.length;
    } catch {
      return STORE_IO_ERROR;
    }
  };

  const storeCas = (kp, kl, hasExpected, ep, el, hasNew, np, nl) => {
    try {
      const key = readStr(kp, kl);
      const current = storage.getItem(key);
      const expected = hasExpected ? readStr(ep, el) : null;
      if ((current ?? null) !== expected) return 1;
      if (hasNew) storage.setItem(key, readStr(np, nl));
      else storage.removeItem(key);
      return 0;
    } catch {
      return 2;
    }
  };

  const storeKeys = (out, cap) => {
    try {
      const keys = [];
      for (let i = 0; i < storage.length; i += 1) keys.push(storage.key(i));
      const bytes = enc.encode(keys.filter((k) => k !== null && !k.includes('\n')).join('\n'));
      if (bytes.length <= cap) mem().set(bytes, out);
      return bytes.length;
    } catch {
      return STORE_IO_ERROR;
    }
  };

  const randomFill = (out, len) => {
    try {
      let done = 0;
      while (done < len) {
        const n = Math.min(65536, len - done);
        const chunk = new Uint8Array(n);
        crypto.getRandomValues(chunk);
        mem().set(chunk, out + done);
        chunk.fill(0);
        done += n;
      }
      return 0;
    } catch {
      return 1;
    }
  };

  const imports = {
    tlx: { store_get: storeGet, store_cas: storeCas, store_keys: storeKeys, random_fill: randomFill },
  };

  let instance;
  if (typeof Response !== 'undefined' && (wasm instanceof Response || typeof wasm?.then === 'function')) {
    ({ instance } = await WebAssembly.instantiateStreaming(wasm, imports));
  } else {
    ({ instance } = await WebAssembly.instantiate(wasm, imports));
  }
  exports_ = instance.exports;

  const clock = nowSeconds || (() => Math.floor(Date.now() / 1000));

  /** Send one request object, get the parsed response ({ok:true,...} or {ok:false,code,message}). */
  function call(request) {
    const body = enc.encode(JSON.stringify({ ...request, now: clock() }));
    const reqPtr = exports_.tlx_alloc(body.length);
    if (!reqPtr) return { ok: false, code: 'Alloc', message: 'request too large' };
    mem().set(body, reqPtr);
    body.fill(0);
    const respPtr = exports_.tlx_call(reqPtr, body.length);
    exports_.tlx_free(reqPtr, body.length); // zeroes it again
    if (!respPtr) return { ok: false, code: 'Call', message: 'module rejected the request' };
    const view = new DataView(exports_.memory.buffer);
    const len = view.getUint32(respPtr, true);
    const text = dec.decode(mem().subarray(respPtr + 4, respPtr + 4 + len));
    exports_.tlx_free(respPtr, 4 + len);
    return JSON.parse(text);
  }

  return { call, MAX_VALUE };
}
