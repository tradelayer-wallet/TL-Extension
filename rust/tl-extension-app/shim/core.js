// The wasm core for extension pages. Top-level await: the bundle is an ES module, and the
// legacy components call the shimmed wallet functions synchronously, so the module must be
// ready before React renders.
import { createCore } from './core-factory.mjs';

const core = await createCore({
  wasm: fetch(chrome.runtime.getURL('wasm/tl_extension_wasm.wasm')),
  storage: window.localStorage,
  crypto: window.crypto,
});

export default core;
