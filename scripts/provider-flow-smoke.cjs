const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.resolve(__dirname, '..');
const WINDOW_JS = path.join(ROOT, 'window.js');

const source = fs.readFileSync(WINDOW_JS, 'utf8');
const listeners = new Set();
const origin = 'http://unit.test';
const sessionId = 'unit-session';
const dummyAccounts = [
  {
    address: 'tltc1qdummytestaddress0000000000000000000',
    pubkey: '02d34db33fd34db33fd34db33fd34db33fd34db33fd34db33fd34db33fd34db33f',
  },
];

const windowObj = {};
windowObj.window = windowObj;
windowObj.globalThis = windowObj;
windowObj.location = { origin };
windowObj.console = console;
windowObj.queueMicrotask = queueMicrotask;
windowObj.setTimeout = setTimeout;
windowObj.clearTimeout = clearTimeout;
windowObj.crypto = {
  randomUUID: () => '00000000-0000-4000-8000-000000000001',
};

windowObj.document = {
  currentScript: {
    dataset: {
      tradelayerSessionId: sessionId,
      tradelayerOrigin: origin,
    },
  },
  querySelector: () => ({
    dataset: {
      tradelayerSessionId: sessionId,
      tradelayerOrigin: origin,
    },
  }),
};

windowObj.addEventListener = (type, handler) => {
  if (type === 'message') {
    listeners.add(handler);
  }
};

windowObj.removeEventListener = (type, handler) => {
  if (type === 'message') {
    listeners.delete(handler);
  }
};

windowObj.postMessage = (data, targetOrigin) => {
  console.log('[unit] postMessage', { targetOrigin, type: data?.type, data });
  const event = {
    source: windowObj.__sourceRef || windowObj,
    origin: targetOrigin,
    data,
  };

  for (const handler of [...listeners]) {
    try {
      handler(event);
    } catch (error) {
      console.error('[unit] handler error:', error);
    }
  }
};

windowObj.__TRADELAYER_DEBUG__ = true;

vm.createContext(windowObj);
vm.runInContext(source, windowObj, { filename: 'window.js' });
vm.runInContext('globalThis.__sourceRef = window;', windowObj);

if (!windowObj.tradelayer) {
  throw new Error('Modern provider was not injected.');
}

if (!windowObj.myWallet) {
  throw new Error('Legacy myWallet provider was not injected.');
}

if (windowObj.myWallet !== windowObj.tradelayer) {
  throw new Error('window.myWallet is not aliased to window.tradelayer.');
}

if (typeof windowObj.myWallet.sendRequest !== 'function') {
  throw new Error('window.myWallet.sendRequest is unavailable.');
}

windowObj.addEventListener('message', (event) => {
  const message = event.data;
  if (!message || message.channel !== 'tradelayer-provider' || message.sessionId !== sessionId) {
    return;
  }

  if (message.type !== 'request') {
    return;
  }

  const { id, method, params } = message.data || {};
  console.log('[unit] request', { id, method, params });

  if (method !== 'requestAccounts' && method !== 'connect' && method !== 'signPSBT') {
    console.log('[unit] sending error response', { id, method });
    windowObj.postMessage(
      {
        channel: 'tradelayer-provider',
        sessionId,
        type: 'response',
        data: { id, success: false, error: `Unsupported method: ${method}` },
      },
      origin
    );
    return;
  }

  console.log('[unit] sending success response', { id, method });
  windowObj.postMessage(
    {
      channel: 'tradelayer-provider',
      sessionId,
      type: 'response',
      data: { id, success: true, result: dummyAccounts },
    },
    origin
  );
});

const assertAccounts = async (label, value) => {
  if (!Array.isArray(value) || value.length === 0 || !value[0]?.address) {
    throw new Error(`${label} did not resolve accounts: ${JSON.stringify(value)}`);
  }
  console.log(`[unit] ${label} ok`, value);
};

(async () => {
  const requestAccounts = await windowObj.tradelayer.requestAccounts('LTCTEST');
  await assertAccounts('requestAccounts', requestAccounts);

  const connectAccounts = await windowObj.tradelayer.connect('LTCTEST');
  await assertAccounts('connect', connectAccounts);

  const directAccounts = await windowObj.tradelayer.request({
    method: 'requestAccounts',
    params: { network: 'LTCTEST' },
  });
  await assertAccounts('direct request', directAccounts);

  const legacyAccounts = await windowObj.myWallet.sendRequest('requestAccounts', {
    network: 'LTCTEST',
  });
  await assertAccounts('legacy myWallet.sendRequest', legacyAccounts);

  const legacyPsbt = await windowObj.myWallet.sendRequest('signPSBT', {
    network: 'LTCTEST',
    transaction: '70736274ff',
  });
  await assertAccounts('legacy signPSBT passthrough', legacyPsbt);

  console.log('[unit] provider smoke test passed');
})().catch((error) => {
  console.error('[unit] provider smoke test failed:', error);
  process.exitCode = 1;
});
