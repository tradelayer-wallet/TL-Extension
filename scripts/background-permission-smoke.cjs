const fs = require('fs');
const path = require('path');
const vm = require('vm');
const esbuild = require('esbuild');

const ROOT = path.resolve(__dirname, '..');
// The worker imports the shared network table, so it is bundled the way the build ships it.
const source = esbuild.buildSync({
  entryPoints: [path.join(ROOT, 'background', 'background.js')],
  bundle: true,
  format: 'iife',
  platform: 'browser',
  write: false,
}).outputFiles[0].text;
const origin = 'https://layerwallet.com';
const popupUrl = 'chrome-extension://unit/popup/popup.html';
const accounts = [{
  address: 'tltc1qdummytestaddress0000000000000000000',
  pubkey: '02d34db33fd34db33fd34db33fd34db33fd34db33fd34db33fd34db33fd34db33f',
  network: 'LTCTEST',
}];
const storage = {
  addresses: accounts,
  sitePermissionsV1: {},
};
const runtimeListeners = [];
const windowsRemovedListeners = [];
const runtimeMessages = [];
let createdWindows = 0;

const chrome = {
  storage: {
    local: {
      get(keys, callback) {
        const result = {};
        for (const key of keys) result[key] = storage[key];
        callback(result);
      },
      set(items, callback) {
        Object.assign(storage, items);
        callback();
      },
    },
  },
  runtime: {
    getURL(file) {
      return `chrome-extension://unit/${file}`;
    },
    sendMessage(message, callback) {
      runtimeMessages.push(message);
      callback({ success: true });
    },
    onMessage: {
      addListener(listener) {
        runtimeListeners.push(listener);
      },
    },
    id: 'unit',
    lastError: null,
  },
  windows: {
    create(_options, callback) {
      createdWindows += 1;
      callback({ id: createdWindows });
    },
    remove(_windowId, callback) {
      callback();
    },
    onRemoved: {
      addListener(listener) {
        windowsRemovedListeners.push(listener);
      },
    },
  },
  tabs: {
    sendMessage(_tabId, _message, _options, callback) {
      callback();
    },
  },
};

const context = {
  chrome,
  console,
  URL,
  URLSearchParams,
  Map,
  Set,
  Promise,
  String,
  Number,
  Array,
  Object,
  Error,
};
vm.createContext(context);
vm.runInContext(source, context, { filename: 'background.js' });

if (runtimeListeners.length !== 1) {
  throw new Error('Background message listener was not registered.');
}

const listener = runtimeListeners[0];
const pageSender = { id: 'unit', origin, url: `${origin}/provider-smoke`, tab: { id: 1 }, frameId: 0 };
const untrustedOrigin = 'https://untrusted.example';
const untrustedSender = {
  id: 'unit',
  origin: untrustedOrigin,
  url: `${untrustedOrigin}/provider-smoke`,
  tab: { id: 2 },
  frameId: 0,
};
const popupSender = { id: 'unit', url: `${popupUrl}?step=13&message=unit-sign` };

const send = (message, sender = pageSender) => new Promise((resolve) => {
  listener(message, sender, resolve);
});

const providerRequest = (id, method, params = {}) => ({
  channel: 'tradelayer-provider',
  type: 'providerRequest',
  data: { id, method, params },
});

const settle = async (done) => {
  for (let attempt = 0; attempt < 50 && !done(); attempt += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
};

const expectFailure = async (label, request, pattern, sender = pageSender) => {
  const response = await send(request, sender);
  if (response?.success !== false || !pattern.test(response.error || '')) {
    throw new Error(`${label} unexpectedly succeeded: ${JSON.stringify(response)}`);
  }
};

const main = async () => {
  await expectFailure(
    'untrusted origin requestAccounts',
    providerRequest('untrusted-accounts', 'requestAccounts', { network: 'LTCTEST' }),
    /origin is not allowed/i,
    untrustedSender
  );

  await expectFailure(
    'untrusted origin signMessage',
    providerRequest('untrusted-sign', 'signMessage', { network: 'LTCTEST', message: 'test message' }),
    /origin is not allowed/i,
    untrustedSender
  );

  await expectFailure(
    'unapproved legacy requestAccounts',
    providerRequest('legacy-unapproved-accounts', 'requestAccounts', {
      network: 'LTCTEST',
      __legacyBridge: true,
    }),
    /not approved for LTCTEST/
  );

  await expectFailure(
    'unapproved legacy signMessage',
    providerRequest('legacy-unapproved-sign', 'signMessage', {
      network: 'LTCTEST',
      message: 'test message',
      __legacyBridge: true,
    }),
    /not approved for LTCTEST/
  );

  await expectFailure(
    'unapproved legacy inferred-network signMessage',
    providerRequest('legacy-unapproved-inferred-sign', 'signMessage', {
      message: 'test message',
      __legacyBridge: true,
    }),
    /not approved for LTCTEST/
  );

  if (createdWindows !== 0) {
    throw new Error('Unapproved legacy signing opened an approval window.');
  }

  storage.sitePermissionsV1 = { [origin]: ['LTCTEST'] };
  const accountResponse = await send(
    providerRequest('modern-approved-accounts', 'requestAccounts', { network: 'LTCTEST' }),
    pageSender
  );
  if (accountResponse?.success !== true || accountResponse.result?.[0]?.address !== accounts[0].address) {
    throw new Error(`Approved requestAccounts did not return accounts: ${JSON.stringify(accountResponse)}`);
  }

  const legacyAccountResponse = await send(
    providerRequest('legacy-approved-accounts', 'requestAccounts', {
      network: 'LTCTEST',
      __legacyBridge: true,
    }),
    pageSender
  );
  if (legacyAccountResponse?.success !== true || legacyAccountResponse.result?.[0]?.address !== accounts[0].address) {
    throw new Error(`Approved legacy requestAccounts did not return accounts: ${JSON.stringify(legacyAccountResponse)}`);
  }

  await expectFailure(
    'approved origin with unapproved network requestAccounts',
    providerRequest('approved-origin-wrong-network', 'requestAccounts', { network: 'LTC' }),
    /not approved for LTC/
  );

  await expectFailure(
    'approved origin with unapproved network signMessage',
    providerRequest('approved-origin-wrong-network-sign', 'signMessage', { network: 'LTC', message: 'test message' }),
    /not approved for LTC/
  );

  if (createdWindows !== 0) {
    throw new Error('Unapproved network signing opened an approval window.');
  }

  let modernSignResponse;
  listener(
    providerRequest('modern-approved-sign', 'signMessage', {
      network: 'LTCTEST',
      message: 'modern test message',
    }),
    pageSender,
    (response) => {
      modernSignResponse = response;
    }
  );

  for (let attempt = 0; attempt < 10 && createdWindows === 0 && !modernSignResponse; attempt += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
  if (createdWindows === 0) {
    throw new Error(`Approved modern sign did not open its approval window: ${JSON.stringify(modernSignResponse)}`);
  }
  const modernPopupReady = await send(
    { method: 'popupReady', payload: { requestId: 'modern-approved-sign' } },
    popupSender
  );
  if (modernPopupReady?.success !== true) {
    throw new Error(`Approved modern sign did not reach the popup: ${JSON.stringify(modernPopupReady)}`);
  }
  const modernSignMessage = runtimeMessages.find(
    (message) => message.method === 'signMessageRequest' && message.payload.requestId === 'modern-approved-sign'
  );
  if (modernSignMessage?.payload.network !== 'LTCTEST') {
    throw new Error(`Approved modern sign was not routed with its approved network: ${JSON.stringify(runtimeMessages)}`);
  }
  const modernRejected = await send(
    {
      method: 'rejectPendingRequest',
      payload: { requestId: 'modern-approved-sign', reason: 'smoke complete' },
    },
    popupSender
  );
  if (modernRejected?.success !== true || modernSignResponse?.success !== false) {
    throw new Error('Approved modern sign request did not remain pending for popup approval.');
  }

  let signResponse;
  const signRequest = providerRequest('legacy-approved-sign', 'signMessage', {
    network: 'LTCTEST',
    message: 'test message',
    __legacyBridge: true,
  });
  listener(signRequest, pageSender, (response) => {
    signResponse = response;
  });

  for (let attempt = 0; attempt < 10 && createdWindows < 2 && !signResponse; attempt += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
  if (createdWindows < 2) {
    throw new Error(`Approved legacy sign did not open its approval window: ${JSON.stringify(signResponse)}`);
  }
  const popupReady = await send(
    { method: 'popupReady', payload: { requestId: 'legacy-approved-sign' } },
    popupSender
  );
  if (popupReady?.success !== true) {
    throw new Error(`Approved legacy sign did not reach the popup: ${JSON.stringify(popupReady)}`);
  }

  const signMessage = runtimeMessages.find(
    (message) => message.method === 'signMessageRequest' && message.payload.requestId === 'legacy-approved-sign'
  );
  if (
    !signMessage ||
    signMessage.payload.requestId !== 'legacy-approved-sign' ||
    signMessage.payload.network !== 'LTCTEST'
  ) {
    throw new Error(`Approved legacy sign was not routed with its approved network: ${JSON.stringify(runtimeMessages)}`);
  }

  const rejected = await send(
    {
      method: 'rejectPendingRequest',
      payload: { requestId: 'legacy-approved-sign', reason: 'smoke complete' },
    },
    popupSender
  );
  if (rejected?.success !== true || signResponse?.success !== false) {
    throw new Error('Approved legacy sign request did not remain pending for popup approval.');
  }

  await expectFailure(
    'extension options page cannot approve',
    { method: 'approvalDecision', payload: { requestId: 'legacy-approved-sign', approved: true } },
    /invalid sender/,
    { id: 'unit', url: 'chrome-extension://unit/options.html' }
  );
  await expectFailure(
    'foreign extension cannot approve',
    { method: 'approvalDecision', payload: { requestId: 'legacy-approved-sign', approved: true } },
    /invalid sender/,
    { id: 'other-extension', url: 'chrome-extension://other-extension/popup/popup.html' }
  );
  await expectFailure(
    'page sender cannot approve a connect request',
    { method: 'approvalDecision', payload: { requestId: 'legacy-approved-sign', approved: true } },
    /invalid sender/,
    pageSender
  );

  // A request id reused by the same page is refused, and must not cancel the request that owns the id.
  const firstResponses = [];
  const windowsBeforeDuplicate = createdWindows;
  listener(providerRequest('dup-id', 'signMessage', { network: 'LTCTEST', message: 'first' }), pageSender, (response) => {
    firstResponses.push(response);
  });
  await settle(() => createdWindows > windowsBeforeDuplicate);
  await expectFailure(
    'duplicate request id',
    providerRequest('dup-id', 'signMessage', { network: 'LTCTEST', message: 'second' }),
    /Duplicate request id/
  );
  const cancelled = await send({ method: 'rejectPendingRequest', payload: { requestId: 'dup-id', reason: 'smoke dup' } }, popupSender);
  if (cancelled?.success !== true) {
    throw new Error(`A duplicate request id removed the pending request it duplicated: ${JSON.stringify(cancelled)}`);
  }
  await settle(() => firstResponses.length > 0);
  if (firstResponses[0]?.success !== false || !/smoke dup/.test(firstResponses[0].error || '')) {
    throw new Error(`The original request was not answered by its rejection: ${JSON.stringify(firstResponses)}`);
  }

  // An approval that cannot produce accounts grants nothing and answers the waiting page.
  const connectResponses = [];
  const windowsBeforeConnect = createdWindows;
  listener(providerRequest('connect-no-ltc', 'connect', { network: 'LTC' }), pageSender, (response) => {
    connectResponses.push(response);
  });
  await settle(() => createdWindows > windowsBeforeConnect);
  await send(
    { method: 'approvalDecision', payload: { requestId: 'connect-no-ltc', approved: true } },
    popupSender
  );
  await settle(() => connectResponses.length > 0);
  if (storage.sitePermissionsV1[origin].includes('LTC')) {
    throw new Error('An approval with no LTC account still granted LTC to the origin.');
  }
  if (connectResponses[0]?.success !== false) {
    throw new Error(`The waiting connect request was not answered after the failed approval: ${JSON.stringify(connectResponses)}`);
  }

  // Network aliases name one network everywhere: each spelling a wallet accepts resolves to it.
  storage.addresses.push({ address: 'DDummyDogecoinAddress00000000000000', pubkey: null, network: 'DOGE' });
  storage.sitePermissionsV1 = { [origin]: ['LTCTEST', 'DOGE'] };
  for (const alias of ['tltc', 'TESTNET', 'litecoin-testnet']) {
    const response = await send(providerRequest(`alias-${alias}`, 'requestAccounts', { network: alias }), pageSender);
    if (response?.success !== true || response.result?.[0]?.address !== accounts[0].address) {
      throw new Error(`Network alias ${alias} did not resolve to LTCTEST: ${JSON.stringify(response)}`);
    }
  }
  const dogeResponse = await send(providerRequest('alias-dogecoin', 'requestAccounts', { network: 'dogecoin' }), pageSender);
  if (dogeResponse?.success !== true || dogeResponse.result?.[0]?.network !== 'DOGE') {
    throw new Error(`Network alias dogecoin did not resolve to DOGE: ${JSON.stringify(dogeResponse)}`);
  }

  console.log('[unit] background permission smoke test passed');
};

main().catch((error) => {
  console.error('[unit] background permission smoke test failed:', error);
  process.exitCode = 1;
});
