const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(ROOT, 'contentScript.js'), 'utf8');
const origin = 'https://www.layerwallet.com';
const listeners = [];
const postedMessages = [];
const runtimeMessages = [];

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
windowObj.crypto = { randomUUID: () => 'content-session' };
windowObj.document = {
  createElement: () => ({
    dataset: {},
    remove() {},
  }),
  head: {
    appendChild(script) {
      if (typeof script.onload === 'function') script.onload();
    },
  },
  documentElement: {
    appendChild(script) {
      if (typeof script.onload === 'function') script.onload();
    },
  },
};

windowObj.addEventListener = (type, handler) => {
  if (type === 'message') listeners.push(handler);
};

windowObj.postMessage = (data, targetOrigin) => {
  postedMessages.push({ data, targetOrigin });
};

windowObj.chrome = {
  runtime: {
    getURL: (file) => `chrome-extension://unit/${file}`,
    lastError: null,
    onMessage: {
      addListener() {},
    },
    sendMessage(message, callback) {
      runtimeMessages.push(message);
      callback({
        success: true,
        result: dummyAccounts,
      });
    },
  },
};

vm.createContext(windowObj);
vm.runInContext(source, windowObj, { filename: 'contentScript.js' });
vm.runInContext('globalThis.__sourceRef = window;', windowObj);

const dispatchPageMessage = (data) => {
  const event = {
    source: windowObj.__sourceRef || windowObj,
    origin,
    data,
  };
  for (const handler of listeners) handler(event);
};

const fail = (message) => {
  throw new Error(message);
};

dispatchPageMessage({
  type: 'request',
  data: {
    id: 7,
    method: 'requestAccounts',
    params: { network: 'LTCTEST' },
  },
});

const legacyRuntime = runtimeMessages[0];
if (!legacyRuntime) fail('Legacy request did not reach runtime.');
if (legacyRuntime.channel !== 'tradelayer-provider') fail('Legacy request used wrong channel.');
if (legacyRuntime.type !== 'providerRequest') fail('Legacy request used wrong runtime type.');
if (legacyRuntime.data.id !== '7') fail(`Legacy id was not string-normalized: ${legacyRuntime.data.id}`);
if (legacyRuntime.data.method !== 'requestAccounts') fail(`Wrong legacy method: ${legacyRuntime.data.method}`);
if (legacyRuntime.data.params.network !== 'LTCTEST') fail('Legacy network param was not forwarded.');
if (legacyRuntime.data.params.__legacyBridge !== true) {
  fail('Legacy request was not marked for compatibility network selection.');
}

const legacyResponse = postedMessages.find((item) => item.data?.type === 'response');
if (!legacyResponse) fail('Legacy response was not posted.');
if (!Array.isArray(legacyResponse.data.data.result)) fail('Legacy response missing data.result.');
if (!Array.isArray(legacyResponse.data.data.payload?.result)) fail('Legacy response missing data.payload.result.');
if (legacyResponse.data.data.id !== 7) fail('Legacy response id changed.');

// A page cannot choose the legacy network rules by sending the flag itself: the flag is set by the
// bridge that received the request, never copied from the page.
dispatchPageMessage({
  channel: 'tradelayer-provider',
  sessionId: 'content-session',
  type: 'request',
  data: {
    id: 'forged-flag',
    method: 'requestAccounts',
    params: { network: 'LTCTEST', __legacyBridge: true },
  },
});
const forgedRuntime = runtimeMessages[runtimeMessages.length - 1];
if (forgedRuntime?.data?.id !== 'forged-flag') fail('Forged-flag request did not reach runtime.');
if (forgedRuntime.data.params.__legacyBridge === true) {
  fail('A page-supplied __legacyBridge flag reached the background on a modern request.');
}

console.log('[unit] legacy content bridge ok', legacyResponse.data.data.result);
