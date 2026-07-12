const CHANNEL = 'tradelayer-provider';
const SITE_PERMISSIONS_KEY = 'sitePermissionsV1';
const ACTIVE_ACCOUNTS_KEY = 'activeAccountsV1';
const APPROVED_HTTPS_ORIGINS = new Set([
  'https://layerwallet.com',
  'https://www.layerwallet.com',
  'https://testnet.layerwallet.com',
]);
// The development package generator changes this in its staged copy only.
const ALLOW_DEVELOPMENT_ORIGINS = false;
const PAGE_METHODS = new Set([
  'connect',
  'requestAccounts',
  'signMessage',
  'signPsbt',
  'signTransaction',
  'addMultisig',
  'fetchUserIP',
  'keepAlive',
]);
const DEBUG = !!globalThis.__TRADELAYER_DEBUG__;

const debugLog = (...args) => {
  if (DEBUG) {
    console.log('[tl-background]', ...args);
  }
};

const normalizeProviderMethod = (method) => {
  if (method === 'signPSBT') return 'signPsbt';
  return method;
};

const pendingRequests = new Map();

let popupWindowId = null;
let popupRequestId = null;

const storageGet = (keys) =>
  new Promise((resolve) => chrome.storage.local.get(keys, resolve));

const storageSet = (items) =>
  new Promise((resolve) => chrome.storage.local.set(items, resolve));

const sendRuntimeMessage = (message) =>
  new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      resolve(response);
    });
  });

const createPopupWindow = (url) =>
  new Promise((resolve, reject) => {
    chrome.windows.create(
      {
        url,
        type: 'popup',
        width: 420,
        height: 640,
      },
      (window) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        resolve(window);
      }
    );
  });

const removeWindow = (windowId) =>
  new Promise((resolve) => {
    chrome.windows.remove(windowId, () => {
      void chrome.runtime.lastError;
      resolve();
    });
  });

const normalizeNetworkId = (network) => {
  const value = String(network || 'LTC').trim().toUpperCase();

  if (value === 'TLTC' || value === 'TLTCTEST') return 'LTCTEST';
  if (value === 'LITECOIN-TESTNET' || value === 'LITECOIN_TESTNET') return 'LTCTEST';
  if (value === 'LITECOIN' || value === 'LTCMAINNET' || value === 'MAINNET') return 'LTC';
  if (value === 'TESTNET') return 'LTCTEST';
  if (value === 'LTC' || value === 'LTCTEST') return value;

  return value;
};

const getSenderOrigin = (sender) => {
  const candidate =
    sender.origin ||
    sender.url ||
    sender.documentUrl ||
    sender.tab?.url ||
    null;

  if (!candidate) return null;

  try {
    return new URL(candidate).origin;
  } catch {
    return null;
  }
};

const isAllowedOrigin = (origin) => {
  if (!origin) return false;

  try {
    const url = new URL(origin);
    if (ALLOW_DEVELOPMENT_ORIGINS &&
      url.protocol === 'http:' &&
      (url.hostname === 'localhost' || url.hostname === '127.0.0.1')
    ) {
      return true;
    }

    return url.protocol === 'https:' && APPROVED_HTTPS_ORIGINS.has(url.origin);
  } catch {
    return false;
  }
};

const getSenderContext = (sender) => {
  const origin = getSenderOrigin(sender);
  const tabId = sender.tab?.id;

  if (!origin || tabId == null) return null;

  return {
    origin,
    tabId,
    frameId: sender.frameId ?? 0,
  };
};

const isPopupSender = (sender) => {
  const popupUrl = chrome.runtime.getURL('popup/popup.html');
  return typeof sender.url === 'string' && sender.url.startsWith(popupUrl);
};

const getPopupUrl = (step, requestId) => {
  const params = new URLSearchParams();
  params.set('step', String(step));
  params.set('message', String(requestId));
  return chrome.runtime.getURL(`popup/popup.html?${params.toString()}`);
};

const respondSuccess = (sendResponse, result) => {
  sendResponse({ success: true, result });
};

const respondError = (sendResponse, error) => {
  const message =
    typeof error === 'string'
      ? error
      : typeof error?.message === 'string'
        ? error.message
        : 'Unknown extension error';

  sendResponse({ success: false, error: message });
};

const sendProviderEvent = (context, event, payload) => {
  chrome.tabs.sendMessage(
    context.tabId,
    {
      channel: CHANNEL,
      type: 'providerEvent',
      event,
      payload,
    },
    { frameId: context.frameId },
    () => {
      void chrome.runtime.lastError;
    }
  );
};

const getSitePermissions = async () => {
  const stored = await storageGet([SITE_PERMISSIONS_KEY]);
  return stored[SITE_PERMISSIONS_KEY] || {};
};

const getApprovedNetworks = async (origin) => {
  const permissions = await getSitePermissions();
  const networks = permissions[origin];
  return Array.isArray(networks) ? networks : [];
};

const inferNetworkFromAddress = (address) => {
  if (typeof address !== 'string') return null;
  const value = address.trim().toLowerCase();

  if (value.startsWith('tltc')) return 'LTCTEST';
  if (value.startsWith('ltc')) return 'LTC';

  return null;
};

const normalizeStoredAddressRecord = (item) => {
  if (typeof item === 'string') {
    return {
      address: item,
      pubkey: null,
      network: normalizeNetworkId(inferNetworkFromAddress(item)),
    };
  }

  if (!item || typeof item.address !== 'string') return null;

  const network = normalizeNetworkId(
    item.network ||
    item.networkId ||
    inferNetworkFromAddress(item.address)
  );

  return {
    address: item.address,
    pubkey: item.pubkey || item.publicKey || null,
    network,
    derivationPath: item.derivationPath || item.path || null,
  };
};

const grantSitePermission = async (origin, network) => {
  const normalized = normalizeNetworkId(network);
  const permissions = await getSitePermissions();
  const approvedNetworks = Array.isArray(permissions[origin]) ? permissions[origin] : [];

  if (!approvedNetworks.includes(normalized)) {
    permissions[origin] = [...approvedNetworks, normalized];
    await storageSet({ [SITE_PERMISSIONS_KEY]: permissions });
  }

  return permissions[origin];
};

const resolveApprovedNetwork = async (origin, network) => {
  const requested = network ? normalizeNetworkId(network) : null;
  const approvedNetworks = await getApprovedNetworks(origin);

  if (requested) {
    if (!approvedNetworks.includes(requested)) {
      throw new Error(`Origin ${origin} is not approved for ${requested}.`);
    }
    return requested;
  }

  if (!approvedNetworks.length) {
    throw new Error(`Origin ${origin} is not approved.`);
  }

  return approvedNetworks[0];
};

const getAddressesForNetwork = async (network) => {
  const normalized = normalizeNetworkId(network);
  const { addresses = [], [ACTIVE_ACCOUNTS_KEY]: activeAccounts = {} } = await storageGet([
    'addresses',
    ACTIVE_ACCOUNTS_KEY,
  ]);
  const filtered = (addresses || [])
    .map(normalizeStoredAddressRecord)
    .filter((item) => item && item.network === normalized);

  if (!filtered.length) {
    throw new Error(`No ${normalized} address is available in wallet storage.`);
  }

  const activeAddress = activeAccounts?.[normalized];
  if (activeAddress) {
    const activeIndex = filtered.findIndex((item) => item.address === activeAddress);
    if (activeIndex > 0) {
      const [active] = filtered.splice(activeIndex, 1);
      filtered.unshift(active);
    }
  }

  return filtered;
};

const getPreferredLegacyNetwork = async (network) => {
  if (network) return normalizeNetworkId(network);

  const { addresses = [] } = await storageGet(['addresses']);
  const normalizedAccounts = (addresses || [])
    .map(normalizeStoredAddressRecord)
    .filter(Boolean);

  if (normalizedAccounts.length === 1) {
    return normalizedAccounts[0].network;
  }

  if (normalizedAccounts.some((item) => item.network === 'LTCTEST')) {
    return 'LTCTEST';
  }

  if (normalizedAccounts.some((item) => item.network === 'LTC')) {
    return 'LTC';
  }

  return 'LTC';
};

const resolveRequestNetwork = async (origin, params) => {
  const network = params?.__legacyBridge
    ? await getPreferredLegacyNetwork(params?.network)
    : params?.network;

  return resolveApprovedNetwork(origin, network);
};

const getExistingMultisig = async (m, pubkeys, network) => {
  const normalized = normalizeNetworkId(network);
  const { multisigs = [] } = await storageGet(['multisigs']);

  return (multisigs || []).find(
    (item) =>
      item?.m === m &&
      Array.isArray(item.pubkeys) &&
      item.pubkeys.length === pubkeys.length &&
      item.pubkeys.every((pubkey, index) => pubkey === pubkeys[index]) &&
      typeof item.address === 'string' &&
      normalizeNetworkId(item.network || inferNetworkFromAddress(item.address)) === normalized
  );
};

const ensurePopup = async (step, requestId) => {
  if (popupWindowId != null) {
    await removeWindow(popupWindowId);
  }

  popupWindowId = null;
  popupRequestId = requestId;

  const popupWindow = await createPopupWindow(getPopupUrl(step, requestId));
  popupWindowId = popupWindow?.id ?? null;
};

const closePopup = async () => {
  const currentWindowId = popupWindowId;
  popupWindowId = null;
  popupRequestId = null;

  if (currentWindowId != null) {
    await removeWindow(currentWindowId);
  }
};

const createPendingRequest = (requestId, kind, context, params, sendResponse) => {
  if (pendingRequests.has(requestId)) {
    throw new Error(`Duplicate request id: ${requestId}`);
  }

  pendingRequests.set(requestId, {
    kind,
    context,
    params,
    sendResponse,
  });
};

const settlePendingRequest = async (requestId, handler) => {
  const pending = pendingRequests.get(requestId);
  if (!pending) {
    throw new Error(`No pending request found for ${requestId}.`);
  }

  pendingRequests.delete(requestId);

  if (popupRequestId === requestId) {
    await closePopup();
  }

  await handler(pending);
};

const rejectPendingRequest = async (requestId, reason) => {
  await settlePendingRequest(requestId, async (pending) => {
    respondError(pending.sendResponse, reason || 'The request was rejected.');
  });
};

const resolvePendingRequest = async (requestId, result) => {
  await settlePendingRequest(requestId, async (pending) => {
    respondSuccess(pending.sendResponse, result);
  });
};

const dispatchPendingRequestToPopup = async (requestId) => {
  const pending = pendingRequests.get(requestId);
  if (!pending) {
    throw new Error(`No pending request found for ${requestId}.`);
  }

  const { context, kind, params } = pending;
  let message = null;

  if (kind === 'connect') {
    message = {
      method: 'connectApprovalRequest',
      payload: {
        requestId,
        origin: context.origin,
        network: params.network,
      },
    };
  } else if (kind === 'signMessage') {
    message = {
      method: 'signMessageRequest',
      payload: {
        requestId,
        origin: context.origin,
        network: params.network,
        messageToSign: params.message,
      },
    };
  } else if (kind === 'signPsbt') {
    message = {
      method: 'signPsbtRequest',
      payload: {
        requestId,
        origin: context.origin,
        network: params.network,
        sellerFlag: !!params.sellerFlag,
        redeemScript: params.redeemScript,
        txToSign: params.psbtHex,
      },
    };
  } else if (kind === 'signTransaction') {
    message = {
      method: 'signTxRequest',
      payload: {
        requestId,
        origin: context.origin,
        network: params.network,
        txToSign: params.transaction,
      },
    };
  } else if (kind === 'addMultisig') {
    message = {
      method: 'addMultisigRequest',
      payload: {
        requestId,
        origin: context.origin,
        network: params.network,
        m: params.m,
        pubkeys: params.pubkeys,
      },
    };
  }

  if (!message) {
    throw new Error(`Unsupported popup request type: ${kind}`);
  }

  await sendRuntimeMessage(message);
};

const handleConnect = async (requestId, context, params, sendResponse) => {
  const network = normalizeNetworkId(params?.network);
  const approvedNetworks = await getApprovedNetworks(context.origin);
  debugLog('connect state', { origin: context.origin, network, approvedNetworks });

  if (approvedNetworks.includes(network)) {
    const accounts = await getAddressesForNetwork(network);
    debugLog('connect immediate accounts', { network, accounts });
    respondSuccess(sendResponse, accounts);
    return;
  }

  createPendingRequest(requestId, 'connect', context, { network }, sendResponse);
  await ensurePopup(17, requestId);
};

const handleRequestAccounts = async (context, params, sendResponse) => {
  const network = await resolveRequestNetwork(context.origin, params);
  const accounts = await getAddressesForNetwork(network);
  debugLog('requestAccounts response', { origin: context.origin, network, accounts });
  respondSuccess(sendResponse, accounts);
};

const handleSignMessage = async (requestId, context, params, sendResponse) => {
  const network = await resolveRequestNetwork(context.origin, params);
  const message = typeof params?.message === 'string' ? params.message : '';

  if (!message) {
    throw new Error('A message string is required for signMessage.');
  }

  createPendingRequest(
    requestId,
    'signMessage',
    context,
    { network, message },
    sendResponse
  );
  await ensurePopup(13, requestId);
};

const handleSignPsbt = async (requestId, context, params, sendResponse) => {
  const network = await resolveRequestNetwork(context.origin, params);
  const psbtHex =
    typeof params?.psbtHex === 'string'
      ? params.psbtHex
      : typeof params?.transaction === 'string'
        ? params.transaction
        : '';

  if (!psbtHex) {
    throw new Error('A psbtHex string is required for signPsbt.');
  }

  createPendingRequest(
    requestId,
    'signPsbt',
    context,
    {
      network,
      psbtHex,
      sellerFlag: !!params?.sellerFlag,
      redeemScript: params?.redeemScript,
    },
    sendResponse
  );
  await ensurePopup(16, requestId);
};

const handleSignTransaction = async (requestId, context, params, sendResponse) => {
  const network = await resolveRequestNetwork(context.origin, params);
  const transaction = params?.transaction || params?.txHex || params?.txToSign;

  if (!transaction) {
    throw new Error('A transaction payload is required for signTransaction.');
  }

  createPendingRequest(
    requestId,
    'signTransaction',
    context,
    { network, transaction },
    sendResponse
  );
  await ensurePopup(13, requestId);
};

const handleAddMultisig = async (requestId, context, params, sendResponse) => {
  const network = await resolveRequestNetwork(context.origin, params);
  const m = Number(params?.m);
  const pubkeys = Array.isArray(params?.pubkeys) ? params.pubkeys : [];

  if (!Number.isInteger(m) || m <= 0) {
    throw new Error('A positive multisig threshold is required.');
  }

  if (!pubkeys.length) {
    throw new Error('At least one multisig pubkey is required.');
  }

  const existing = await getExistingMultisig(m, pubkeys, network);
  if (existing) {
    respondSuccess(sendResponse, existing);
    return;
  }

  createPendingRequest(
    requestId,
    'addMultisig',
    context,
    { network, m, pubkeys },
    sendResponse
  );
  await ensurePopup(18, requestId);
};

const handleProviderRequest = async (message, sender, sendResponse) => {
  if (message.channel !== CHANNEL || message.type !== 'providerRequest') {
    return false;
  }

  const { data } = message;
  const requestId = typeof data?.id === 'string' ? data.id : null;
  const method = normalizeProviderMethod(data?.method);
  const params = data?.params || {};
  debugLog('providerRequest', { requestId, method, params, senderUrl: sender.url });

  if (!requestId) {
    respondError(sendResponse, 'Provider request id is missing.');
    return true;
  }

  if (!PAGE_METHODS.has(method)) {
    respondError(sendResponse, `Unsupported provider method: ${method}`);
    return true;
  }

  const context = getSenderContext(sender);
  if (!context || !isAllowedOrigin(context.origin)) {
    respondError(sendResponse, 'This origin is not allowed to access the wallet.');
    return true;
  }

  try {
    if (method === 'keepAlive') {
      respondSuccess(sendResponse, 'ok');
      return true;
    }

    if (method === 'fetchUserIP') {
      respondSuccess(sendResponse, {
        ip: null,
        isVpn: false,
        countryCode: 'Unknown',
      });
      return true;
    }

    if (method === 'connect') {
      await handleConnect(requestId, context, params, sendResponse);
      return true;
    }

    if (method === 'requestAccounts') {
      await handleRequestAccounts(context, params, sendResponse);
      return true;
    }

    if (method === 'signMessage') {
      await handleSignMessage(requestId, context, params, sendResponse);
      return true;
    }

    if (method === 'signPsbt') {
      await handleSignPsbt(requestId, context, params, sendResponse);
      return true;
    }

    if (method === 'signTransaction') {
      await handleSignTransaction(requestId, context, params, sendResponse);
      return true;
    }

    if (method === 'addMultisig') {
      await handleAddMultisig(requestId, context, params, sendResponse);
      return true;
    }
  } catch (error) {
    respondError(sendResponse, error);
    if (pendingRequests.has(requestId)) {
      pendingRequests.delete(requestId);
    }
    if (popupRequestId === requestId) {
      await closePopup();
    }
    return true;
  }

  respondError(sendResponse, `Unhandled provider method: ${method}`);
  return true;
};

chrome.windows.onRemoved.addListener((windowId) => {
  if (windowId !== popupWindowId) return;

  const requestId = popupRequestId;
  popupWindowId = null;
  popupRequestId = null;

  if (requestId && pendingRequests.has(requestId)) {
    rejectPendingRequest(requestId, 'The approval window was closed.').catch((error) => {
      console.error('Failed to reject request after popup close:', error);
    });
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.channel === CHANNEL && message?.type === 'providerRequest') {
    handleProviderRequest(message, sender, sendResponse).catch((error) => {
      debugLog('providerRequest failed', error);
      respondError(sendResponse, error);
    });
    return true;
  }

  if (!message?.method) {
    return false;
  }

  if (
    ['popupReady', 'approvalDecision', 'signMessageResponse', 'signTxResponse', 'addMultisigResponse', 'rejectPendingRequest'].includes(message.method) &&
    !isPopupSender(sender)
  ) {
    respondError(sendResponse, 'Popup-only method called from an invalid sender.');
    return true;
  }

  if (message.method === 'popupReady') {
    dispatchPendingRequestToPopup(message.payload?.requestId)
      .then(() => respondSuccess(sendResponse, true))
      .catch((error) => respondError(sendResponse, error));
    return true;
  }

  if (message.method === 'approvalDecision') {
    const requestId = message.payload?.requestId;
    const approved = !!message.payload?.approved;

    (async () => {
      const pending = pendingRequests.get(requestId);
      if (!pending || pending.kind !== 'connect') {
        throw new Error(`No pending connect request found for ${requestId}.`);
      }

      if (!approved) {
        await rejectPendingRequest(requestId, 'User rejected site connection.');
        respondSuccess(sendResponse, true);
        return;
      }

      await grantSitePermission(pending.context.origin, pending.params.network);
      const accounts = await getAddressesForNetwork(pending.params.network);

      await resolvePendingRequest(requestId, accounts);
      sendProviderEvent(pending.context, 'accountsChanged', accounts);
      sendProviderEvent(pending.context, 'networkChanged', pending.params.network);
      respondSuccess(sendResponse, true);
    })().catch((error) => respondError(sendResponse, error));

    return true;
  }

  if (message.method === 'signMessageResponse') {
    resolvePendingRequest(message.payload?.requestId, message.payload?.signedMessage)
      .then(() => respondSuccess(sendResponse, true))
      .catch((error) => respondError(sendResponse, error));
    return true;
  }

  if (message.method === 'signTxResponse') {
    const signedTx = message.payload?.signedTx?.data || message.payload?.signedTx;
    resolvePendingRequest(message.payload?.requestId, signedTx)
      .then(() => respondSuccess(sendResponse, true))
      .catch((error) => respondError(sendResponse, error));
    return true;
  }

  if (message.method === 'addMultisigResponse') {
    resolvePendingRequest(message.payload?.requestId, message.payload?.result)
      .then(() => respondSuccess(sendResponse, true))
      .catch((error) => respondError(sendResponse, error));
    return true;
  }

  if (message.method === 'rejectPendingRequest') {
    rejectPendingRequest(message.payload?.requestId, message.payload?.reason)
      .then(() => respondSuccess(sendResponse, true))
      .catch((error) => respondError(sendResponse, error));
    return true;
  }

  return false;
});
