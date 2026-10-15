/**
 * Who sent a runtime message. The one rule the service worker and the popup
 * both apply:
 *   'popup'     the popup page of this extension
 *   'extension' another page of this extension, or the service worker
 *   'page'      a content script (it runs in a tab, so sender.tab is set)
 *   'foreign'   anything else, including messages from other extensions
 * Approval and signing messages come only from 'popup'. Provider requests come
 * from 'page' and are checked by origin instead.
 * @param {chrome.runtime.MessageSender|undefined} sender
 * @param {string} runtimeId this extension's id (chrome.runtime.id)
 * @param {string} popupUrl chrome.runtime.getURL('popup/popup.html')
 * @returns {'popup'|'extension'|'page'|'foreign'}
 */
export function senderClass(sender, runtimeId, popupUrl) {
  if (!sender || sender.id !== runtimeId) return 'foreign';
  if (sender.tab !== undefined) return 'page';
  return typeof sender.url === 'string' && sender.url.startsWith(popupUrl) ? 'popup' : 'extension';
}
