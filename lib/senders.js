/**
 * Who sent a runtime message. The one rule the service worker and the popup
 * both apply:
 *   'popup'     the approval page of this extension (the popup window or the toolbar popup)
 *   'extension' another page of this extension, or the service worker
 *   'page'      a content script: sender.id is this extension, but sender.url is the web page
 *   'foreign'   anything else, including messages from other extensions
 * A document is classified by its URL, not by sender.tab: the approval window is
 * a popup window that has a tab, so the tab says nothing about who it is.
 * Approval and signing messages come only from 'popup'. Provider requests come
 * from 'page' and are checked by origin instead.
 * @param {chrome.runtime.MessageSender|undefined} sender
 * @param {{id: string, getURL: (path: string) => string}} runtime chrome.runtime
 * @returns {'popup'|'extension'|'page'|'foreign'}
 */
export function senderClass(sender, runtime) {
  if (!sender || sender.id !== runtime.id) return 'foreign';
  const url = typeof sender.url === 'string' ? sender.url : '';
  if (!url.startsWith(runtime.getURL(''))) return 'page';
  return url.startsWith(runtime.getURL('popup/popup.html')) ? 'popup' : 'extension';
}
