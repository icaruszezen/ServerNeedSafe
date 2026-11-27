/**
 * Copies plain text to the system clipboard with automatic fallback for
 * non-secure HTTP contexts (e.g. LAN/public IP access where navigator.clipboard
 * is undefined) and restricted WebView/browser permission environments.
 */
export async function copyTextToClipboard(text: string): Promise<void> {
  if (
    typeof navigator !== 'undefined' &&
    navigator.clipboard &&
    typeof navigator.clipboard.writeText === 'function' &&
    (typeof window === 'undefined' || window.isSecureContext !== false)
  ) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch {
      // Fall back to legacy execCommand('copy') when Async Clipboard API rejects
      // (e.g. WebView permission quirks or transient focus issues).
    }
  }

  if (copyViaExecCommand(text)) {
    return;
  }

  throw new Error('Clipboard copy is unavailable in the current browser context');
}

function copyViaExecCommand(text: string): boolean {
  if (typeof document === 'undefined' || !document.body) {
    return false;
  }

  const activeEl =
    document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const dialogContainer = activeEl?.closest('[role="dialog"], dialog');
  const mountTarget =
    dialogContainer instanceof HTMLElement ? dialogContainer : document.body;

  const selection = document.getSelection();
  const savedRanges: Range[] = [];
  if (selection) {
    for (let i = 0; i < selection.rangeCount; i += 1) {
      savedRanges.push(selection.getRangeAt(i).cloneRange());
    }
  }

  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.setAttribute('readonly', '');
  textarea.setAttribute('aria-hidden', 'true');
  textarea.tabIndex = -1;
  textarea.style.position = 'fixed';
  textarea.style.top = '0';
  textarea.style.left = '0';
  textarea.style.width = '1px';
  textarea.style.height = '1px';
  textarea.style.padding = '0';
  textarea.style.margin = '0';
  textarea.style.border = '0';
  textarea.style.outline = 'none';
  textarea.style.boxShadow = 'none';
  textarea.style.background = 'transparent';
  textarea.style.opacity = '0';
  textarea.style.pointerEvents = 'none';
  // Keep >= 16px to prevent iOS Safari from auto-zooming on focus.
  textarea.style.fontSize = '16px';

  mountTarget.appendChild(textarea);

  try {
    try {
      textarea.focus({ preventScroll: true });
    } catch {
      textarea.focus();
    }
    textarea.select();
    textarea.setSelectionRange(0, text.length);

    return typeof document.execCommand === 'function' && document.execCommand('copy');
  } catch {
    return false;
  } finally {
    textarea.remove();

    if (selection) {
      selection.removeAllRanges();
      for (const range of savedRanges) {
        try {
          selection.addRange(range);
        } catch {
          // Ignore detached range errors.
        }
      }
    }

    if (activeEl && activeEl.isConnected) {
      try {
        activeEl.focus({ preventScroll: true });
      } catch {
        // Ignore focus restoration errors.
      }
    }
  }
}
