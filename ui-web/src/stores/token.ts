/**
 * The admin token, and where it is kept.
 *
 * The operator pastes it once. It is kept in the browser's local storage
 * because the console is a page on the instance's own listener: the token is
 * the whole of the authority, and there is no session to hold it instead.
 *
 * The instance never puts the token in the page it serves. The token file's
 * permissions are what keep another user on a shared machine out of the
 * management surface, and a token in the page would hand it to anyone who can
 * fetch the page — which is anyone on the machine.
 */
import { ref } from 'vue';

/** Where the token is kept between visits. */
const STORAGE_KEY = 'nexapipe.console.token';

function read(): string {
  try {
    return localStorage.getItem(STORAGE_KEY) ?? '';
  } catch {
    // A browser with local storage turned off still gets a console; it just
    // has to be pasted again after a reload.
    return '';
  }
}

/** The token, shared by every store and page. */
const token = ref(read());

export function useTokenStore() {
  function setToken(value: string): void {
    const trimmed = value.trim();
    token.value = trimmed;
    try {
      if (trimmed) {
        localStorage.setItem(STORAGE_KEY, trimmed);
      } else {
        localStorage.removeItem(STORAGE_KEY);
      }
    } catch {
      // Nothing to do: the token is in memory either way.
    }
  }

  function clearToken(): void {
    setToken('');
  }

  return {
    token,
    /** Whether there is a token to send. */
    hasToken: () => token.value.length > 0,
    setToken,
    clearToken,
  };
}
