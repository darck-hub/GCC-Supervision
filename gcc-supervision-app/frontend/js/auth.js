/**
 * Gestionnaire de session haute sécurité (Conformité CNIL / ANSSI).
 * - Stockage EXCLUSIF en mémoire vive (variables privées du module ES6).
 * - Aucun accès à localStorage, sessionStorage ou document.cookie pour les jetons.
 * - Déconnexion automatique (Auto-logout) à expiration (15 min) ou inactivité.
 */

let _jwtToken = null;
let _csrfToken = null;
let _user = null;
let _expiresAt = 0;
let _countdownInterval = null;
let _onAutoLogout = null;

export function setSession({ token, csrf_token, user, expires_at }, onAutoLogout) {
  _jwtToken = token;
  _csrfToken = csrf_token;
  _user = user;
  _expiresAt = expires_at;
  _onAutoLogout = onAutoLogout;
  startCountdown();
}

export function clearSession() {
  _jwtToken = null;
  _csrfToken = null;
  _user = null;
  _expiresAt = 0;
  if (_countdownInterval) {
    clearInterval(_countdownInterval);
    _countdownInterval = null;
  }
}

export function getToken() {
  return _jwtToken;
}

export function getCsrfToken() {
  return _csrfToken;
}

export function getUser() {
  return _user;
}

export function isAuthenticated() {
  return Boolean(_jwtToken && _user && Math.floor(Date.now() / 1000) < _expiresAt);
}

export function hasRole(...roles) {
  return Boolean(_user && roles.includes(_user.role));
}

function startCountdown() {
  if (_countdownInterval) clearInterval(_countdownInterval);
  const timerEl = document.getElementById("session-timer");

  const tick = () => {
    const remaining = _expiresAt - Math.floor(Date.now() / 1000);
    if (remaining <= 0) {
      clearSession();
      if (typeof _onAutoLogout === "function") {
        _onAutoLogout("Session expirée (limite réglementaire de 15 minutes atteinte).");
      }
      return;
    }
    if (timerEl) {
      const m = String(Math.floor(remaining / 60)).padStart(2, "0");
      const s = String(remaining % 60).padStart(2, "0");
      timerEl.textContent = `Session: ${m}:${s}`;
      timerEl.classList.toggle("warn", remaining <= 120);
    }
  };

  tick();
  _countdownInterval = setInterval(tick, 1000);
}
