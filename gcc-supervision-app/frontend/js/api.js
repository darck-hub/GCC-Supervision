/**
 * Client HTTP centralisé.
 * Injecte automatiquement Authorization: Bearer <JWT> et X-GCC-CSRF sur chaque mutation.
 */

import { getCsrfToken, getToken } from "./auth.js";

let _unauthorizedHandler = null;

export function setUnauthorizedHandler(fn) {
  _unauthorizedHandler = fn;
}

export async function apiRequest(path, { method = "GET", body = null } = {}) {
  const headers = { Accept: "application/json" };
  const token = getToken();
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  if (method !== "GET" && method !== "HEAD") {
    headers["Content-Type"] = "application/json";
    const csrf = getCsrfToken();
    if (csrf) {
      headers["X-GCC-CSRF"] = csrf;
    }
  }

  const response = await fetch(path, {
    method,
    headers,
    body: body !== null ? JSON.stringify(body) : undefined,
    credentials: "same-origin",
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && path !== "/api/auth/login" && _unauthorizedHandler) {
      _unauthorizedHandler(payload.error || "Session invalide ou expirée.");
    }
    throw new Error(payload.error || `Erreur HTTP ${response.status}`);
  }
  return payload;
}
