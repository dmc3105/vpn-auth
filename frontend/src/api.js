const CSRF_COOKIE_NAME = import.meta.env.VITE_CSRF_COOKIE_NAME || "vpn_admin_csrf";
const USER_CSRF_COOKIE_NAME = import.meta.env.VITE_USER_CSRF_COOKIE_NAME || "vpn_user_csrf";

function getApiBase() {
  const raw = import.meta.env.VITE_API_BASE || "http://localhost:8000/api";
  if (raw.startsWith("http://") || raw.startsWith("https://")) return raw;
  if (!raw.startsWith("/")) return raw;
  if (typeof window === "undefined") return raw;
  const { origin, protocol, host, hostname } = window.location;
  if (import.meta.env.DEV) return `${origin}${raw}`;
  if (hostname === "localhost" || hostname === "127.0.0.1") return `${origin}${raw}`;
  if (protocol === "https:") return `${origin}${raw}`;
  return `https://${host}${raw}`;
}

function extractErrorMessage(data) {
  if (!data) return "Request failed";
  if (typeof data.detail === "string") return data.detail;

  if (Array.isArray(data.detail)) {
    const parts = data.detail.map((item) => {
      if (typeof item === "string") return item;
      if (item?.msg && Array.isArray(item?.loc)) {
        return `${item.loc.join(".")}: ${item.msg}`;
      }
      if (item?.msg) return item.msg;
      return JSON.stringify(item);
    });
    return parts.filter(Boolean).join("; ") || "Request failed";
  }

  if (typeof data.message === "string") return data.message;
  return "Request failed";
}

async function request(path, options = {}) {
  const { headers: customHeaders = {}, ...restOptions } = options;
  const method = (restOptions.method || "GET").toUpperCase();
  const needsCsrf = ["POST", "PUT", "PATCH", "DELETE"].includes(method);
  const isAdminPath = path === "/admin/logout" || path.startsWith("/admin/");
  const csrfToken = needsCsrf
    ? (isAdminPath ? readCookie(CSRF_COOKIE_NAME) : readCookie(USER_CSRF_COOKIE_NAME) || readCookie(CSRF_COOKIE_NAME))
    : null;
  const response = await fetch(`${getApiBase()}${path}`, {
    ...restOptions,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
      ...customHeaders
    }
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(extractErrorMessage(data));
  }
  return data;
}

function readCookie(name) {
  const cookie = document.cookie
    .split("; ")
    .find((row) => row.startsWith(`${name}=`));
  return cookie ? decodeURIComponent(cookie.split("=")[1]) : "";
}

export function requestEmailCode(email) {
  return request("/auth/request-email-code", {
    method: "POST",
    body: JSON.stringify({ email })
  });
}

export function verifyEmailCode(email, code) {
  return request("/auth/verify-email-code", {
    method: "POST",
    body: JSON.stringify({ email, code })
  });
}

export function loginWithEmailCode(email, code) {
  return request("/auth/login-email-code", {
    method: "POST",
    body: JSON.stringify({ email, code })
  });
}

export function userLogout() {
  return request("/auth/logout", { method: "POST" });
}

export function userSession() {
  return request("/auth/session");
}

export function requestDeleteCode(email) {
  return request("/profile/request-delete-code", {
    method: "POST",
    body: JSON.stringify({ email })
  });
}

export function deleteProfile(email, code) {
  return request("/profile/delete", {
    method: "POST",
    body: JSON.stringify({ email, code })
  });
}

export function registerUser(payload) {
  return request("/register", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export function getProfileConnection() {
  return request("/profile/connection");
}

export function adminLogin(username, password) {
  return request("/admin/login", {
    method: "POST",
    body: JSON.stringify({ username, password })
  });
}

export function adminLogout() {
  return request("/admin/logout", { method: "POST" });
}

export function adminSession() {
  return request("/admin/session");
}

export function createInviteCodes(amount) {
  return request("/admin/invite-codes", {
    method: "POST",
    body: JSON.stringify({ amount })
  });
}

export function getInviteCodes(params = {}) {
  const qs = new URLSearchParams(
    Object.entries(params)
      .filter(([, value]) => value !== undefined && value !== null)
      .map(([key, value]) => [key, String(value)])
  ).toString();
  return request(`/admin/invite-codes${qs ? `?${qs}` : ""}`);
}

export function deleteInviteCode(code) {
  return request(`/admin/invite-codes/${encodeURIComponent(code)}`, { method: "DELETE" });
}

export function setInviteCodeDeliveryStatus(code, deliveryStatus) {
  return request(`/admin/invite-codes/${encodeURIComponent(code)}/delivery-status`, {
    method: "PATCH",
    body: JSON.stringify({ delivery_status: deliveryStatus })
  });
}

export function getUsers(params = {}) {
  const qs = new URLSearchParams(
    Object.entries(params)
      .filter(([, value]) => value !== undefined && value !== null)
      .map(([key, value]) => [key, String(value)])
  ).toString();
  return request(`/admin/users${qs ? `?${qs}` : ""}`);
}

export function deleteUserById(userId) {
  return request(`/admin/users/${userId}`, { method: "DELETE" });
}

export function createAdminUser(payload) {
  return request("/admin/users", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export function getAdminUserConnection(userId) {
  return request(`/admin/users/${userId}/connection`);
}
