export interface User {
  readonly id: string;
  readonly username: string;
  readonly emoji?: string;
  readonly avatar_url?: string;
  readonly telegram_username?: string;
  readonly telegram_first_name?: string;
  readonly telegram_last_name?: string;
  readonly created_at: string;
}

export interface Session {
  readonly token: string;
  readonly user: User;
}

export interface TelegramRegistrationInfo {
  readonly bot_username?: string;
  readonly bot_url?: string;
  readonly code_ttl_seconds: number;
}

const sessionStorageKey = "66msg.session";

export async function registerWithTelegramCode(
  code: string,
  username: string,
  password: string,
): Promise<Session> {
  return authRequest("/auth/register/telegram-code", {
    code,
    username,
    password,
  });
}

export async function registerWithPassword(
  username: string,
  password: string,
): Promise<Session> {
  return authRequest("/auth/register/password", { username, password });
}

export async function loginWithPassword(
  username: string,
  password: string,
): Promise<Session> {
  return authRequest("/auth/login/password", { username, password });
}

export async function loginWithTelegramCode(
  username: string,
  code: string,
): Promise<Session> {
  return authRequest("/auth/login/telegram-code", { username, code });
}

export async function requestTelegramLoginCode(
  username: string,
): Promise<void> {
  const response = await fetch(
    `${apiBaseUrl()}/auth/login/telegram-code/request`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username }),
    },
  );
  const body: unknown = await response.json().catch(() => undefined);
  if (!response.ok) {
    throw new Error(readErrorMessage(body));
  }
}

export async function requestPasswordResetCode(
  username: string,
): Promise<void> {
  await plainRequest("/auth/password-reset/request", { username });
}

export async function resetPassword(
  username: string,
  code: string,
  password: string,
): Promise<void> {
  await plainRequest("/auth/password-reset", { username, code, password });
}

export async function fetchTelegramRegistrationInfo(): Promise<TelegramRegistrationInfo> {
  const response = await fetch(`${apiBaseUrl()}/auth/telegram`);
  const body: unknown = await response.json().catch(() => undefined);
  if (!response.ok || !isTelegramRegistrationInfo(body)) {
    throw new Error(readErrorMessage(body));
  }
  return body;
}

export async function uploadAvatar(
  token: string,
  file: File,
): Promise<User> {
  if (file.size > 5 * 1024 * 1024) {
    throw new Error("Аватар должен быть не больше 5 МБ");
  }
  if (!["image/jpeg", "image/png", "image/webp", "image/gif"].includes(file.type)) {
    throw new Error("Поддерживаются JPEG, PNG, WebP и GIF");
  }

  return avatarRequest(token, "PUT", file);
}

export async function removeAvatar(token: string): Promise<User> {
  return avatarRequest(token, "DELETE");
}

async function avatarRequest(
  token: string,
  method: "PUT" | "DELETE",
  file?: File,
): Promise<User> {
  const request: RequestInit = {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(file === undefined ? {} : { "Content-Type": file.type }),
    },
  };
  if (file !== undefined) request.body = file;

  const response = await fetch(`${apiBaseUrl()}/profile/avatar`, request);
  const body: unknown = await response.json().catch(() => undefined);
  if (!response.ok || !isUser(body)) {
    throw new Error(readErrorMessage(body));
  }
  updateStoredSessionUser(token, body);
  return body;
}

async function authRequest(
  path: string,
  body: Record<string, string>,
): Promise<Session> {
  const response = await fetch(`${apiBaseUrl()}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  const responseBody: unknown = await response.json().catch(() => undefined);
  if (!response.ok) {
    throw new Error(readErrorMessage(responseBody));
  }
  if (!isSession(responseBody)) {
    throw new Error("Сервер вернул некорректный ответ");
  }

  localStorage.setItem(sessionStorageKey, JSON.stringify(responseBody));
  return responseBody;
}

async function plainRequest(
  path: string,
  body: Record<string, string>,
): Promise<void> {
  const response = await fetch(`${apiBaseUrl()}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (response.ok) return;

  const responseBody: unknown = await response.json().catch(() => undefined);
  throw new Error(readErrorMessage(responseBody));
}

export function readSession(): Session | undefined {
  const value = localStorage.getItem(sessionStorageKey);
  if (value === null) return undefined;

  try {
    const parsed: unknown = JSON.parse(value);
    return isSession(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

export function clearSession(): void {
  localStorage.removeItem(sessionStorageKey);
}

function updateStoredSessionUser(token: string, user: User): void {
  const session = readSession();
  if (session?.token === token) {
    localStorage.setItem(sessionStorageKey, JSON.stringify({ token, user }));
  }
}

export function apiBaseUrl(): string {
  const configuredUrl = import.meta.env.VITE_API_URL;
  if (typeof configuredUrl === "string" && configuredUrl.length > 0) {
    return configuredUrl.replace(/\/$/, "");
  }

  if (
    window.location.protocol === "tauri:" ||
    window.location.hostname === "tauri.localhost"
  ) {
    return "http://127.0.0.1:8080";
  }

  return `${window.location.protocol}//${window.location.hostname}:8080`;
}

function readErrorMessage(value: unknown): string {
  return isRecord(value) && typeof value.message === "string"
    ? value.message
    : "Не удалось связаться с сервером";
}

function isSession(value: unknown): value is Session {
  return (
    isRecord(value) &&
    typeof value.token === "string" &&
    value.token.split(".").length === 3 &&
    isUser(value.user)
  );
}

function isUser(value: unknown): value is User {
  return (
    isRecord(value) &&
    typeof value.id === "string" &&
    typeof value.username === "string" &&
    (value.avatar_url === undefined || typeof value.avatar_url === "string") &&
    typeof value.created_at === "string"
  );
}

function isTelegramRegistrationInfo(
  value: unknown,
): value is TelegramRegistrationInfo {
  return (
    isRecord(value) &&
    typeof value.code_ttl_seconds === "number" &&
    (value.bot_username === undefined ||
      typeof value.bot_username === "string") &&
    (value.bot_url === undefined || typeof value.bot_url === "string")
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
