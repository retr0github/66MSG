export interface User {
  readonly id: string;
  readonly username: string;
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

export async function fetchTelegramRegistrationInfo(): Promise<TelegramRegistrationInfo> {
  const response = await fetch(`${apiBaseUrl()}/auth/telegram`);
  const body: unknown = await response.json().catch(() => undefined);
  if (!response.ok || !isTelegramRegistrationInfo(body)) {
    throw new Error(readErrorMessage(body));
  }
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

export function apiBaseUrl(): string {
  const configuredUrl = import.meta.env.VITE_API_URL;
  if (typeof configuredUrl === "string" && configuredUrl.length > 0) {
    return configuredUrl.replace(/\/$/, "");
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
