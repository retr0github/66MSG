import { useCallback, useEffect, useState } from "react";
import { apiBaseUrl, clearSession, type Session, type User } from "./auth";

export interface PrivateMessage {
  readonly id: string;
  readonly sender_id: string;
  readonly recipient_id: string;
  readonly text: string;
  readonly attachment?: FileAttachment;
  readonly sent_at: string;
}

export interface PolygonMessage {
  readonly id: string;
  readonly author_id: string;
  readonly text: string;
  readonly attachment?: FileAttachment;
  readonly sent_at: string;
}

export interface FileAttachment {
  readonly id: string;
  readonly name: string;
  readonly size: number;
  readonly content_type: string;
}

export type ConnectionState = "connecting" | "online" | "offline";

type ServerEvent =
  | {
      readonly type: "ready";
      readonly current_user: User;
      readonly users: readonly User[];
      readonly messages: readonly PrivateMessage[];
      readonly polygon_messages: readonly PolygonMessage[];
    }
  | { readonly type: "user_registered"; readonly user: User }
  | { readonly type: "user_updated"; readonly user: User }
  | { readonly type: "private_message"; readonly message: PrivateMessage }
  | { readonly type: "polygon_message"; readonly message: PolygonMessage }
  | { readonly type: "session_revoked"; readonly session_id: string }
  | { readonly type: "error"; readonly message: string };

interface ChatConnection {
  readonly users: readonly User[];
  readonly privateMessages: readonly PrivateMessage[];
  readonly polygonMessages: readonly PolygonMessage[];
  readonly connection: ConnectionState;
  readonly error: string | undefined;
  readonly sendPrivateMessage: (recipientId: string, text: string) => boolean;
  readonly sendPolygonMessage: (text: string) => boolean;
  readonly updateUserEmoji: (emoji: string) => boolean;
  readonly sendFile: (conversationId: string, file: File) => Promise<boolean>;
  readonly syncUser: (user: User) => void;
}

const reconnectDelayMs = 1_500;

export function useChat(session: Session): ChatConnection {
  const [users, setUsers] = useState<readonly User[]>([session.user]);
  const [privateMessages, setPrivateMessages] = useState<
    readonly PrivateMessage[]
  >([]);
  const [polygonMessages, setPolygonMessages] = useState<
    readonly PolygonMessage[]
  >([]);
  const [connection, setConnection] = useState<ConnectionState>("connecting");
  const [error, setError] = useState<string>();
  const [socket, setSocket] = useState<WebSocket>();

  useEffect(() => {
    let active = true;
    let reconnectTimer: number | undefined;
    let currentSocket: WebSocket | undefined;

    const connect = () => {
      setConnection("connecting");
      const nextSocket = new WebSocket(websocketUrl(session.token));
      currentSocket = nextSocket;
      setSocket(nextSocket);

      nextSocket.addEventListener("open", () => {
        if (!active) return;
        setConnection("online");
        setError(undefined);
      });

      nextSocket.addEventListener("message", (message) => {
        const event = parseServerEvent(message.data);
        if (event === undefined || !active) return;

        switch (event.type) {
          case "ready":
            setUsers(event.users);
            setPrivateMessages(event.messages);
            setPolygonMessages(event.polygon_messages);
            break;
          case "user_registered":
            setUsers((current) =>
              current.some((user) => user.id === event.user.id)
                ? current
                : [...current, event.user],
            );
            break;
          case "user_updated":
            setUsers((current) =>
              current.map((user) =>
                user.id === event.user.id ? event.user : user,
              ),
            );
            break;
          case "private_message":
            setPrivateMessages((current) =>
              appendUnique(current, event.message),
            );
            break;
          case "polygon_message":
            setPolygonMessages((current) =>
              appendUnique(current, event.message),
            );
            break;
          case "session_revoked":
            clearSession();
            window.location.reload();
            break;
          case "error":
            setError(event.message);
            break;
        }
      });

      nextSocket.addEventListener("close", () => {
        if (!active) return;
        setConnection("offline");
        setSocket(undefined);
        reconnectTimer = window.setTimeout(connect, reconnectDelayMs);
      });

      nextSocket.addEventListener("error", () => {
        if (!active) return;
        setError("Не удалось подключиться к серверу");
      });
    };

    connect();

    return () => {
      active = false;
      if (reconnectTimer !== undefined) {
        window.clearTimeout(reconnectTimer);
      }
      currentSocket?.close();
    };
  }, [session.token]);

  const sendEvent = useCallback(
    (event: Record<string, string>): boolean => {
      if (socket?.readyState !== WebSocket.OPEN) {
        setError("Соединение ещё не установлено");
        return false;
      }
      socket.send(JSON.stringify(event));
      setError(undefined);
      return true;
    },
    [socket],
  );

  const sendPrivateMessage = useCallback(
    (recipientId: string, text: string) =>
      sendEvent({
        type: "send_private_message",
        recipient_id: recipientId,
        text,
      }),
    [sendEvent],
  );

  const sendPolygonMessage = useCallback(
    (text: string) => sendEvent({ type: "send_polygon_message", text }),
    [sendEvent],
  );

  const updateUserEmoji = useCallback(
    (emoji: string) => sendEvent({ type: "update_user_emoji", emoji }),
    [sendEvent],
  );

  const sendFile = useCallback(
    async (conversationId: string, file: File): Promise<boolean> => {
      if (file.size === 0) {
        setError("Нельзя отправить пустой файл");
        return false;
      }
      if (file.size > 8 * 1024 * 1024) {
        setError("Файл должен быть не больше 8 МБ");
        return false;
      }

      const query = new URLSearchParams({
        conversation_id: conversationId,
        filename: file.name,
      });
      try {
        const response = await fetch(`${apiBaseUrl()}/chat/file?${query}`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${session.token}`,
            "Content-Type": file.type || "application/octet-stream",
          },
          body: file,
        });
        if (!response.ok) {
          const body: unknown = await response.json().catch(() => undefined);
          throw new Error(
            isRecord(body) && typeof body.message === "string"
              ? body.message
              : "Не удалось отправить файл",
          );
        }
        setError(undefined);
        return true;
      } catch (reason) {
        setError(
          reason instanceof Error ? reason.message : "Не удалось отправить файл",
        );
        return false;
      }
    },
    [session.token],
  );

  const syncUser = useCallback((user: User) => {
    setUsers((current) =>
      current.some((existing) => existing.id === user.id)
        ? current.map((existing) => (existing.id === user.id ? user : existing))
        : [...current, user],
    );
  }, []);

  return {
    users,
    privateMessages,
    polygonMessages,
    connection,
    error,
    sendPrivateMessage,
    sendPolygonMessage,
    updateUserEmoji,
    sendFile,
    syncUser,
  };
}

function appendUnique<T extends { readonly id: string }>(
  current: readonly T[],
  item: T,
): readonly T[] {
  return current.some((existing) => existing.id === item.id)
    ? current
    : [...current, item];
}

function websocketUrl(token: string): string {
  const configuredUrl = import.meta.env.VITE_WS_URL;
  if (typeof configuredUrl === "string" && configuredUrl.length > 0) {
    const separator = configuredUrl.includes("?") ? "&" : "?";
    return `${configuredUrl}${separator}token=${encodeURIComponent(token)}`;
  }

  const baseUrl = new URL(apiBaseUrl());
  baseUrl.protocol = baseUrl.protocol === "https:" ? "wss:" : "ws:";
  baseUrl.pathname = "/ws";
  baseUrl.search = new URLSearchParams({ token }).toString();
  return baseUrl.toString();
}

function parseServerEvent(value: unknown): ServerEvent | undefined {
  if (typeof value !== "string") return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return undefined;
  }
  if (!isRecord(parsed) || typeof parsed.type !== "string") return undefined;

  switch (parsed.type) {
    case "ready":
      return isUser(parsed.current_user) &&
        Array.isArray(parsed.users) &&
        parsed.users.every(isUser) &&
        Array.isArray(parsed.messages) &&
        parsed.messages.every(isPrivateMessage) &&
        Array.isArray(parsed.polygon_messages) &&
        parsed.polygon_messages.every(isPolygonMessage)
        ? {
            type: "ready",
            current_user: parsed.current_user,
            users: parsed.users,
            messages: parsed.messages,
            polygon_messages: parsed.polygon_messages,
          }
        : undefined;
    case "user_registered":
      return isUser(parsed.user)
        ? { type: "user_registered", user: parsed.user }
        : undefined;
    case "user_updated":
      return isUser(parsed.user)
        ? { type: "user_updated", user: parsed.user }
        : undefined;
    case "private_message":
      return isPrivateMessage(parsed.message)
        ? { type: "private_message", message: parsed.message }
        : undefined;
    case "polygon_message":
      return isPolygonMessage(parsed.message)
        ? { type: "polygon_message", message: parsed.message }
        : undefined;
    case "session_revoked":
      return typeof parsed.session_id === "string"
        ? { type: "session_revoked", session_id: parsed.session_id }
        : undefined;
    case "error":
      return typeof parsed.message === "string"
        ? { type: "error", message: parsed.message }
        : undefined;
    default:
      return undefined;
  }
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

function isPrivateMessage(value: unknown): value is PrivateMessage {
  return (
    isRecord(value) &&
    typeof value.id === "string" &&
    typeof value.sender_id === "string" &&
    typeof value.recipient_id === "string" &&
    typeof value.text === "string" &&
    (value.attachment === undefined || isFileAttachment(value.attachment)) &&
    typeof value.sent_at === "string"
  );
}

function isPolygonMessage(value: unknown): value is PolygonMessage {
  return (
    isRecord(value) &&
    typeof value.id === "string" &&
    typeof value.author_id === "string" &&
    typeof value.text === "string" &&
    (value.attachment === undefined || isFileAttachment(value.attachment)) &&
    typeof value.sent_at === "string"
  );
}

function isFileAttachment(value: unknown): value is FileAttachment {
  return (
    isRecord(value) &&
    typeof value.id === "string" &&
    typeof value.name === "string" &&
    typeof value.size === "number" &&
    typeof value.content_type === "string"
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
