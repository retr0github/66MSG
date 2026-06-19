import {
  type FormEvent,
  type KeyboardEvent,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  clearSession,
  fetchTelegramRegistrationInfo,
  loginWithPassword,
  loginWithTelegramCode,
  readSession,
  registerWithTelegramCode,
  requestTelegramLoginCode,
  type Session,
  type TelegramRegistrationInfo,
  type User,
} from "./auth";
import { type ConnectionState, useChat } from "./chat";

type Conversation = "polygon" | string;
type AuthMode = "register" | "login";
type LoginMethod = "telegram" | "password";

export function App() {
  const [session, setSession] = useState<Session | undefined>(readSession);

  if (session === undefined) {
    return <AuthScreen onAuthenticated={setSession} />;
  }

  return (
    <Messenger
      session={session}
      onLogout={() => {
        clearSession();
        setSession(undefined);
      }}
    />
  );
}

function AuthScreen({
  onAuthenticated,
}: {
  readonly onAuthenticated: (session: Session) => void;
}) {
  const [mode, setMode] = useState<AuthMode>("register");
  const [loginMethod, setLoginMethod] =
    useState<LoginMethod>("telegram");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [passwordConfirmation, setPasswordConfirmation] = useState("");
  const [code, setCode] = useState("");
  const [telegram, setTelegram] = useState<TelegramRegistrationInfo>();
  const [error, setError] = useState<string>();
  const [pending, setPending] = useState(false);
  const [codeRequested, setCodeRequested] = useState(false);
  const [requestingCode, setRequestingCode] = useState(false);

  useEffect(() => {
    fetchTelegramRegistrationInfo()
      .then(setTelegram)
      .catch((reason: unknown) => {
        setError(
          reason instanceof Error
            ? reason.message
            : "Не удалось получить данные Telegram-бота",
        );
      });
  }, []);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setPending(true);
    setError(undefined);
    try {
      if (mode === "register") {
        if (password !== passwordConfirmation) {
          throw new Error("Пароли не совпадают");
        }
        onAuthenticated(
          await registerWithTelegramCode(code, username, password),
        );
      } else if (loginMethod === "telegram") {
        onAuthenticated(await loginWithTelegramCode(username, code));
      } else {
        onAuthenticated(await loginWithPassword(username, password));
      }
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Не удалось выполнить вход",
      );
    } finally {
      setPending(false);
    }
  };

  const requestLoginCode = async () => {
    setRequestingCode(true);
    setError(undefined);
    try {
      await requestTelegramLoginCode(username);
      setCodeRequested(true);
      setCode("");
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Не удалось отправить код в Telegram",
      );
    } finally {
      setRequestingCode(false);
    }
  };

  return (
    <main className="auth-page">
      <section className="auth-card">
        <div className="auth-logo">
          <span className="brand-mark">66</span>
          <div>
            <strong>66MSG</strong>
            <small>Ваше пространство для общения</small>
          </div>
        </div>

        <div className="auth-tabs" role="tablist">
          <button
            className={mode === "register" ? "active" : ""}
            type="button"
            onClick={() => {
              setMode("register");
              setCodeRequested(false);
              setError(undefined);
            }}
          >
            Регистрация
          </button>
          <button
            className={mode === "login" ? "active" : ""}
            type="button"
            onClick={() => {
              setMode("login");
              setCodeRequested(false);
              setError(undefined);
            }}
          >
            Вход
          </button>
        </div>

        <div className="auth-heading">
          <h1>{mode === "register" ? "Создание аккаунта" : "Вход в 66MSG"}</h1>
          <p>
            {mode === "register"
              ? "Подтвердите Telegram, выберите ник и установите пароль."
              : "Войдите через Telegram-код или используйте ник и пароль."}
          </p>
        </div>

        {mode === "login" ? (
          <div className="auth-tabs login-methods" role="tablist">
            <button
              className={loginMethod === "telegram" ? "active" : ""}
              type="button"
              onClick={() => {
                setLoginMethod("telegram");
                setCodeRequested(false);
                setError(undefined);
              }}
            >
              Через Telegram
            </button>
            <button
              className={loginMethod === "password" ? "active" : ""}
              type="button"
              onClick={() => {
                setLoginMethod("password");
                setError(undefined);
              }}
            >
              По паролю
            </button>
          </div>
        ) : null}

        {mode === "register" ? (
          <>
            <ol className="telegram-steps">
              <li>Откройте Telegram-бота</li>
              <li>
                Отправьте{" "}
                <strong>
                  /register
                </strong>
              </li>
              <li>Введите полученный код в течение 5 минут</li>
            </ol>
            {telegram?.bot_url === undefined ? (
              <p className="bot-warning">
                Адрес бота ещё не настроен на сервере.
              </p>
            ) : (
              <a
                className="telegram-button"
                href={telegram.bot_url}
                target="_blank"
                rel="noreferrer"
              >
                Открыть @{telegram.bot_username}
              </a>
            )}
          </>
        ) : null}

        <form className="auth-form" onSubmit={submit}>
          <label>
            Ник в 66MSG
            <input
              value={username}
              minLength={3}
              maxLength={24}
              autoComplete="username"
              pattern="[\p{L}\p{N}_-]{3,24}"
              onChange={(event) => {
                setUsername(event.target.value);
                setCodeRequested(false);
                setCode("");
              }}
              placeholder="Например, night_fox"
              required
            />
            <small>От 3 до 24 символов: буквы, цифры, _ и -</small>
          </label>

          {mode === "login" && loginMethod === "telegram" ? (
            <div className="telegram-login-request">
              <p>
                Нажмите кнопку — бот автоматически отправит код на Telegram,
                привязанный к этому аккаунту.
              </p>
              <button
                className="telegram-button"
                type="button"
                disabled={
                  requestingCode || username.trim().length < 3
                }
                onClick={requestLoginCode}
              >
                {requestingCode
                  ? "Отправляем…"
                  : codeRequested
                    ? "Отправить новый код"
                    : "Получить код в Telegram"}
              </button>
              {codeRequested ? (
                <small>Код отправлен и действует 5 минут.</small>
              ) : null}
            </div>
          ) : null}

          {mode === "register" || loginMethod === "password" ? (
            <label>
              Пароль
              <input
                value={password}
                type="password"
                minLength={8}
                maxLength={128}
                autoComplete={
                  mode === "register" ? "new-password" : "current-password"
                }
                onChange={(event) => setPassword(event.target.value)}
                placeholder="Не менее 8 символов"
                required
              />
            </label>
          ) : null}

          {mode === "register" ? (
            <label>
              Повторите пароль
              <input
                value={passwordConfirmation}
                type="password"
                minLength={8}
                maxLength={128}
                autoComplete="new-password"
                onChange={(event) =>
                  setPasswordConfirmation(event.target.value)
                }
                required
              />
            </label>
          ) : null}

          {mode === "register" ||
          (loginMethod === "telegram" && codeRequested) ? (
            <label>
              Код из Telegram
              <input
                className="code-input"
                value={code}
                inputMode="numeric"
                pattern="[0-9]{6}"
                maxLength={6}
                autoComplete="one-time-code"
                onChange={(event) =>
                  setCode(event.target.value.replace(/\D/g, "").slice(0, 6))
                }
                placeholder="000000"
                required
              />
            </label>
          ) : null}

          <AuthError message={error} />
          <button
            className="primary-button"
            type="submit"
            disabled={
              pending ||
              username.trim().length < 3 ||
              ((mode === "register" || loginMethod === "telegram") &&
                (!codeRequested && mode === "login" ||
                  code.length !== 6)) ||
              ((mode === "register" || loginMethod === "password") &&
                password.length < 8) ||
              (mode === "register" &&
                passwordConfirmation.length < 8)
            }
          >
            {pending
              ? "Проверяем…"
              : mode === "register"
                ? "Создать аккаунт"
                : "Войти"}
          </button>
        </form>
      </section>
    </main>
  );
}

function AuthError({ message }: { readonly message: string | undefined }) {
  return message === undefined ? null : (
    <p className="error-message" role="alert">
      {message}
    </p>
  );
}

function Messenger({
  session,
  onLogout,
}: {
  readonly session: Session;
  readonly onLogout: () => void;
}) {
  const {
    users,
    privateMessages,
    polygonMessages,
    connection,
    error,
    sendPrivateMessage,
    sendPolygonMessage,
  } = useChat(session);
  const contacts = useMemo(
    () => users.filter((user) => user.id !== session.user.id),
    [session.user.id, users],
  );
  const usersById = useMemo(
    () => new Map(users.map((user) => [user.id, user])),
    [users],
  );
  const [conversation, setConversation] =
    useState<Conversation>("polygon");
  const [draft, setDraft] = useState("");
  const messagesEnd = useRef<HTMLDivElement>(null);
  const selectedUser =
    conversation === "polygon"
      ? undefined
      : contacts.find((user) => user.id === conversation);
  const visibleMessages = useMemo(
    () =>
      conversation === "polygon"
        ? polygonMessages
        : privateMessages.filter(
            (message) =>
              (message.sender_id === session.user.id &&
                message.recipient_id === conversation) ||
              (message.sender_id === conversation &&
                message.recipient_id === session.user.id),
          ),
    [
      conversation,
      polygonMessages,
      privateMessages,
      session.user.id,
    ],
  );

  useEffect(() => {
    messagesEnd.current?.scrollIntoView({ behavior: "smooth" });
  }, [visibleMessages]);

  const submitMessage = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const text = draft.trim();
    if (text.length === 0) return;

    const sent =
      conversation === "polygon"
        ? sendPolygonMessage(text)
        : sendPrivateMessage(conversation, text);
    if (sent) setDraft("");
  };

  const handleComposerKeyDown = (
    event: KeyboardEvent<HTMLTextAreaElement>,
  ) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      event.currentTarget.form?.requestSubmit();
    }
  };

  const title =
    conversation === "polygon" ? "66Polygon" : selectedUser?.username;
  const subtitle =
    conversation === "polygon"
      ? "Общий чат для всех зарегистрированных пользователей"
      : "Личная переписка";

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">66</span>
          <div>
            <strong>66MSG</strong>
            <small>общение без границ</small>
          </div>
        </div>

        <nav className="contacts" aria-label="Чаты">
          <div className="contacts-title">
            <p>ОБЩИЙ ЧАТ</p>
          </div>
          <button
            className={`contact polygon-contact ${
              conversation === "polygon" ? "active" : ""
            }`}
            type="button"
            onClick={() => setConversation("polygon")}
          >
            <span className="avatar polygon-avatar">66</span>
            <span>
              <strong>66Polygon</strong>
              <small>Общая беседа</small>
            </span>
          </button>

          <div className="contacts-title private-title">
            <p>ЛИЧНЫЕ СООБЩЕНИЯ</p>
            <span>{contacts.length}</span>
          </div>
          {contacts.length === 0 ? (
            <p className="empty-contacts">Другие пользователи пока не зарегистрировались.</p>
          ) : (
            contacts.map((user) => (
              <ContactButton
                key={user.id}
                user={user}
                active={user.id === conversation}
                onClick={() => setConversation(user.id)}
              />
            ))
          )}
        </nav>

        <div className="profile">
          <span className="avatar">{initials(session.user.username)}</span>
          <span className="profile-name">
            <small>Вы вошли как</small>
            <strong>{session.user.username}</strong>
          </span>
          <button type="button" onClick={onLogout}>
            Выйти
          </button>
        </div>
      </aside>

      <section className="chat">
        <header className="chat-header">
          <div>
            <strong>{title ?? "Личные сообщения"}</strong>
            <span>{subtitle}</span>
          </div>
          <ConnectionBadge state={connection} />
        </header>

        <div className="message-list" aria-live="polite">
          {visibleMessages.length === 0 ? (
            <EmptyState
              mark={conversation === "polygon" ? "66" : initials(title ?? "?")}
              title={
                conversation === "polygon"
                  ? "Добро пожаловать в 66Polygon"
                  : `Начните диалог с ${title ?? "пользователем"}`
              }
              text={
                conversation === "polygon"
                  ? "Это общий чат. Сообщения здесь видят все зарегистрированные пользователи."
                  : "Сообщения в этом диалоге видны только вам двоим."
              }
            />
          ) : (
            visibleMessages.map((message) => {
              const authorId =
                "author_id" in message ? message.author_id : message.sender_id;
              const author = usersById.get(authorId);
              const own = authorId === session.user.id;
              return (
                <article
                  className={`message ${own ? "own" : ""}`}
                  key={message.id}
                >
                  <span className="avatar">
                    {initials(author?.username ?? "?")}
                  </span>
                  <div className="message-body">
                    <header>
                      <strong>{own ? "Вы" : author?.username ?? "Пользователь"}</strong>
                      <time dateTime={message.sent_at}>
                        {formatTime(message.sent_at)}
                      </time>
                    </header>
                    <p>{message.text}</p>
                  </div>
                </article>
              );
            })
          )}
          <div ref={messagesEnd} />
        </div>

        <div className="composer-area">
          <AuthError message={error} />
          <form className="composer" onSubmit={submitMessage}>
            <textarea
              value={draft}
              maxLength={2_000}
              rows={1}
              disabled={conversation !== "polygon" && selectedUser === undefined}
              onChange={(event) => setDraft(event.target.value)}
              onKeyDown={handleComposerKeyDown}
              placeholder={`Сообщение в ${title ?? "чат"}`}
              aria-label="Текст сообщения"
            />
            <button
              type="submit"
              disabled={
                connection !== "online" ||
                draft.trim().length === 0 ||
                (conversation !== "polygon" && selectedUser === undefined)
              }
            >
              Отправить
            </button>
          </form>
          <small>Enter — отправить · Shift + Enter — новая строка</small>
        </div>
      </section>
    </main>
  );
}

function ContactButton({
  user,
  active,
  onClick,
}: {
  readonly user: User;
  readonly active: boolean;
  readonly onClick: () => void;
}) {
  return (
    <button
      className={`contact ${active ? "active" : ""}`}
      type="button"
      onClick={onClick}
    >
      <span className="avatar">{initials(user.username)}</span>
      <span>
        <strong>{user.username}</strong>
        <small>Личные сообщения</small>
      </span>
    </button>
  );
}

function EmptyState({
  mark,
  title,
  text,
}: {
  readonly mark: string;
  readonly title: string;
  readonly text: string;
}) {
  return (
    <div className="welcome">
      <span className="welcome-mark">{mark}</span>
      <h1>{title}</h1>
      <p>{text}</p>
    </div>
  );
}

function ConnectionBadge({ state }: { readonly state: ConnectionState }) {
  const labels: Record<ConnectionState, string> = {
    connecting: "Подключение…",
    online: "В сети",
    offline: "Переподключение…",
  };

  return (
    <span className={`connection ${state}`}>
      <i aria-hidden="true" />
      {labels[state]}
    </span>
  );
}

function initials(name: string): string {
  const normalized = name.trim();
  return normalized.length === 0 ? "?" : normalized.slice(0, 2).toUpperCase();
}

function formatTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";

  return new Intl.DateTimeFormat("ru", {
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}
