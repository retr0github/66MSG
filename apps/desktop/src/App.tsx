import {
  type FormEvent,
  type KeyboardEvent,
  type ReactNode,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  apiBaseUrl,
  clearSession,
  fetchTelegramRegistrationInfo,
  loginWithPassword,
  loginWithTelegramCode,
  readSession,
  removeAvatar,
  registerWithPassword,
  registerWithTelegramCode,
  requestPasswordResetCode,
  requestTelegramLoginCode,
  resetPassword,
  uploadAvatar,
  type Session,
  type TelegramRegistrationInfo,
  type User,
} from "./auth";
import { type ConnectionState, type FileAttachment, useChat } from "./chat";
import { type ScreenShareQuality, useVoiceChat } from "./voice";

type Conversation = "polygon" | string;
type AuthMode = "register" | "login" | "reset";
type LoginMethod = "telegram" | "password";

const telegramAuthEnabled = false;

interface DraftPhoto {
  readonly id: string;
  readonly file: File;
  readonly previewUrl: string;
}

const userEmojiOptions = [
  "😀",
  "😄",
  "😊",
  "🥰",
  "😍",
  "😂",
  "😉",
  "😎",
  "🥳",
  "🤩",
  "😴",
  "🤔",
  "🫡",
  "🤖",
  "👻",
  "👽",
  "💀",
  "😈",
  "🐱",
  "🐶",
  "🦊",
  "🐸",
  "🐼",
  "🐵",
  "🦁",
  "🐯",
  "🐧",
  "🦄",
  "🔥",
  "✨",
  "⭐",
  "⚡",
  "💜",
  "❤️",
  "💙",
  "💚",
  "🌈",
  "🌙",
  "☀️",
  "🚀",
  "🎮",
  "🎧",
] as const;

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
  const [loginMethod, setLoginMethod] = useState<LoginMethod>("password");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [passwordConfirmation, setPasswordConfirmation] = useState("");
  const [code, setCode] = useState("");
  const [telegram, setTelegram] = useState<TelegramRegistrationInfo>();
  const [error, setError] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const [pending, setPending] = useState(false);
  const [codeRequested, setCodeRequested] = useState(false);
  const [requestingCode, setRequestingCode] = useState(false);

  useEffect(() => {
    if (!telegramAuthEnabled) return;

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
        onAuthenticated(await registerWithPassword(username, password));
      } else if (mode === "reset") {
        if (password !== passwordConfirmation) {
          throw new Error("Пароли не совпадают");
        }
        await resetPassword(username, code, password);
        setMode("login");
        setLoginMethod("password");
        setCodeRequested(false);
        setCode("");
        setPassword("");
        setPasswordConfirmation("");
        setNotice("Пароль изменён. Теперь можно войти с новым паролем.");
      } else if (telegramAuthEnabled && loginMethod === "telegram") {
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

  const requestResetCode = async () => {
    setRequestingCode(true);
    setError(undefined);
    setNotice(undefined);
    try {
      await requestPasswordResetCode(username);
      setCodeRequested(true);
      setCode("");
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Не удалось отправить код восстановления в Telegram",
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
            aria-selected={mode === "register"}
            onClick={() => {
              setMode("register");
              setCodeRequested(false);
              setError(undefined);
              setNotice(undefined);
            }}
          >
            Регистрация
          </button>
          <button
            className={mode === "login" || mode === "reset" ? "active" : ""}
            type="button"
            aria-selected={mode === "login" || mode === "reset"}
            onClick={() => {
              setMode("login");
              setCodeRequested(false);
              setError(undefined);
              setNotice(undefined);
            }}
          >
            Вход
          </button>
        </div>

        <div className="auth-heading">
          <span className="auth-eyebrow">
            {mode === "register"
              ? "Новый профиль"
              : mode === "reset"
                ? "Восстановление доступа"
                : "С возвращением"}
          </span>
          <h1>
            {mode === "register"
              ? "Создание аккаунта"
              : mode === "reset"
                ? "Новый пароль"
                : "Вход в 66MSG"}
          </h1>
          <p>
            {mode === "register"
              ? "Выберите ник и установите пароль. Telegram временно не нужен."
              : mode === "reset"
                ? "Получите код в привязанный Telegram и задайте новый пароль."
                : "Введите ник и пароль, чтобы войти в 66MSG."}
          </p>
        </div>

        {telegramAuthEnabled && mode === "login" ? (
          <div className="auth-tabs login-methods" role="tablist">
            <button
              className={loginMethod === "telegram" ? "active" : ""}
              type="button"
              aria-selected={loginMethod === "telegram"}
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
              aria-selected={loginMethod === "password"}
              onClick={() => {
                setLoginMethod("password");
                setError(undefined);
              }}
            >
              По паролю
            </button>
          </div>
        ) : null}

        {telegramAuthEnabled && mode === "register" ? (
          <div className="telegram-onboarding">
            <ol className="telegram-steps">
              <li>
                <span>Откройте Telegram-бота</span>
              </li>
              <li>
                <span>
                  Отправьте <strong>/register</strong>
                </span>
              </li>
              <li>
                <span>Введите полученный код в течение 5 минут</span>
              </li>
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
          </div>
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

          {telegramAuthEnabled && mode === "login" && loginMethod === "telegram" ? (
            <div className="telegram-login-request">
              <p>
                Нажмите кнопку — бот автоматически отправит код на Telegram,
                привязанный к этому аккаунту.
              </p>
              <button
                className="telegram-button"
                type="button"
                disabled={requestingCode || username.trim().length < 3}
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

          {telegramAuthEnabled && mode === "reset" ? (
            <div className="telegram-login-request">
              <p>
                Бот отправит код в Telegram, привязанный к указанному аккаунту.
              </p>
              <button
                className="telegram-button"
                type="button"
                disabled={requestingCode || username.trim().length < 3}
                onClick={requestResetCode}
              >
                {requestingCode
                  ? "Отправляем…"
                  : codeRequested
                    ? "Отправить новый код"
                    : "Получить код восстановления"}
              </button>
              {codeRequested ? (
                <small>Код отправлен и действует 5 минут.</small>
              ) : null}
            </div>
          ) : null}

          {mode === "register" ||
          (mode === "login" && loginMethod === "password") ||
          (mode === "reset" && codeRequested) ? (
            <label>
              {mode === "reset" ? "Новый пароль" : "Пароль"}
              <input
                value={password}
                type="password"
                minLength={8}
                maxLength={128}
                autoComplete={
                  mode === "register" || mode === "reset"
                    ? "new-password"
                    : "current-password"
                }
                onChange={(event) => setPassword(event.target.value)}
                placeholder="Не менее 8 символов"
                required
              />
            </label>
          ) : null}

          {telegramAuthEnabled && mode === "login" && loginMethod === "password" ? (
            <button
              className="forgot-password-button"
              type="button"
              onClick={() => {
                setMode("reset");
                setCodeRequested(false);
                setCode("");
                setPassword("");
                setPasswordConfirmation("");
                setError(undefined);
                setNotice(undefined);
              }}
            >
              Забыли пароль?
            </button>
          ) : null}

          {mode === "register" || (mode === "reset" && codeRequested) ? (
            <label>
              {mode === "reset" ? "Повторите новый пароль" : "Повторите пароль"}
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

          {telegramAuthEnabled &&
          ((mode === "login" && loginMethod === "telegram" && codeRequested) ||
            (mode === "reset" && codeRequested)) ? (
            <label className="code-field">
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
          {notice === undefined ? null : (
            <p className="auth-notice" role="status">
              {notice}
            </p>
          )}
          <button
            className="primary-button"
            type="submit"
            disabled={
              pending ||
              username.trim().length < 3 ||
              (telegramAuthEnabled &&
                ((mode === "login" && loginMethod === "telegram") ||
                  mode === "reset") &&
                (!codeRequested || code.length !== 6)) ||
              ((mode === "register" ||
                mode === "login" ||
                mode === "reset") &&
                password.length < 8) ||
              ((mode === "register" || mode === "reset") &&
                passwordConfirmation.length < 8)
            }
          >
            {pending
              ? "Проверяем…"
              : mode === "register"
                ? "Создать аккаунт"
                : mode === "reset"
                  ? "Сменить пароль"
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
    sendFile,
    updateUserEmoji,
    syncUser,
  } = useChat(session);
  const currentUser =
    users.find((user) => user.id === session.user.id) ?? session.user;
  const contacts = useMemo(
    () => users.filter((user) => user.id !== session.user.id),
    [session.user.id, users],
  );
  const usersById = useMemo(
    () => new Map(users.map((user) => [user.id, user])),
    [users],
  );
  const [conversation, setConversation] = useState<Conversation>("polygon");
  const [draft, setDraft] = useState("");
  const [photoDrafts, setPhotoDrafts] = useState<readonly DraftPhoto[]>([]);
  const [photoDraftError, setPhotoDraftError] = useState<string>();
  const [filePending, setFilePending] = useState(false);
  const [avatarPending, setAvatarPending] = useState(false);
  const [avatarError, setAvatarError] = useState<string>();
  const [screenShareMenuOpen, setScreenShareMenuOpen] = useState(false);
  const [hiddenScreenShareIds, setHiddenScreenShareIds] = useState<
    readonly string[]
  >([]);
  const [volumeParticipantId, setVolumeParticipantId] = useState<string>();
  const avatarInput = useRef<HTMLInputElement>(null);
  const photoDraftsRef = useRef<readonly DraftPhoto[]>([]);
  const messagesEnd = useRef<HTMLDivElement>(null);
  const selectedUser =
    conversation === "polygon"
      ? undefined
      : contacts.find((user) => user.id === conversation);
  const voice = useVoiceChat(session, conversation);
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
    [conversation, polygonMessages, privateMessages, session.user.id],
  );

  const clearPhotoDrafts = () => {
    photoDraftsRef.current.forEach((photo) =>
      URL.revokeObjectURL(photo.previewUrl),
    );
    photoDraftsRef.current = [];
    setPhotoDrafts([]);
  };

  const removePhotoDraft = (id: string) => {
    setPhotoDrafts((current) => {
      const removed = current.find((photo) => photo.id === id);
      if (removed !== undefined) URL.revokeObjectURL(removed.previewUrl);
      const next = current.filter((photo) => photo.id !== id);
      photoDraftsRef.current = next;
      return next;
    });
  };

  const addPhotoDrafts = (files: FileList | null) => {
    const selectedFiles = files === null ? [] : Array.from(files);
    if (selectedFiles.length === 0) return;

    const accepted: DraftPhoto[] = [];
    let hasRejectedFile = false;

    selectedFiles.forEach((file) => {
      if (!file.type.startsWith("image/")) {
        hasRejectedFile = true;
        return;
      }
      if (file.size === 0 || file.size > 8 * 1024 * 1024) {
        hasRejectedFile = true;
        return;
      }
      accepted.push(createDraftPhoto(file));
    });

    if (accepted.length > 0) {
      setPhotoDrafts((current) => {
        const next = [...current, ...accepted];
        photoDraftsRef.current = next;
        return next;
      });
    }

    setPhotoDraftError(
      hasRejectedFile
        ? "Можно добавить только изображения до 8 МБ."
        : undefined,
    );
  };

  useEffect(() => {
    messagesEnd.current?.scrollIntoView({ behavior: "smooth" });
  }, [visibleMessages]);

  useEffect(() => {
    setHiddenScreenShareIds([]);
    clearPhotoDrafts();
    setPhotoDraftError(undefined);
  }, [conversation]);

  useEffect(
    () => () => {
      clearPhotoDrafts();
    },
    [],
  );

  const submitMessage = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const text = draft.trim();
    if (text.length === 0 && photoDrafts.length === 0) return;

    if (text.length > 0) {
      const sent =
        conversation === "polygon"
          ? sendPolygonMessage(text)
          : sendPrivateMessage(conversation, text);
      if (!sent) return;
    }

    if (photoDrafts.length === 0) {
      setDraft("");
      return;
    }

    setFilePending(true);
    try {
      for (const photo of photoDrafts) {
        const sent = await sendFile(conversation, photo.file);
        if (!sent) return;
      }
      setDraft("");
      setPhotoDraftError(undefined);
      clearPhotoDrafts();
    } finally {
      setFilePending(false);
    }
  };

  const handleComposerKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      event.currentTarget.form?.requestSubmit();
    }
  };

  const downloadAttachment = async (attachment: FileAttachment) => {
    try {
      const response = await fetch(
        `${apiBaseUrl()}/chat/file/${attachment.id}`,
        {
          headers: { Authorization: `Bearer ${session.token}` },
        },
      );
      if (!response.ok) throw new Error("Не удалось скачать файл");
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = attachment.name;
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
    } catch (reason) {
      window.alert(
        reason instanceof Error ? reason.message : "Не удалось скачать файл",
      );
    }
  };

  const selectAvatar = async (file: File | undefined) => {
    if (file === undefined) return;
    setAvatarPending(true);
    setAvatarError(undefined);
    try {
      syncUser(await uploadAvatar(session.token, file));
    } catch (reason) {
      setAvatarError(
        reason instanceof Error
          ? reason.message
          : "Не удалось загрузить аватар",
      );
    } finally {
      setAvatarPending(false);
    }
  };

  const clearAvatar = async () => {
    setAvatarPending(true);
    setAvatarError(undefined);
    try {
      syncUser(await removeAvatar(session.token));
    } catch (reason) {
      setAvatarError(
        reason instanceof Error ? reason.message : "Не удалось удалить аватар",
      );
    } finally {
      setAvatarPending(false);
    }
  };

  const title =
    conversation === "polygon" ? "66Polygon" : selectedUser?.username;
  const visibleScreenShares = voice.screenShares.filter(
    (share) => !hiddenScreenShareIds.includes(share.id),
  );
  const hiddenScreenShares = voice.screenShares.filter((share) =>
    hiddenScreenShareIds.includes(share.id),
  );
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
            <p className="empty-contacts">
              Другие пользователи пока не зарегистрировались.
            </p>
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
          {avatarError === undefined ? null : (
            <p className="profile-avatar-error" role="alert">
              {avatarError}
            </p>
          )}
          <details
            className={`profile-avatar-menu ${avatarPending ? "pending" : ""}`}
          >
            <summary
              aria-label="Открыть меню аватара"
              title="Настройки аватара"
            >
              <Avatar user={currentUser} />
              <span className="avatar-menu-indicator" aria-hidden="true">
                {avatarPending ? "…" : "⌄"}
              </span>
            </summary>
            <div className="avatar-actions">
              <button
                type="button"
                disabled={avatarPending}
                onClick={(event) => {
                  event.currentTarget
                    .closest("details")
                    ?.removeAttribute("open");
                  avatarInput.current?.click();
                }}
              >
                <span aria-hidden="true">✎</span>
                Изменить аватар
              </button>
              <button
                className="avatar-delete-action"
                type="button"
                disabled={avatarPending || currentUser.avatar_url === undefined}
                onClick={(event) => {
                  event.currentTarget
                    .closest("details")
                    ?.removeAttribute("open");
                  void clearAvatar();
                }}
              >
                <span aria-hidden="true">⌫</span>
                Удалить аватар
              </button>
            </div>
          </details>
          <input
            ref={avatarInput}
            className="avatar-file-input"
            type="file"
            accept="image/jpeg,image/png,image/webp,image/gif"
            disabled={avatarPending}
            onChange={(event) => {
              const file = event.target.files?.[0];
              event.target.value = "";
              void selectAvatar(file);
            }}
          />
          <span className="profile-name">
            <small>Вы вошли как</small>
            <UserName user={currentUser} />
          </span>
          <details className="emoji-picker">
            <summary
              aria-label="Выбрать эмодзи возле никнейма"
              title="Выбрать эмодзи"
            >
              {currentUser.emoji ?? "+"}
            </summary>
            <div className="emoji-menu">
              <p>Эмодзи возле ника</p>
              <div>
                {userEmojiOptions.map((emoji) => (
                  <button
                    className={currentUser.emoji === emoji ? "active" : ""}
                    type="button"
                    key={emoji}
                    aria-label={`Выбрать ${emoji}`}
                    onClick={(event) => {
                      if (updateUserEmoji(emoji)) {
                        event.currentTarget
                          .closest("details")
                          ?.removeAttribute("open");
                      }
                    }}
                  >
                    {emoji}
                  </button>
                ))}
              </div>
              <button
                className="emoji-clear"
                type="button"
                disabled={currentUser.emoji === undefined}
                onClick={(event) => {
                  if (updateUserEmoji("")) {
                    event.currentTarget
                      .closest("details")
                      ?.removeAttribute("open");
                  }
                }}
              >
                Без эмодзи
              </button>
            </div>
          </details>
          <button className="logout-button" type="button" onClick={onLogout}>
            Выйти
          </button>
        </div>
      </aside>

      <section
        className={`chat ${
          voice.participants.length > 0 ? "voice-sidebar-active" : ""
        } ${
          visibleScreenShares.length > 0 || voice.cameraFeeds.length > 0
            ? "screen-share-active"
            : ""
        }`}
      >
        <header className="chat-header">
          <div>
            <strong>
              {selectedUser === undefined ? (
                (title ?? "Личные сообщения")
              ) : (
                <UserName user={selectedUser} />
              )}
            </strong>
            <span>{subtitle}</span>
          </div>
          <div className="chat-header-actions">
            {voice.state === "connected" ? (
              <div className="voice-controls">
                <span>{voice.participants.length} в голосовом чате</span>
                <button
                  type="button"
                  disabled={voice.deafened}
                  title={
                    voice.deafened
                      ? "Сначала отключите режим «Заглушить всех»"
                      : undefined
                  }
                  onClick={() => void voice.toggleMute()}
                >
                  {voice.muted ? "Включить микрофон" : "Выключить микрофон"}
                </button>
                <button
                  className={voice.cameraEnabled ? "camera-active" : ""}
                  type="button"
                  onClick={() => void voice.toggleCamera()}
                >
                  {voice.cameraEnabled ? "Выключить камеру" : "Включить камеру"}
                </button>
                <button
                  className={voice.deafened ? "deafen-active" : ""}
                  type="button"
                  onClick={() => void voice.toggleDeafen()}
                >
                  {voice.deafened ? "Включить звук всех" : "Заглушить всех"}
                </button>
                <div className="screen-share-picker">
                  <button
                    className={voice.screenSharing ? "screen-share-stop" : ""}
                    type="button"
                    onClick={() => {
                      if (voice.screenSharing) {
                        void voice.toggleScreenShare("1080p30");
                      } else {
                        setScreenShareMenuOpen((open) => !open);
                      }
                    }}
                  >
                    {voice.screenSharing
                      ? "Остановить показ"
                      : "Показать экран"}
                  </button>
                  {!voice.screenSharing && screenShareMenuOpen ? (
                    <div
                      className="screen-share-menu"
                      role="menu"
                      aria-label="Качество демонстрации экрана"
                    >
                      {(
                        [
                          ["1080p60", "1080p · 60 fps"],
                          ["1080p30", "1080p · 30 fps"],
                          ["720p60", "720p · 60 fps"],
                          ["720p30", "720p · 30 fps"],
                        ] as const satisfies readonly [
                          ScreenShareQuality,
                          string,
                        ][]
                      ).map(([quality, label]) => (
                        <button
                          type="button"
                          role="menuitem"
                          key={quality}
                          onClick={() => {
                            setScreenShareMenuOpen(false);
                            void voice.toggleScreenShare(quality);
                          }}
                        >
                          {label}
                        </button>
                      ))}
                    </div>
                  ) : null}
                </div>
                {voice.screenSharing && voice.screenShareHasAudio ? (
                  <span className="screen-audio-status">Со звуком</span>
                ) : null}
                {voice.audioPlaybackBlocked ? (
                  <button
                    className="enable-share-audio"
                    type="button"
                    onClick={() => void voice.enableAudioPlayback()}
                  >
                    Включить звук показа
                  </button>
                ) : null}
                {hiddenScreenShares.length > 0 ? (
                  <button
                    type="button"
                    onClick={() => setHiddenScreenShareIds([])}
                  >
                    Смотреть демонстрацию
                  </button>
                ) : null}
                <button
                  className="voice-leave"
                  type="button"
                  onClick={voice.leave}
                >
                  Выйти
                </button>
              </div>
            ) : (
              <button
                className="voice-join"
                type="button"
                disabled={
                  voice.state === "connecting" ||
                  (conversation !== "polygon" && selectedUser === undefined)
                }
                onClick={() => void voice.join()}
              >
                {voice.state === "connecting"
                  ? "Подключение…"
                  : "Голосовой чат"}
              </button>
            )}
            <ConnectionBadge state={connection} />
          </div>
        </header>

        {visibleScreenShares.length > 0 || voice.cameraFeeds.length > 0 ? (
          <section
            className="screen-share-stage"
            aria-label="Видео голосового чата"
          >
            {voice.cameraFeeds.map((feed) => {
              const user = usersById.get(feed.identity);
              return (
                <FullscreenMediaCard className="camera-card" key={feed.id}>
                  <CameraPlayer track={feed.track} local={feed.local} />
                  <header>
                    <Avatar user={user} fallbackName={feed.name} />
                    <strong>
                      {user?.username ?? feed.name}
                      {feed.local ? " (вы)" : ""}
                    </strong>
                  </header>
                </FullscreenMediaCard>
              );
            })}
            {visibleScreenShares.map((share) => {
              const user = usersById.get(share.identity);
              return (
                <FullscreenMediaCard
                  className="screen-share-card"
                  key={share.id}
                  onClose={() =>
                    setHiddenScreenShareIds((current) => [
                      ...current.filter((id) => id !== share.id),
                      share.id,
                    ])
                  }
                >
                  <header>
                    <Avatar user={user} fallbackName={share.name} />
                    <strong>
                      Экран пользователя {user?.username ?? share.name}
                    </strong>
                  </header>
                  <ScreenSharePlayer track={share.track} />
                </FullscreenMediaCard>
              );
            })}
          </section>
        ) : null}

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
                  <Avatar
                    user={author}
                    fallbackName={author?.username ?? "?"}
                  />
                  <div className="message-body">
                    <header>
                      <strong>
                        {own ? (
                          <UserName user={currentUser} />
                        ) : author === undefined ? (
                          "Пользователь"
                        ) : (
                          <UserName user={author} />
                        )}
                      </strong>
                      <time dateTime={message.sent_at}>
                        {formatTime(message.sent_at)}
                      </time>
                    </header>
                    {message.text.length > 0 ? <p>{message.text}</p> : null}
                    {message.attachment ===
                    undefined ? null : isImageAttachment(message.attachment) ? (
                      <ImageAttachment
                        attachment={message.attachment}
                        token={session.token}
                      />
                    ) : (
                      <button
                        className="file-attachment"
                        type="button"
                        onClick={() =>
                          void downloadAttachment(message.attachment!)
                        }
                      >
                        <span className="file-icon" aria-hidden="true">
                          ↧
                        </span>
                        <span>
                          <strong>{message.attachment.name}</strong>
                          <small>
                            {formatFileSize(message.attachment.size)}
                          </small>
                        </span>
                      </button>
                    )}
                  </div>
                </article>
              );
            })
          )}
          <div ref={messagesEnd} />
        </div>

        <div className="composer-area">
          <AuthError message={voice.error} />
          <AuthError message={error} />
          <AuthError message={photoDraftError} />
          {photoDrafts.length === 0 ? null : (
            <div className="photo-draft-list" aria-label="Выбранные фото">
              {photoDrafts.map((photo) => (
                <article className="photo-draft" key={photo.id}>
                  <img src={photo.previewUrl} alt={photo.file.name} />
                  <button
                    type="button"
                    aria-label={`Убрать ${photo.file.name}`}
                    title="Убрать фото"
                    disabled={filePending}
                    onClick={() => removePhotoDraft(photo.id)}
                  >
                    ×
                  </button>
                </article>
              ))}
            </div>
          )}
          <form className="composer" onSubmit={submitMessage}>
            <label
              className={`file-picker ${filePending ? "pending" : ""}`}
              title="Отправить файл до 8 МБ"
            >
              <span aria-hidden="true">{filePending ? "…" : "+"}</span>
              <input
                type="file"
                accept="image/*"
                multiple
                disabled={
                  filePending ||
                  connection !== "online" ||
                  (conversation !== "polygon" && selectedUser === undefined)
                }
                onChange={(event) => {
                  addPhotoDrafts(event.target.files);
                  event.target.value = "";
                }}
              />
            </label>
            <textarea
              value={draft}
              maxLength={2_000}
              rows={1}
              disabled={
                conversation !== "polygon" && selectedUser === undefined
              }
              onChange={(event) => setDraft(event.target.value)}
              onKeyDown={handleComposerKeyDown}
              placeholder={`Сообщение в ${title ?? "чат"}`}
              aria-label="Текст сообщения"
            />
            <button
              type="submit"
              disabled={
                filePending ||
                connection !== "online" ||
                (draft.trim().length === 0 && photoDrafts.length === 0) ||
                (conversation !== "polygon" && selectedUser === undefined)
              }
            >
              Отправить
            </button>
          </form>
          <small>Enter — отправить · Shift + Enter — новая строка</small>
        </div>

        {voice.participants.length > 0 ? (
          <aside
            className="voice-participants"
            aria-label="Участники голосового чата"
          >
            <strong className="voice-participants-title">
              Голосовой чат · {voice.participants.length}
            </strong>
            <div className="voice-participants-list">
              {voice.participants.map((participant) => {
                const user = usersById.get(participant.identity);
                return (
                  <div
                    className={`voice-participant ${
                      participant.speaking && !participant.muted
                        ? "speaking"
                        : ""
                    } ${
                      volumeParticipantId === participant.identity
                        ? "volume-open"
                        : ""
                    }`}
                    key={participant.identity}
                    role={
                      participant.local || voice.state !== "connected"
                        ? undefined
                        : "button"
                    }
                    tabIndex={
                      participant.local || voice.state !== "connected" ? -1 : 0
                    }
                    onClick={() => {
                      if (participant.local || voice.state !== "connected") {
                        return;
                      }
                      setVolumeParticipantId((current) =>
                        current === participant.identity
                          ? undefined
                          : participant.identity,
                      );
                    }}
                    onKeyDown={(event) => {
                      if (
                        participant.local ||
                        voice.state !== "connected" ||
                        (event.key !== "Enter" && event.key !== " ")
                      ) {
                        return;
                      }
                      event.preventDefault();
                      setVolumeParticipantId((current) =>
                        current === participant.identity
                          ? undefined
                          : participant.identity,
                      );
                    }}
                  >
                    <Avatar user={user} fallbackName={participant.name} />
                    <span className="voice-participant-name">
                      {user?.username ?? participant.name}
                      {participant.local ? " (вы)" : ""}
                    </span>
                    <span
                      className={
                        participant.muted
                          ? "muted-microphone"
                          : "active-microphone"
                      }
                      role="img"
                      aria-label={
                        participant.muted
                          ? "Микрофон выключен"
                          : "Микрофон включён"
                      }
                      title={
                        participant.muted
                          ? "Микрофон выключен"
                          : "Микрофон включён"
                      }
                    >
                      🎙
                    </span>
                    {participant.local ||
                    voice.state !== "connected" ||
                    volumeParticipantId !== participant.identity ? null : (
                      <div
                        className="participant-volume-controls"
                        onClick={(event) => event.stopPropagation()}
                        onKeyDown={(event) => event.stopPropagation()}
                      >
                        <label>
                          <span>Голос</span>
                          <input
                            type="range"
                            min="0"
                            max="200"
                            step="5"
                            value={
                              voice.participantVoiceVolumes[
                                participant.identity
                              ] ?? 100
                            }
                            aria-label={`Громкость голоса пользователя ${
                              user?.username ?? participant.name
                            }`}
                            onChange={(event) =>
                              voice.setParticipantVoiceVolume(
                                participant.identity,
                                Number(event.target.value),
                              )
                            }
                          />
                          <output>
                            {voice.participantVoiceVolumes[
                              participant.identity
                            ] ?? 100}
                            %
                          </output>
                        </label>
                        <label>
                          <span>Демонстрация</span>
                          <input
                            type="range"
                            min="0"
                            max="200"
                            step="5"
                            value={
                              voice.participantShareVolumes[
                                participant.identity
                              ] ?? 100
                            }
                            aria-label={`Громкость демонстрации пользователя ${
                              user?.username ?? participant.name
                            }`}
                            onChange={(event) =>
                              voice.setParticipantShareVolume(
                                participant.identity,
                                Number(event.target.value),
                              )
                            }
                          />
                          <output>
                            {voice.participantShareVolumes[
                              participant.identity
                            ] ?? 100}
                            %
                          </output>
                        </label>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </aside>
        ) : null}
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
      <Avatar user={user} />
      <span>
        <UserName user={user} />
        <small>Личные сообщения</small>
      </span>
    </button>
  );
}

function Avatar({
  user,
  fallbackName,
}: {
  readonly user: User | undefined;
  readonly fallbackName?: string;
}) {
  const name = user?.username ?? fallbackName ?? "?";
  return (
    <span className="avatar">
      {user?.avatar_url === undefined ? (
        initials(name)
      ) : (
        <img src={avatarSource(user.avatar_url)} alt="" />
      )}
    </span>
  );
}

function ScreenSharePlayer({
  track,
}: {
  readonly track: import("livekit-client").Track;
}) {
  const video = useRef<HTMLVideoElement>(null);

  useEffect(() => {
    const element = video.current;
    if (element === null) return;
    track.attach(element);
    return () => {
      track.detach(element);
    };
  }, [track]);

  return <video ref={video} autoPlay playsInline />;
}

function CameraPlayer({
  track,
  local,
}: {
  readonly track: import("livekit-client").Track;
  readonly local: boolean;
}) {
  const video = useRef<HTMLVideoElement>(null);

  useEffect(() => {
    const element = video.current;
    if (element === null) return;
    track.attach(element);
    return () => {
      track.detach(element);
    };
  }, [track]);

  return <video ref={video} autoPlay playsInline muted={local} />;
}

function FullscreenMediaCard({
  className,
  children,
  onClose,
}: {
  readonly className: string;
  readonly children: ReactNode;
  readonly onClose?: () => void;
}) {
  const container = useRef<HTMLElement>(null);
  const [fullscreen, setFullscreen] = useState(false);

  useEffect(() => {
    const update = () =>
      setFullscreen(document.fullscreenElement === container.current);
    document.addEventListener("fullscreenchange", update);
    return () => document.removeEventListener("fullscreenchange", update);
  }, []);

  const toggleFullscreen = async () => {
    try {
      if (document.fullscreenElement === container.current) {
        await document.exitFullscreen();
      } else {
        await container.current?.requestFullscreen();
      }
    } catch {
      // Some embedded windows can deny fullscreen; media remains available.
    }
  };

  return (
    <article className={className} ref={container}>
      {children}
      <button
        className="media-fullscreen-button"
        type="button"
        aria-label={
          fullscreen ? "Выйти из полноэкранного режима" : "На весь экран"
        }
        title={fullscreen ? "Выйти из полноэкранного режима" : "На весь экран"}
        onClick={() => void toggleFullscreen()}
      >
        {fullscreen ? "↙" : "⛶"}
      </button>
      {onClose === undefined ? null : (
        <button
          className="media-close-button"
          type="button"
          aria-label="Прекратить просмотр демонстрации"
          title="Прекратить просмотр"
          onClick={onClose}
        >
          ×
        </button>
      )}
    </article>
  );
}

function ImageAttachment({
  attachment,
  token,
}: {
  readonly attachment: FileAttachment;
  readonly token: string;
}) {
  const [source, setSource] = useState<string>();
  const [open, setOpen] = useState(false);

  useEffect(() => {
    let active = true;
    let objectUrl: string | undefined;

    fetch(`${apiBaseUrl()}/chat/file/${attachment.id}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then(async (response) => {
        if (!response.ok) throw new Error();
        const bytes = await response.arrayBuffer();
        return new Blob([bytes], { type: attachment.content_type });
      })
      .then((blob) => {
        if (!active) return;
        objectUrl = URL.createObjectURL(blob);
        setSource(objectUrl);
      })
      .catch(() => {
        if (active) setSource("");
      });

    return () => {
      active = false;
      if (objectUrl !== undefined) URL.revokeObjectURL(objectUrl);
    };
  }, [attachment.content_type, attachment.id, token]);

  if (source === undefined) {
    return (
      <div className="image-attachment loading">Загрузка изображения…</div>
    );
  }
  if (source === "") {
    return (
      <button className="file-attachment" type="button">
        Не удалось показать изображение
      </button>
    );
  }

  return (
    <div
      className="image-attachment"
      role="button"
      tabIndex={0}
      title="Открыть изображение"
      onClick={() => setOpen(true)}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          setOpen(true);
        }
      }}
    >
      <img src={source} alt={attachment.name} />
      {open ? (
        <ImageViewer
          source={source}
          name={attachment.name}
          onClose={() => setOpen(false)}
        />
      ) : null}
    </div>
  );
}

function ImageViewer({
  source,
  name,
  onClose,
}: {
  readonly source: string;
  readonly name: string;
  readonly onClose: () => void;
}) {
  useEffect(() => {
    const closeOnEscape = (event: globalThis.KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);

  return (
    <span
      className="image-viewer"
      role="dialog"
      aria-modal="true"
      aria-label={`Просмотр ${name}`}
      onClick={(event) => {
        event.stopPropagation();
        onClose();
      }}
    >
      <img
        src={source}
        alt={name}
        onClick={(event) => event.stopPropagation()}
      />
      <button
        type="button"
        aria-label="Закрыть изображение"
        title="Закрыть"
        onClick={(event) => {
          event.stopPropagation();
          onClose();
        }}
      >
        ×
      </button>
    </span>
  );
}

function avatarSource(value: string): string {
  return value.startsWith("http://") || value.startsWith("https://")
    ? value
    : `${apiBaseUrl()}${value}`;
}

function UserName({ user }: { readonly user: User }) {
  return (
    <span className="username-with-emoji">
      <span>{user.username}</span>
      {user.emoji ? (
        <span className="username-emoji" aria-hidden="true">
          {user.emoji}
        </span>
      ) : null}
    </span>
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

function createDraftPhoto(file: File): DraftPhoto {
  const randomUUID = globalThis.crypto?.randomUUID;
  const id =
    typeof randomUUID === "function"
      ? randomUUID.call(globalThis.crypto)
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;

  return {
    id,
    file,
    previewUrl: URL.createObjectURL(file),
  };
}

function formatTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";

  return new Intl.DateTimeFormat("ru", {
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function formatFileSize(value: number): string {
  if (value < 1024) return `${value} Б`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} КБ`;
  return `${(value / (1024 * 1024)).toFixed(1)} МБ`;
}

function isImageAttachment(attachment: FileAttachment): boolean {
  return attachment.content_type.toLowerCase().startsWith("image/");
}
