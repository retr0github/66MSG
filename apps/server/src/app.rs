use std::{
    collections::{HashMap, VecDeque},
    fmt::Write as _,
    fs,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use axum::{
    Json, Router,
    extract::{
        ConnectInfo, Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{Duration as ChronoDuration, Utc};
use hmac::{Hmac, Mac};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::{sync::broadcast, time::sleep};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::{DefaultOnResponse, TraceLayer},
};
use tracing::{Level, debug, error, info, warn};
use uuid::Uuid;

use crate::{
    config::Config,
    error::AppError,
    models::{
        AuthResponse, ClientEvent, HealthResponse, PasswordLoginRequest, PolygonMessage,
        PrivateMessage, ServerEvent, ServiceStatus, StoredData, StoredSession, StoredUser,
        TelegramCode, TelegramCodePurpose, TelegramLoginCodeRequest, TelegramLoginCodeResponse,
        TelegramLoginRequest, TelegramRegistrationInfo, TelegramRegistrationRequest, User,
    },
};

type HmacSha256 = Hmac<Sha256>;

const USERNAME_MIN: usize = 3;
const USERNAME_MAX: usize = 24;
const PASSWORD_MIN: usize = 8;
const PASSWORD_MAX: usize = 128;
const MESSAGE_LIMIT: usize = 2_000;
const TELEGRAM_CODE_TTL_MINUTES: i64 = 5;
const TELEGRAM_CODE_MAX_ATTEMPTS: u8 = 5;
const RATE_LIMIT_WINDOW: Duration = Duration::from_mins(5);
const RATE_LIMIT_ATTEMPTS: usize = 5;
const JWT_TTL_DAYS: i64 = 30;

#[derive(Clone)]
struct AppState {
    data: Arc<Mutex<StoredData>>,
    data_path: Arc<PathBuf>,
    jwt_secret: Arc<Vec<u8>>,
    telegram_code_secret: Arc<Vec<u8>>,
    telegram_bot_username: Option<String>,
    telegram_bot: Option<TelegramBot>,
    registration_attempts: Arc<Mutex<HashMap<IpAddr, VecDeque<Instant>>>>,
    events: broadcast::Sender<ServerEvent>,
}

impl AppState {
    fn load(config: &Config, telegram_bot: Option<TelegramBot>) -> Result<Self, AppError> {
        let data_path = config.data_path();
        let data = if data_path.exists() {
            serde_json::from_slice(&fs::read(data_path)?)?
        } else {
            StoredData::default()
        };
        let (events, _) = broadcast::channel(256);

        Ok(Self {
            data: Arc::new(Mutex::new(data)),
            data_path: Arc::new(data_path.to_path_buf()),
            jwt_secret: Arc::new(config.jwt_secret().as_bytes().to_vec()),
            telegram_code_secret: Arc::new(config.telegram_code_secret().as_bytes().to_vec()),
            telegram_bot_username: config.telegram_bot_username().map(ToOwned::to_owned),
            telegram_bot,
            registration_attempts: Arc::new(Mutex::new(HashMap::new())),
            events,
        })
    }

    fn data(&self) -> Result<MutexGuard<'_, StoredData>, ApiError> {
        self.data
            .lock()
            .map_err(|_| ApiError::internal("Не удалось получить доступ к данным"))
    }

    fn persist(&self, data: &StoredData) -> Result<(), ApiError> {
        if let Some(parent) = self.data_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|_| ApiError::internal("Не удалось создать папку данных"))?;
        }

        let json = serde_json::to_vec_pretty(data)
            .map_err(|_| ApiError::internal("Не удалось подготовить данные к сохранению"))?;
        let temporary_path = self.data_path.with_extension("json.tmp");
        fs::write(&temporary_path, json)
            .map_err(|_| ApiError::internal("Не удалось записать данные"))?;

        if self.data_path.exists() {
            fs::remove_file(self.data_path.as_ref())
                .map_err(|_| ApiError::internal("Не удалось обновить файл данных"))?;
        }
        fs::rename(temporary_path, self.data_path.as_ref())
            .map_err(|_| ApiError::internal("Не удалось завершить сохранение данных"))
    }

    fn user_for_token(&self, token: &str) -> Result<AuthenticatedUser, ApiError> {
        let claims = decode::<JwtClaims>(
            token,
            &DecodingKey::from_secret(&self.jwt_secret),
            &Validation::new(Algorithm::HS256),
        )
        .map_err(|_| ApiError::unauthorized("Сессия недействительна. Войдите снова"))?
        .claims;
        let user_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| ApiError::unauthorized("Некорректная сессия"))?;
        let session_id = Uuid::parse_str(&claims.jti)
            .map_err(|_| ApiError::unauthorized("Некорректная сессия"))?;

        let data = self.data()?;
        let session_is_active = data.sessions.iter().any(|session| {
            session.id == session_id && session.user_id == user_id && session.revoked_at.is_none()
        });
        if !session_is_active {
            return Err(ApiError::unauthorized("Сессия завершена. Войдите снова"));
        }
        let user = data
            .users
            .iter()
            .find(|stored| stored.user.id == user_id)
            .map(|stored| stored.user.clone())
            .ok_or_else(|| ApiError::unauthorized("Пользователь не найден"))?;
        Ok(AuthenticatedUser { user, session_id })
    }

    fn create_session(&self, user_id: Uuid) -> Result<(String, Uuid), ApiError> {
        let issued_at = Utc::now();
        let session_id = Uuid::new_v4();
        {
            let mut data = self.data()?;
            let mut updated = data.clone();
            updated.sessions.push(StoredSession {
                id: session_id,
                user_id,
                created_at: issued_at,
                revoked_at: None,
            });
            self.persist(&updated)?;
            *data = updated;
        }
        let claims = JwtClaims {
            sub: user_id.to_string(),
            jti: session_id.to_string(),
            iat: issued_at.timestamp(),
            exp: (issued_at + ChronoDuration::days(JWT_TTL_DAYS)).timestamp(),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(&self.jwt_secret),
        )
        .map_err(|_| ApiError::internal("Не удалось выпустить токен"))?;
        Ok((token, session_id))
    }

    fn check_registration_rate(&self, ip: IpAddr) -> Result<(), ApiError> {
        let now = Instant::now();
        let mut all_attempts = self
            .registration_attempts
            .lock()
            .map_err(|_| ApiError::internal("Не удалось проверить лимит запросов"))?;
        let attempts = all_attempts.entry(ip).or_default();
        while attempts
            .front()
            .is_some_and(|time| now.duration_since(*time) > RATE_LIMIT_WINDOW)
        {
            attempts.pop_front();
        }
        if attempts.len() >= RATE_LIMIT_ATTEMPTS {
            return Err(ApiError::too_many_attempts());
        }
        attempts.push_back(now);
        Ok(())
    }

    fn issue_telegram_code(
        &self,
        telegram_user: &TelegramUser,
        purpose: TelegramCodePurpose,
    ) -> Result<String, ApiError> {
        let code = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000_u32));
        let code_hash = self.code_hash(&code, telegram_user.id)?;
        let lookup_hash = self.lookup_hash(&code)?;
        let now = Utc::now();

        let mut data = self.data()?;
        let mut updated = data.clone();
        for existing in &mut updated.telegram_codes {
            if existing.telegram_id == telegram_user.id
                && existing.purpose == purpose
                && existing.used_at.is_none()
                && existing.expires_at > now
            {
                existing.used_at = Some(now);
            }
        }
        updated.telegram_codes.push(TelegramCode {
            code_hash,
            lookup_hash,
            telegram_id: telegram_user.id,
            username: telegram_user.username.clone(),
            first_name: Some(telegram_user.first_name.clone()),
            last_name: telegram_user.last_name.clone(),
            expires_at: now + ChronoDuration::minutes(TELEGRAM_CODE_TTL_MINUTES),
            used_at: None,
            attempts: 0,
            purpose,
        });
        self.persist(&updated)?;
        *data = updated;
        Ok(code)
    }

    fn code_hash(&self, code: &str, telegram_id: i64) -> Result<String, ApiError> {
        hmac_hex(
            &self.telegram_code_secret,
            format!("{code}:{telegram_id}").as_bytes(),
        )
    }

    fn lookup_hash(&self, code: &str) -> Result<String, ApiError> {
        hmac_hex(&self.telegram_code_secret, code.as_bytes())
    }
}

#[derive(Debug)]
struct AuthenticatedUser {
    user: User,
    session_id: Uuid,
}

#[derive(Clone)]
struct TelegramBot {
    client: reqwest::Client,
    token: Arc<String>,
}

impl TelegramBot {
    fn endpoint(&self, method: &str) -> String {
        format!("https://api.telegram.org/bot{}/{method}", self.token)
    }

    async fn send_text(&self, chat_id: i64, text: &str) -> Result<(), ApiError> {
        let response = self
            .client
            .post(self.endpoint("sendMessage"))
            .json(&serde_json::json!({ "chat_id": chat_id, "text": text }))
            .send()
            .await
            .map_err(|_| ApiError::telegram_unavailable())?;
        if !response.status().is_success() {
            return Err(ApiError::telegram_unavailable());
        }
        Ok(())
    }

    async fn send_login_notification(
        &self,
        chat_id: i64,
        username: &str,
        session_id: Uuid,
    ) -> Result<(), ApiError> {
        let response = self
            .client
            .post(self.endpoint("sendMessage"))
            .json(&serde_json::json!({
                "chat_id": chat_id,
                "text": format!(
                    "Выполнен вход в аккаунт 66MSG «{username}».\n\nЕсли это не вы"
                ),
                "reply_markup": {
                    "inline_keyboard": [[{
                        "text": "Выйти из аккаунта с этого устройства",
                        "callback_data": format!("revoke:{session_id}")
                    }]]
                }
            }))
            .send()
            .await
            .map_err(|_| ApiError::telegram_unavailable())?;
        if !response.status().is_success() {
            return Err(ApiError::telegram_unavailable());
        }
        Ok(())
    }

    async fn answer_callback(&self, callback_id: &str, text: &str) {
        let result = self
            .client
            .post(self.endpoint("answerCallbackQuery"))
            .json(&serde_json::json!({
                "callback_query_id": callback_id,
                "text": text,
                "show_alert": true
            }))
            .send()
            .await;
        if result.is_err() {
            warn!("failed to answer Telegram callback");
        }
    }
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "BAD_REQUEST", message)
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", message)
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", message)
    }

    fn invalid_code() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "INVALID_CODE",
            "Неверный одноразовый код",
        )
    }

    fn code_expired() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "CODE_EXPIRED",
            "Срок действия кода истёк",
        )
    }

    fn too_many_attempts() -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "TOO_MANY_ATTEMPTS",
            "Слишком много попыток. Получите новый код позже",
        )
    }

    fn telegram_already_registered() -> Self {
        Self::new(
            StatusCode::CONFLICT,
            "TELEGRAM_ALREADY_REGISTERED",
            "Этот Telegram-аккаунт уже зарегистрирован",
        )
    }

    fn username_taken() -> Self {
        Self::new(StatusCode::CONFLICT, "USERNAME_TAKEN", "Этот ник уже занят")
    }

    fn telegram_not_registered() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "TELEGRAM_NOT_REGISTERED",
            "К этому Telegram-аккаунту ещё не привязан аккаунт 66MSG",
        )
    }

    fn telegram_unavailable() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "TELEGRAM_UNAVAILABLE",
            "Не удалось отправить сообщение в Telegram. Попробуйте позже",
        )
    }
}

#[derive(Serialize)]
struct ApiErrorBody {
    code: &'static str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ApiErrorBody {
                code: self.code,
                message: self.message,
            }),
        )
            .into_response()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    sub: String,
    jti: String,
    iat: i64,
    exp: i64,
}

#[derive(Deserialize)]
struct AuthQuery {
    token: String,
}

pub fn build_router(config: &Config) -> Result<Router, AppError> {
    let telegram_bot = config
        .telegram_bot_token()
        .and_then(|token| build_telegram_bot(token, config.telegram_proxy_url()));
    let state = AppState::load(config, telegram_bot.clone())?;

    if let Some(bot) = telegram_bot {
        tokio::spawn(run_telegram_bot(state.clone(), bot));
    } else {
        warn!("TELEGRAM_BOT_TOKEN is not set; Telegram bot polling is disabled");
    }

    Ok(Router::new()
        .route("/health", get(health))
        .route("/auth/telegram", get(telegram_registration_info))
        .route(
            "/auth/register/telegram-code",
            post(register_with_telegram_code),
        )
        .route("/auth/login/password", post(login_with_password))
        .route(
            "/auth/login/telegram-code/request",
            post(request_telegram_login_code),
        )
        .route("/auth/login/telegram-code", post(login_with_telegram_code))
        .route("/ws", get(websocket))
        .with_state(state)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST])
                .allow_headers(Any),
        )
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &axum::http::Request<axum::body::Body>| {
                    tracing::info_span!(
                        "http_request",
                        method = %request.method(),
                        path = request.uri().path()
                    )
                })
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        ))
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: ServiceStatus::Healthy,
        service: "66msg-server",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn telegram_registration_info(
    State(state): State<AppState>,
) -> Json<TelegramRegistrationInfo> {
    let bot_url = state
        .telegram_bot_username
        .as_ref()
        .map(|username| format!("https://t.me/{username}"));
    Json(TelegramRegistrationInfo {
        bot_username: state.telegram_bot_username.clone(),
        bot_url,
        code_ttl_seconds: TELEGRAM_CODE_TTL_MINUTES * 60,
    })
}

async fn register_with_telegram_code(
    State(state): State<AppState>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    Json(request): Json<TelegramRegistrationRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    state.check_registration_rate(address.ip())?;

    let code = request.code.trim();
    if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ApiError::invalid_code());
    }
    let username = validate_username(&request.username)?;
    validate_password(&request.password)?;
    let password_hash = hash_password(&request.password)?;
    let now = Utc::now();

    let user = {
        let mut data = state.data()?;
        let mut updated = data.clone();
        let Some(code_index) = updated.telegram_codes.iter().rposition(|item| {
            item.used_at.is_none()
                && item.purpose == TelegramCodePurpose::Registration
                && verify_hmac_hex(
                    &state.telegram_code_secret,
                    code.as_bytes(),
                    &item.lookup_hash,
                )
        }) else {
            return Err(ApiError::invalid_code());
        };

        let (telegram_id, telegram_username, first_name, last_name) = {
            let registration_code = &mut updated.telegram_codes[code_index];
            if registration_code.attempts >= TELEGRAM_CODE_MAX_ATTEMPTS {
                return Err(ApiError::too_many_attempts());
            }
            if registration_code.expires_at <= now {
                return Err(ApiError::code_expired());
            }

            let expected_payload = format!("{code}:{}", registration_code.telegram_id);
            if !verify_hmac_hex(
                &state.telegram_code_secret,
                expected_payload.as_bytes(),
                &registration_code.code_hash,
            ) {
                registration_code.attempts = registration_code.attempts.saturating_add(1);
                state.persist(&updated)?;
                *data = updated;
                return Err(ApiError::invalid_code());
            }
            (
                registration_code.telegram_id,
                registration_code.username.clone(),
                registration_code.first_name.clone(),
                registration_code.last_name.clone(),
            )
        };

        if updated
            .users
            .iter()
            .any(|stored| stored.telegram_id == Some(telegram_id))
        {
            return Err(ApiError::telegram_already_registered());
        }

        if username_exists(&updated, &username) {
            return Err(ApiError::username_taken());
        }

        let user = User {
            id: Uuid::new_v4(),
            username,
            telegram_username,
            telegram_first_name: first_name,
            telegram_last_name: last_name,
            created_at: now,
        };
        updated.telegram_codes[code_index].used_at = Some(now);
        updated.users.push(StoredUser {
            user: user.clone(),
            telegram_id: Some(telegram_id),
            password_hash: Some(password_hash),
        });

        state.persist(&updated)?;
        *data = updated;
        user
    };

    let (token, session_id) = state.create_session(user.id)?;
    notify_login(&state, &user, session_id).await;
    let _receiver_count = state
        .events
        .send(ServerEvent::UserRegistered { user: user.clone() });
    Ok(Json(AuthResponse { token, user }))
}

async fn login_with_password(
    State(state): State<AppState>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    Json(request): Json<PasswordLoginRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    state.check_registration_rate(address.ip())?;
    let username = request.username.trim();
    let stored = state
        .data()?
        .users
        .iter()
        .find(|item| item.user.username.eq_ignore_ascii_case(username))
        .cloned()
        .ok_or_else(invalid_credentials)?;
    let password_hash = stored
        .password_hash
        .as_deref()
        .ok_or_else(invalid_credentials)?;
    let parsed_hash = PasswordHash::new(password_hash).map_err(|_| invalid_credentials())?;
    Argon2::default()
        .verify_password(request.password.as_bytes(), &parsed_hash)
        .map_err(|_| invalid_credentials())?;

    let (token, session_id) = state.create_session(stored.user.id)?;
    notify_login(&state, &stored.user, session_id).await;
    Ok(Json(AuthResponse {
        token,
        user: stored.user,
    }))
}

async fn request_telegram_login_code(
    State(state): State<AppState>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    Json(request): Json<TelegramLoginCodeRequest>,
) -> Result<Json<TelegramLoginCodeResponse>, ApiError> {
    state.check_registration_rate(address.ip())?;
    let stored = state
        .data()?
        .users
        .iter()
        .find(|item| {
            item.user
                .username
                .eq_ignore_ascii_case(request.username.trim())
        })
        .cloned()
        .ok_or_else(ApiError::telegram_not_registered)?;
    let telegram_id = stored
        .telegram_id
        .ok_or_else(ApiError::telegram_not_registered)?;
    let bot = state
        .telegram_bot
        .clone()
        .ok_or_else(ApiError::telegram_unavailable)?;
    let telegram_user = TelegramUser {
        id: telegram_id,
        first_name: stored
            .user
            .telegram_first_name
            .clone()
            .unwrap_or_else(|| stored.user.username.clone()),
        last_name: stored.user.telegram_last_name.clone(),
        username: stored.user.telegram_username.clone(),
    };
    let code = state.issue_telegram_code(&telegram_user, TelegramCodePurpose::Login)?;
    if let Err(error) = bot
        .send_text(
            telegram_id,
            &format!(
                "Ваш код входа в 66MSG: {code}. Он действует {TELEGRAM_CODE_TTL_MINUTES} минут."
            ),
        )
        .await
    {
        invalidate_latest_code(&state, telegram_id, TelegramCodePurpose::Login)?;
        return Err(error);
    }
    Ok(Json(TelegramLoginCodeResponse {
        expires_in_seconds: TELEGRAM_CODE_TTL_MINUTES * 60,
    }))
}

async fn login_with_telegram_code(
    State(state): State<AppState>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    Json(request): Json<TelegramLoginRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    state.check_registration_rate(address.ip())?;
    let username = request.username.trim();
    let code = request.code.trim();
    if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ApiError::invalid_code());
    }
    let now = Utc::now();

    let user = {
        let mut data = state.data()?;
        let mut updated = data.clone();
        let stored = updated
            .users
            .iter()
            .find(|item| item.user.username.eq_ignore_ascii_case(username))
            .cloned()
            .ok_or_else(ApiError::invalid_code)?;
        let telegram_id = stored.telegram_id.ok_or_else(ApiError::invalid_code)?;
        let Some(code_index) = updated.telegram_codes.iter().rposition(|item| {
            item.telegram_id == telegram_id
                && item.purpose == TelegramCodePurpose::Login
                && item.used_at.is_none()
        }) else {
            return Err(ApiError::invalid_code());
        };

        let login_code = &mut updated.telegram_codes[code_index];
        if login_code.attempts >= TELEGRAM_CODE_MAX_ATTEMPTS {
            return Err(ApiError::too_many_attempts());
        }
        if login_code.expires_at <= now {
            return Err(ApiError::code_expired());
        }
        let expected_payload = format!("{code}:{telegram_id}");
        if !verify_hmac_hex(
            &state.telegram_code_secret,
            expected_payload.as_bytes(),
            &login_code.code_hash,
        ) {
            login_code.attempts = login_code.attempts.saturating_add(1);
            state.persist(&updated)?;
            *data = updated;
            return Err(ApiError::invalid_code());
        }

        login_code.used_at = Some(now);
        state.persist(&updated)?;
        *data = updated;
        stored.user
    };

    let (token, session_id) = state.create_session(user.id)?;
    notify_login(&state, &user, session_id).await;
    Ok(Json(AuthResponse { token, user }))
}

async fn websocket(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Query(query): Query<AuthQuery>,
) -> Result<Response, ApiError> {
    let authenticated = state.user_for_token(&query.token)?;
    Ok(ws.on_upgrade(move |socket| handle_socket(socket, state, authenticated)))
}

async fn handle_socket(mut socket: WebSocket, state: AppState, authenticated: AuthenticatedUser) {
    let current_user = authenticated.user;
    let session_id = authenticated.session_id;
    let mut events = state.events.subscribe();
    let ready = match ready_event(&state, &current_user) {
        Ok(event) => event,
        Err(api_error) => {
            let _result = send_event(
                &mut socket,
                &ServerEvent::Error {
                    message: api_error.message,
                },
            )
            .await;
            return;
        }
    };

    if send_event(&mut socket, &ready).await.is_err() {
        return;
    }

    loop {
        tokio::select! {
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Text(payload))) => {
                        if let Some(event) = process_client_message(&state, current_user.id, &payload)
                            && send_event(&mut socket, &event).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(payload))) => {
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(receive_error)) => {
                        debug!(%receive_error, "websocket receive error");
                        break;
                    }
                }
            }
            event = events.recv() => {
                match event {
                    Ok(ServerEvent::SessionRevoked { session_id: revoked })
                        if revoked == session_id => {
                            let _result = send_event(
                                &mut socket,
                                &ServerEvent::SessionRevoked { session_id },
                            )
                            .await;
                            let _result = socket.send(Message::Close(None)).await;
                            break;
                        }
                    Ok(event) if event_is_visible(&event, current_user.id) => {
                        if send_event(&mut socket, &event).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!(skipped, "websocket client lagged behind");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

fn ready_event(state: &AppState, current_user: &User) -> Result<ServerEvent, ApiError> {
    let data = state.data()?;
    let users = data
        .users
        .iter()
        .map(|stored| stored.user.clone())
        .collect();
    let messages = data
        .messages
        .iter()
        .filter(|message| {
            message.sender_id == current_user.id || message.recipient_id == current_user.id
        })
        .cloned()
        .collect();

    Ok(ServerEvent::Ready {
        current_user: current_user.clone(),
        users,
        messages,
        polygon_messages: data.polygon_messages.clone(),
    })
}

fn process_client_message(state: &AppState, sender_id: Uuid, payload: &str) -> Option<ServerEvent> {
    let Ok(event) = serde_json::from_str::<ClientEvent>(payload) else {
        return Some(ServerEvent::Error {
            message: "Некорректный формат сообщения".to_owned(),
        });
    };

    match event {
        ClientEvent::SendPrivateMessage { recipient_id, text } => {
            let text = match validated_message_text(&text) {
                Ok(text) => text,
                Err(message) => return Some(ServerEvent::Error { message }),
            };
            if recipient_id == sender_id {
                return Some(ServerEvent::Error {
                    message: "Нельзя отправить личное сообщение самому себе".to_owned(),
                });
            }

            let message = PrivateMessage {
                id: Uuid::new_v4(),
                sender_id,
                recipient_id,
                text,
                sent_at: Utc::now(),
            };
            let result = (|| -> Result<(), ApiError> {
                let mut data = state.data()?;
                if !data
                    .users
                    .iter()
                    .any(|stored| stored.user.id == recipient_id)
                {
                    return Err(ApiError::bad_request("Получатель не найден"));
                }
                let mut updated = data.clone();
                updated.messages.push(message.clone());
                state.persist(&updated)?;
                *data = updated;
                Ok(())
            })();
            if let Err(api_error) = result {
                return Some(ServerEvent::Error {
                    message: api_error.message,
                });
            }
            let _receiver_count = state.events.send(ServerEvent::PrivateMessage { message });
            None
        }
        ClientEvent::SendPolygonMessage { text } => {
            let text = match validated_message_text(&text) {
                Ok(text) => text,
                Err(message) => return Some(ServerEvent::Error { message }),
            };
            let message = PolygonMessage {
                id: Uuid::new_v4(),
                author_id: sender_id,
                text,
                sent_at: Utc::now(),
            };
            let result = (|| -> Result<(), ApiError> {
                let mut data = state.data()?;
                let mut updated = data.clone();
                updated.polygon_messages.push(message.clone());
                state.persist(&updated)?;
                *data = updated;
                Ok(())
            })();
            if let Err(api_error) = result {
                return Some(ServerEvent::Error {
                    message: api_error.message,
                });
            }
            let _receiver_count = state.events.send(ServerEvent::PolygonMessage { message });
            None
        }
    }
}

fn validated_message_text(text: &str) -> Result<String, String> {
    let text = text.trim();
    if text.is_empty() || text.chars().count() > MESSAGE_LIMIT {
        return Err(format!(
            "Сообщение должно содержать от 1 до {MESSAGE_LIMIT} символов"
        ));
    }
    Ok(text.to_owned())
}

fn event_is_visible(event: &ServerEvent, user_id: Uuid) -> bool {
    match event {
        ServerEvent::PrivateMessage { message } => {
            message.sender_id == user_id || message.recipient_id == user_id
        }
        ServerEvent::Ready { .. }
        | ServerEvent::UserRegistered { .. }
        | ServerEvent::PolygonMessage { .. }
        | ServerEvent::Error { .. } => true,
        ServerEvent::SessionRevoked { .. } => false,
    }
}

async fn notify_login(state: &AppState, user: &User, session_id: Uuid) {
    let Some(bot) = state.telegram_bot.clone() else {
        return;
    };
    let telegram_id = match state.data() {
        Ok(data) => data
            .users
            .iter()
            .find(|stored| stored.user.id == user.id)
            .and_then(|stored| stored.telegram_id),
        Err(_) => None,
    };
    let Some(telegram_id) = telegram_id else {
        return;
    };
    if let Err(error) = bot
        .send_login_notification(telegram_id, &user.username, session_id)
        .await
    {
        warn!(message = %error.message, "failed to send login notification");
    }
}

fn invalidate_latest_code(
    state: &AppState,
    telegram_id: i64,
    purpose: TelegramCodePurpose,
) -> Result<(), ApiError> {
    let mut data = state.data()?;
    let mut updated = data.clone();
    if let Some(code) = updated.telegram_codes.iter_mut().rev().find(|code| {
        code.telegram_id == telegram_id && code.purpose == purpose && code.used_at.is_none()
    }) {
        code.used_at = Some(Utc::now());
    }
    state.persist(&updated)?;
    *data = updated;
    Ok(())
}

fn validate_username(value: &str) -> Result<String, ApiError> {
    let username = value.trim();
    let length = username.chars().count();
    if !(USERNAME_MIN..=USERNAME_MAX).contains(&length) {
        return Err(ApiError::bad_request(format!(
            "Ник должен содержать от {USERNAME_MIN} до {USERNAME_MAX} символов"
        )));
    }
    if !username
        .chars()
        .all(|character| character.is_alphanumeric() || matches!(character, '_' | '-'))
    {
        return Err(ApiError::bad_request(
            "В нике разрешены только буквы, цифры, дефис и подчёркивание",
        ));
    }
    Ok(username.to_owned())
}

fn validate_password(value: &str) -> Result<(), ApiError> {
    let length = value.chars().count();
    if !(PASSWORD_MIN..=PASSWORD_MAX).contains(&length) {
        return Err(ApiError::bad_request(format!(
            "Пароль должен содержать от {PASSWORD_MIN} до {PASSWORD_MAX} символов"
        )));
    }
    Ok(())
}

fn hash_password(password: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| ApiError::internal("Не удалось защитить пароль"))
}

fn invalid_credentials() -> ApiError {
    ApiError::unauthorized("Неверный ник или пароль")
}

fn username_exists(data: &StoredData, username: &str) -> bool {
    data.users
        .iter()
        .any(|stored| stored.user.username.eq_ignore_ascii_case(username))
}

fn hmac_hex(secret: &[u8], payload: &[u8]) -> Result<String, ApiError> {
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| ApiError::internal("Некорректный HMAC-секрет"))?;
    mac.update(payload);
    Ok(encode_hex(&mac.finalize().into_bytes()))
}

fn verify_hmac_hex(secret: &[u8], payload: &[u8], expected_hex: &str) -> bool {
    let Some(expected) = decode_hex(expected_hex) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
        return false;
    };
    mac.update(payload);
    mac.verify_slice(&expected).is_ok()
}

fn encode_hex(value: &[u8]) -> String {
    value.iter().fold(
        String::with_capacity(value.len() * 2),
        |mut output, byte| {
            let _result = write!(output, "{byte:02x}");
            output
        },
    )
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(text, 16).ok()
        })
        .collect()
}

async fn send_event(socket: &mut WebSocket, event: &ServerEvent) -> Result<(), ()> {
    let payload = serde_json::to_string(event).map_err(|serialization_error| {
        warn!(%serialization_error, "failed to serialize websocket event");
    })?;

    socket
        .send(Message::Text(payload.into()))
        .await
        .map_err(|send_error| {
            debug!(%send_error, "failed to send websocket event");
        })
}

#[derive(Debug, Deserialize)]
struct TelegramApiResponse<T> {
    ok: bool,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct TelegramUpdate {
    update_id: i64,
    message: Option<TelegramMessage>,
    callback_query: Option<TelegramCallbackQuery>,
}

#[derive(Debug, Deserialize)]
struct TelegramMessage {
    chat: TelegramChat,
    from: Option<TelegramUser>,
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TelegramChat {
    id: i64,
}

#[derive(Debug, Deserialize)]
struct TelegramUser {
    id: i64,
    first_name: String,
    last_name: Option<String>,
    username: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TelegramCallbackQuery {
    id: String,
    from: TelegramUser,
    data: Option<String>,
}

fn build_telegram_bot(token: &str, proxy_url: Option<&str>) -> Option<TelegramBot> {
    let mut client_builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(35));
    if let Some(proxy_url) = proxy_url {
        let Ok(proxy) = reqwest::Proxy::all(proxy_url) else {
            error!("TELEGRAM_PROXY_URL is invalid; Telegram bot polling is disabled");
            return None;
        };
        client_builder = client_builder.proxy(proxy);
    }
    let Ok(client) = client_builder.build() else {
        error!("failed to create Telegram HTTP client");
        return None;
    };
    Some(TelegramBot {
        client,
        token: Arc::new(token.to_owned()),
    })
}

async fn run_telegram_bot(state: AppState, bot: TelegramBot) {
    let mut offset = 0_i64;
    info!("Telegram bot polling started");

    loop {
        let response = bot
            .client
            .get(bot.endpoint("getUpdates"))
            .query(&[
                ("offset", offset.to_string()),
                ("timeout", "25".to_owned()),
                (
                    "allowed_updates",
                    r#"["message","callback_query"]"#.to_owned(),
                ),
            ])
            .timeout(Duration::from_secs(35))
            .send()
            .await;

        match response {
            Ok(response) => match response
                .json::<TelegramApiResponse<Vec<TelegramUpdate>>>()
                .await
            {
                Ok(body) if body.ok => {
                    for update in body.result.unwrap_or_default() {
                        offset = offset.max(update.update_id + 1);
                        handle_telegram_update(&bot, &state, update).await;
                    }
                }
                Ok(_) => warn!("Telegram getUpdates returned an unsuccessful response"),
                Err(parse_error) => warn!(%parse_error, "failed to parse Telegram response"),
            },
            Err(request_error) => {
                warn!(
                    timeout = request_error.is_timeout(),
                    connect = request_error.is_connect(),
                    "Telegram polling request failed"
                );
                sleep(Duration::from_secs(3)).await;
            }
        }
    }
}

async fn handle_telegram_update(bot: &TelegramBot, state: &AppState, update: TelegramUpdate) {
    if let Some(callback) = update.callback_query {
        handle_telegram_callback(bot, state, callback).await;
        return;
    }
    let Some(message) = update.message else {
        return;
    };
    let command = message.text.as_deref().unwrap_or_default();
    let purpose = if command.starts_with("/start") || command.starts_with("/register") {
        TelegramCodePurpose::Registration
    } else {
        send_telegram_message(
            bot,
            message.chat.id,
            "Для регистрации отправьте /register. Код входа запрашивается автоматически на сайте 66MSG.",
        )
        .await;
        return;
    };
    let Some(telegram_user) = message.from else {
        return;
    };

    let is_registered = match state.data() {
        Ok(data) => data
            .users
            .iter()
            .any(|stored| stored.telegram_id == Some(telegram_user.id)),
        Err(issue_error) => {
            error!(message = %issue_error.message, "failed to read Telegram account status");
            return;
        }
    };
    if purpose == TelegramCodePurpose::Registration && is_registered {
        send_telegram_message(
            bot,
            message.chat.id,
            "Этот Telegram уже привязан к аккаунту 66MSG. Для входа запросите код на сайте.",
        )
        .await;
        return;
    }
    match state.issue_telegram_code(&telegram_user, purpose) {
        Ok(code) => {
            send_telegram_message(
                bot,
                message.chat.id,
                &format!(
                    "Ваш код регистрации: {code}. Он действует {TELEGRAM_CODE_TTL_MINUTES} минут."
                ),
            )
            .await;
        }
        Err(issue_error) => {
            error!(message = %issue_error.message, "failed to issue Telegram registration code");
            send_telegram_message(
                bot,
                message.chat.id,
                "Не удалось создать код. Попробуйте ещё раз позже.",
            )
            .await;
        }
    }
}

async fn handle_telegram_callback(
    bot: &TelegramBot,
    state: &AppState,
    callback: TelegramCallbackQuery,
) {
    let Some(data) = callback.data.as_deref() else {
        return;
    };
    let Some(session_text) = data.strip_prefix("revoke:") else {
        return;
    };
    let Ok(session_id) = Uuid::parse_str(session_text) else {
        bot.answer_callback(&callback.id, "Некорректная сессия")
            .await;
        return;
    };

    let result = (|| -> Result<bool, ApiError> {
        let mut stored = state.data()?;
        let mut updated = stored.clone();
        let user_ids: Vec<Uuid> = updated
            .users
            .iter()
            .filter(|user| user.telegram_id == Some(callback.from.id))
            .map(|user| user.user.id)
            .collect();
        let Some(session) = updated
            .sessions
            .iter_mut()
            .find(|session| session.id == session_id && user_ids.contains(&session.user_id))
        else {
            return Ok(false);
        };
        if session.revoked_at.is_none() {
            session.revoked_at = Some(Utc::now());
            state.persist(&updated)?;
            *stored = updated;
            let _receiver_count = state
                .events
                .send(ServerEvent::SessionRevoked { session_id });
        }
        Ok(true)
    })();

    match result {
        Ok(true) => {
            bot.answer_callback(&callback.id, "Устройство вышло из аккаунта 66MSG")
                .await;
        }
        Ok(false) => {
            bot.answer_callback(&callback.id, "Сессия уже завершена или не найдена")
                .await;
        }
        Err(_) => {
            bot.answer_callback(&callback.id, "Не удалось завершить сессию")
                .await;
        }
    }
}

async fn send_telegram_message(bot: &TelegramBot, chat_id: i64, text: &str) {
    if let Err(error) = bot.send_text(chat_id, text).await {
        warn!(message = %error.message, "failed to send Telegram message");
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        fs,
        sync::{Arc, Mutex},
    };

    use argon2::{
        Argon2,
        password_hash::{PasswordHash, PasswordVerifier},
    };
    use chrono::Utc;
    use tokio::sync::broadcast;
    use uuid::Uuid;

    use super::{
        AppState, event_is_visible, hash_password, hmac_hex, validate_password, validate_username,
        verify_hmac_hex,
    };
    use crate::models::{ServerEvent, StoredData, StoredUser, User};

    #[test]
    fn hmac_verification_is_exact() {
        let secret = b"this-secret-is-long-enough-for-tests";
        let result = hmac_hex(secret, b"123456:42");
        assert!(result.is_ok());
        let hash = result.unwrap_or_default();
        assert!(verify_hmac_hex(secret, b"123456:42", &hash));
        assert!(!verify_hmac_hex(secret, b"123457:42", &hash));
    }

    #[test]
    fn validates_selected_username() {
        assert_eq!(
            validate_username(" Alex_66 ").ok().as_deref(),
            Some("Alex_66")
        );
        assert!(validate_username("ab").is_err());
        assert!(validate_username("bad nickname").is_err());
    }

    #[test]
    fn hashes_and_verifies_password() {
        assert!(validate_password("correct-password").is_ok());
        assert!(validate_password("short").is_err());

        let encoded = hash_password("correct-password");
        assert!(encoded.is_ok());
        let encoded = encoded.unwrap_or_default();
        let parsed = PasswordHash::new(&encoded);
        assert!(parsed.is_ok());
        if let Ok(parsed) = parsed {
            assert!(
                Argon2::default()
                    .verify_password(b"correct-password", &parsed)
                    .is_ok()
            );
            assert!(
                Argon2::default()
                    .verify_password(b"wrong-password", &parsed)
                    .is_err()
            );
        }
    }

    #[test]
    fn revoked_session_is_rejected() {
        let user = User {
            id: Uuid::new_v4(),
            username: "session_test".to_owned(),
            telegram_username: None,
            telegram_first_name: None,
            telegram_last_name: None,
            created_at: Utc::now(),
        };
        let mut data = StoredData::default();
        data.users.push(StoredUser {
            user: user.clone(),
            telegram_id: Some(123),
            password_hash: None,
        });
        let path = std::env::temp_dir().join(format!("66msg-test-{}.json", Uuid::new_v4()));
        let (events, _) = broadcast::channel(8);
        let state = AppState {
            data: Arc::new(Mutex::new(data)),
            data_path: Arc::new(path.clone()),
            jwt_secret: Arc::new(vec![b'x'; 32]),
            telegram_code_secret: Arc::new(vec![b'y'; 32]),
            telegram_bot_username: None,
            telegram_bot: None,
            registration_attempts: Arc::new(Mutex::new(HashMap::new())),
            events,
        };

        let created = state.create_session(user.id);
        assert!(created.is_ok());
        if let Ok((token, session_id)) = created {
            assert!(state.user_for_token(&token).is_ok());
            if let Ok(mut stored) = state.data()
                && let Some(session) = stored
                    .sessions
                    .iter_mut()
                    .find(|session| session.id == session_id)
            {
                session.revoked_at = Some(Utc::now());
            }
            assert!(state.user_for_token(&token).is_err());
        }

        let _result = fs::remove_file(path);
    }

    #[test]
    fn session_revocation_is_not_broadcast_to_other_devices() {
        assert!(!event_is_visible(
            &ServerEvent::SessionRevoked {
                session_id: Uuid::new_v4(),
            },
            Uuid::new_v4(),
        ));
    }
}
