use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: ServiceStatus,
    pub service: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceStatus {
    Healthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emoji: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telegram_username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telegram_first_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telegram_last_name: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAttachment {
    pub id: Uuid,
    pub name: String,
    pub size: usize,
    pub content_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateMessage {
    pub id: Uuid,
    pub sender_id: Uuid,
    pub recipient_id: Uuid,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment: Option<FileAttachment>,
    pub sent_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolygonMessage {
    pub id: Uuid,
    pub author_id: Uuid,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment: Option<FileAttachment>,
    pub sent_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredUser {
    #[serde(flatten)]
    pub user: User,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telegram_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelegramCodePurpose {
    #[default]
    Registration,
    Login,
    PasswordReset,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramCode {
    pub code_hash: String,
    pub lookup_hash: String,
    pub telegram_id: i64,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub attempts: u8,
    #[serde(default)]
    pub purpose: TelegramCodePurpose,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoredData {
    #[serde(default)]
    pub users: Vec<StoredUser>,
    #[serde(default)]
    pub messages: Vec<PrivateMessage>,
    #[serde(default)]
    pub polygon_messages: Vec<PolygonMessage>,
    #[serde(default)]
    pub telegram_codes: Vec<TelegramCode>,
    #[serde(default)]
    pub sessions: Vec<StoredSession>,
}

#[derive(Debug, Deserialize)]
pub struct TelegramRegistrationRequest {
    pub code: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct PasswordRegistrationRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct PasswordLoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct TelegramLoginRequest {
    pub username: String,
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct TelegramLoginCodeRequest {
    pub username: String,
}

#[derive(Debug, Deserialize)]
pub struct PasswordResetRequest {
    pub username: String,
    pub code: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct TelegramLoginCodeResponse {
    pub expires_in_seconds: i64,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: User,
}

#[derive(Debug, Serialize)]
pub struct TelegramRegistrationInfo {
    pub bot_username: Option<String>,
    pub bot_url: Option<String>,
    pub code_ttl_seconds: i64,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientEvent {
    SendPrivateMessage { recipient_id: Uuid, text: String },
    SendPolygonMessage { text: String },
    UpdateUserEmoji { emoji: String },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerEvent {
    Ready {
        current_user: User,
        users: Vec<User>,
        messages: Vec<PrivateMessage>,
        polygon_messages: Vec<PolygonMessage>,
    },
    UserRegistered {
        user: User,
    },
    UserUpdated {
        user: User,
    },
    PrivateMessage {
        message: PrivateMessage,
    },
    PolygonMessage {
        message: PolygonMessage,
    },
    SessionRevoked {
        session_id: Uuid,
    },
    Error {
        message: String,
    },
}
