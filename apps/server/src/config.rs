use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use crate::error::AppError;

#[derive(Debug, Clone)]
pub struct Config {
    host: IpAddr,
    port: u16,
    data_path: PathBuf,
    jwt_secret: String,
    telegram_code_secret: String,
    telegram_bot_token: Option<String>,
    telegram_bot_username: Option<String>,
    telegram_proxy_url: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, AppError> {
        let host = env::var("MSG_SERVER_HOST")
            .ok()
            .map(|value| value.parse())
            .transpose()
            .map_err(|source| AppError::InvalidConfig {
                key: "MSG_SERVER_HOST",
                source: Box::new(source),
            })?
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));

        let port = env::var("MSG_SERVER_PORT")
            .ok()
            .map(|value| value.parse())
            .transpose()
            .map_err(|source| AppError::InvalidConfig {
                key: "MSG_SERVER_PORT",
                source: Box::new(source),
            })?
            .unwrap_or(8080);

        let data_path = env::var_os("MSG_DATA_PATH")
            .map_or_else(|| PathBuf::from("data/66msg.json"), PathBuf::from);
        let jwt_secret = required_secret("JWT_SECRET")?;
        let telegram_code_secret = required_secret("TELEGRAM_CODE_SECRET")?;
        let telegram_bot_token = optional_nonempty("TELEGRAM_BOT_TOKEN");
        let telegram_bot_username = env::var("TELEGRAM_BOT_USERNAME")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.trim_start_matches('@').to_owned());
        let telegram_proxy_url = optional_nonempty("TELEGRAM_PROXY_URL");

        Ok(Self {
            host,
            port,
            data_path,
            jwt_secret,
            telegram_code_secret,
            telegram_bot_token,
            telegram_bot_username,
            telegram_proxy_url,
        })
    }

    pub const fn socket_address(&self) -> SocketAddr {
        SocketAddr::new(self.host, self.port)
    }

    pub fn data_path(&self) -> &std::path::Path {
        &self.data_path
    }

    pub fn jwt_secret(&self) -> &str {
        &self.jwt_secret
    }

    pub fn telegram_code_secret(&self) -> &str {
        &self.telegram_code_secret
    }

    pub fn telegram_bot_token(&self) -> Option<&str> {
        self.telegram_bot_token.as_deref()
    }

    pub fn telegram_bot_username(&self) -> Option<&str> {
        self.telegram_bot_username.as_deref()
    }

    pub fn telegram_proxy_url(&self) -> Option<&str> {
        self.telegram_proxy_url.as_deref()
    }
}

fn required_secret(key: &'static str) -> Result<String, AppError> {
    let value = env::var(key).map_err(|_| AppError::MissingConfig { key })?;
    if value.len() < 32 {
        return Err(AppError::WeakSecret { key });
    }
    Ok(value)
}

fn optional_nonempty(key: &'static str) -> Option<String> {
    env::var(key).ok().filter(|value| !value.trim().is_empty())
}
