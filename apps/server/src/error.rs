use std::{error::Error as StdError, io};

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("missing required environment variable {key}")]
    MissingConfig { key: &'static str },
    #[error("{key} must contain at least 32 characters")]
    WeakSecret { key: &'static str },
    #[error("invalid configuration value for {key}: {source}")]
    InvalidConfig {
        key: &'static str,
        source: Box<dyn StdError + Send + Sync>,
    },
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("data file contains invalid JSON: {0}")]
    InvalidData(#[from] serde_json::Error),
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    code: &'static str,
    message: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::MissingConfig { .. }
            | Self::WeakSecret { .. }
            | Self::InvalidConfig { .. }
            | Self::Io(_)
            | Self::InvalidData(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = ErrorResponse {
            code: "internal_error",
            message: self.to_string(),
        };

        (status, Json(body)).into_response()
    }
}
