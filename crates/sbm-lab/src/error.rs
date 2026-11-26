use std::io;
use std::path::PathBuf;

/// Recoverable laboratory failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Message(String),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("toml: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("{path}: {source}")]
    Path { path: PathBuf, source: io::Error },
}

impl Error {
    pub fn message(text: impl Into<String>) -> Self {
        Self::Message(text.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
