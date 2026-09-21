//! Launcher authentication client.
//!
//! The connector speaks the `P5XA` request/response protocol against the
//! server's sidecar port (login port + 3).  A successful exchange returns the
//! account-bound rider nickname that is then written into the client launcher
//! profile before the game starts.

use std::{
    io::{self, Read, Write},
    net::SocketAddr,
    time::Duration,
};

use p5136_core::auth_protocol::{
    AuthOperation, AuthRequest, AuthStatus, decode_auth_response, encode_auth_request,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LauncherAuthMode {
    Register,
    Login,
}

#[derive(Debug)]
pub enum LauncherAuthError {
    Io(io::Error),
    Timeout,
    Protocol(String),
    Rejected(AuthStatus, String),
}

impl std::fmt::Display for LauncherAuthError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "launcher authentication I/O failure: {error}"),
            Self::Timeout => write!(formatter, "launcher authentication timed out"),
            Self::Protocol(message) => write!(formatter, "launcher authentication protocol error: {message}"),
            Self::Rejected(status, message) => {
                write!(formatter, "launcher authentication rejected ({status:?}): {message}")
            }
        }
    }
}

impl std::error::Error for LauncherAuthError {}

/// Result of a successful launcher authentication exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LauncherAuthOutcome {
    pub nickname: String,
    pub status_message: String,
}

fn auth_response_status_text(status: AuthStatus) -> &'static str {
    match status {
        AuthStatus::Ok => "ok",
        AuthStatus::InvalidRequest => "invalid request",
        AuthStatus::AccountExists => "account already exists",
        AuthStatus::AccountNotFound => "account not found or wrong password",
        AuthStatus::WrongPassword => "wrong password",
        AuthStatus::NicknameTaken => "nickname already taken",
        AuthStatus::RegistrationDisabled => "registration disabled",
        AuthStatus::NicknameInvalid => "invalid nickname",
        AuthStatus::InternalError => "server error",
    }
}

/// Runs one launcher auth exchange against `sidecar_address`.
///
/// The connection is opened, a single request frame is written, exactly one
/// response frame is read, and the connection is dropped.  On `Ok` the
/// account has been accepted and the returned nickname is bound to it.
pub fn run_launcher_auth(
    sidecar_address: SocketAddr,
    mode: LauncherAuthMode,
    username: &str,
    password: &str,
    nickname: &str,
    timeout: Duration,
) -> Result<LauncherAuthOutcome, LauncherAuthError> {
    let operation = match mode {
        LauncherAuthMode::Register => AuthOperation::Register,
        LauncherAuthMode::Login => AuthOperation::Login,
    };
    let request = AuthRequest {
        operation,
        username: username.to_owned(),
        password: password.to_owned(),
        nickname: nickname.to_owned(),
    };
    let frame = encode_auth_request(&request).map_err(|error| {
        LauncherAuthError::Protocol(format!("request encode failed: {error:?}"))
    })?;

    let stream = std::net::TcpStream::connect_timeout(&sidecar_address, timeout)
        .map_err(LauncherAuthError::Io)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(LauncherAuthError::Io)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(LauncherAuthError::Io)?;
    let mut stream = stream;
    stream.write_all(&frame).map_err(LauncherAuthError::Io)?;

    let mut header = [0_u8; 8];
    stream.read_exact(&mut header).map_err(LauncherAuthError::Io)?;
    if &header[0..4] != b"P5XA" {
        return Err(LauncherAuthError::Protocol("unexpected response magic".into()));
    }
    let body_length = usize::from(u16::from_le_bytes([header[6], header[7]]));
    if body_length > 512 {
        return Err(LauncherAuthError::Protocol("response frame too large".into()));
    }
    let mut body = vec![0_u8; body_length];
    stream.read_exact(&mut body).map_err(LauncherAuthError::Io)?;
    let mut response_frame = Vec::with_capacity(8 + body_length);
    response_frame.extend_from_slice(&header);
    response_frame.extend_from_slice(&body);

    let response = decode_auth_response(&response_frame)
        .map_err(|error| LauncherAuthError::Protocol(format!("response decode failed: {error:?}")))?;
    if response.status == AuthStatus::Ok {
        Ok(LauncherAuthOutcome {
            nickname: response.nickname,
            status_message: response.message,
        })
    } else {
        Err(LauncherAuthError::Rejected(
            response.status,
            if response.message.is_empty() {
                auth_response_status_text(response.status).to_owned()
            } else {
                response.message
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_response_status_map_has_no_uncovered_status() {
        let statuses = [
            AuthStatus::Ok,
            AuthStatus::InvalidRequest,
            AuthStatus::AccountExists,
            AuthStatus::AccountNotFound,
            AuthStatus::WrongPassword,
            AuthStatus::NicknameTaken,
            AuthStatus::RegistrationDisabled,
            AuthStatus::NicknameInvalid,
            AuthStatus::InternalError,
        ];
        for status in statuses {
            assert!(!auth_response_status_text(status).is_empty());
        }
    }
}