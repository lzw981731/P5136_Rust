//! Launcher authentication protocol (independent of the P5136 game wire).
//!
//! The stock P5136 client never sends or receives these bytes.  The optional
//! launcher (`p5136` GUI connector) opens a short-lived TCP connection to the
//! sidecar port and exchanges a single request/response pair before launching
//! the game.  Registering an account binds an account name, a password, and a
//! rider nickname; logging in validates the credentials and returns the
//! bound nickname together with a short-lived login ticket that the login
//! session subsequently requires.

pub const AUTH_PROTOCOL_VERSION: u16 = 1;
pub const AUTH_MAGIC: [u8; 4] = *b"P5XA";
pub const AUTH_HEADER_LENGTH: usize = 8;
pub const AUTH_MAX_USERNAME_BYTES: usize = 32;
pub const AUTH_MAX_PASSWORD_BYTES: usize = 64;
pub const AUTH_MAX_NICKNAME_BYTES: usize = 128;
pub const AUTH_MAX_MESSAGE_BYTES: usize = 256;
pub const AUTH_MAX_FRAME_BYTES: usize = 512;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOperation {
    Register = 1,
    Login = 2,
}

impl AuthOperation {
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Register),
            2 => Some(Self::Login),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStatus {
    Ok = 0,
    InvalidRequest = 1,
    AccountExists = 2,
    AccountNotFound = 3,
    WrongPassword = 4,
    NicknameTaken = 5,
    RegistrationDisabled = 6,
    NicknameInvalid = 7,
    InternalError = 8,
}

impl AuthStatus {
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Ok,
            1 => Self::InvalidRequest,
            2 => Self::AccountExists,
            3 => Self::AccountNotFound,
            4 => Self::WrongPassword,
            5 => Self::NicknameTaken,
            6 => Self::RegistrationDisabled,
            7 => Self::NicknameInvalid,
            _ => Self::InternalError,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    pub operation: AuthOperation,
    pub username: String,
    pub password: String,
    /// Required for register; ignored for login.
    pub nickname: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResponse {
    pub status: AuthStatus,
    /// Bound nickname echo (login) or provisioned nickname (register).
    pub nickname: String,
    /// Human-readable message (usually empty on success).
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthCodecError {
    FrameTooLong,
    Truncated,
    InvalidVersion,
    InvalidMagic,
    InvalidOperation,
    InvalidUtf8,
    ReservedLengthMismatch,
}

fn append_length_prefixed(output: &mut Vec<u8>, bytes: &[u8]) -> Option<()> {
    let len = u16::try_from(bytes.len()).ok()?;
    output.extend_from_slice(&len.to_le_bytes());
    output.extend_from_slice(bytes);
    Some(())
}

fn read_length_prefixed<'a>(
    input: &'a [u8],
    cursor: &mut usize,
) -> Result<&'a [u8], AuthCodecError> {
    let remaining = input
        .len()
        .checked_sub(*cursor)
        .ok_or(AuthCodecError::Truncated)?;
    if remaining < 2 {
        return Err(AuthCodecError::Truncated);
    }
    let len = usize::from(u16::from_le_bytes(
        input[*cursor..*cursor + 2].try_into().expect("two bytes checked"),
    ));
    *cursor += 2;
    let end = cursor.checked_add(len).ok_or(AuthCodecError::FrameTooLong)?;
    if end > input.len() {
        return Err(AuthCodecError::Truncated);
    }
    let slice = &input[*cursor..end];
    *cursor = end;
    Ok(slice)
}

/// Encodes a launcher auth request frame.
pub fn encode_auth_request(request: &AuthRequest) -> Result<Vec<u8>, AuthCodecError> {
    let username = request.username.as_bytes();
    let password = request.password.as_bytes();
    let nickname = request.nickname.as_bytes();
    if username.is_empty()
        || username.len() > AUTH_MAX_USERNAME_BYTES
        || password.is_empty()
        || password.len() > AUTH_MAX_PASSWORD_BYTES
        || nickname.len() > AUTH_MAX_NICKNAME_BYTES
    {
        return Err(AuthCodecError::FrameTooLong);
    }
    let mut body = Vec::with_capacity(1 + 3 * 2 + username.len() + password.len() + nickname.len());
    body.push(request.operation as u8);
    append_length_prefixed(&mut body, username).ok_or(AuthCodecError::FrameTooLong)?;
    append_length_prefixed(&mut body, password).ok_or(AuthCodecError::FrameTooLong)?;
    append_length_prefixed(&mut body, nickname).ok_or(AuthCodecError::FrameTooLong)?;
    if AUTH_HEADER_LENGTH + body.len() > AUTH_MAX_FRAME_BYTES {
        return Err(AuthCodecError::FrameTooLong);
    }
    let mut output = Vec::with_capacity(AUTH_HEADER_LENGTH + body.len());
    output.extend_from_slice(&AUTH_MAGIC);
    output.extend_from_slice(&AUTH_PROTOCOL_VERSION.to_le_bytes());
    output.extend_from_slice(&u16::try_from(body.len()).expect("bounded body length").to_le_bytes());
    output.extend_from_slice(&body);
    Ok(output)
}

/// Decodes a launcher auth request frame (used by the server side).
pub fn decode_auth_request(frame: &[u8]) -> Result<AuthRequest, AuthCodecError> {
    if frame.len() < AUTH_HEADER_LENGTH {
        return Err(AuthCodecError::Truncated);
    }
    if frame[0..4] != AUTH_MAGIC {
        return Err(AuthCodecError::InvalidMagic);
    }
    if u16::from_le_bytes(frame[4..6].try_into().expect("four bytes checked"))
        != AUTH_PROTOCOL_VERSION
    {
        return Err(AuthCodecError::InvalidVersion);
    }
    let body_len = usize::from(u16::from_le_bytes(frame[6..8].try_into().expect("two bytes checked")));
    let body = frame
        .get(AUTH_HEADER_LENGTH..AUTH_HEADER_LENGTH + body_len)
        .ok_or(AuthCodecError::Truncated)?;
    let mut cursor = 0_usize;
    let operation_byte = *body.first().ok_or(AuthCodecError::Truncated)?;
    let operation = AuthOperation::from_u8(operation_byte).ok_or(AuthCodecError::InvalidOperation)?;
    cursor += 1;
    let username = read_length_prefixed(body, &mut cursor)?;
    let password = read_length_prefixed(body, &mut cursor)?;
    let nickname = read_length_prefixed(body, &mut cursor)?;
    if cursor != body.len() {
        return Err(AuthCodecError::ReservedLengthMismatch);
    }
    let username = std::str::from_utf8(username).map_err(|_| AuthCodecError::InvalidUtf8)?;
    let password = std::str::from_utf8(password).map_err(|_| AuthCodecError::InvalidUtf8)?;
    let nickname = std::str::from_utf8(nickname).map_err(|_| AuthCodecError::InvalidUtf8)?;
    Ok(AuthRequest {
        operation,
        username: username.to_owned(),
        password: password.to_owned(),
        nickname: nickname.to_owned(),
    })
}

/// Encodes a launcher auth response frame.
pub fn encode_auth_response(response: &AuthResponse) -> Result<Vec<u8>, AuthCodecError> {
    let nickname = response.nickname.as_bytes();
    let message = response.message.as_bytes();
    if nickname.len() > AUTH_MAX_NICKNAME_BYTES || message.len() > AUTH_MAX_MESSAGE_BYTES {
        return Err(AuthCodecError::FrameTooLong);
    }
    let mut body = Vec::with_capacity(1 + 2 + nickname.len() + 2 + message.len());
    body.push(response.status as u8);
    append_length_prefixed(&mut body, nickname).ok_or(AuthCodecError::FrameTooLong)?;
    append_length_prefixed(&mut body, message).ok_or(AuthCodecError::FrameTooLong)?;
    if AUTH_HEADER_LENGTH + body.len() > AUTH_MAX_FRAME_BYTES {
        return Err(AuthCodecError::FrameTooLong);
    }
    let mut output = Vec::with_capacity(AUTH_HEADER_LENGTH + body.len());
    output.extend_from_slice(&AUTH_MAGIC);
    output.extend_from_slice(&AUTH_PROTOCOL_VERSION.to_le_bytes());
    output.extend_from_slice(&u16::try_from(body.len()).expect("bounded body length").to_le_bytes());
    output.extend_from_slice(&body);
    Ok(output)
}

/// Decodes a launcher auth response frame (used by the connector side).
pub fn decode_auth_response(frame: &[u8]) -> Result<AuthResponse, AuthCodecError> {
    if frame.len() < AUTH_HEADER_LENGTH {
        return Err(AuthCodecError::Truncated);
    }
    if frame[0..4] != AUTH_MAGIC {
        return Err(AuthCodecError::InvalidMagic);
    }
    if u16::from_le_bytes(frame[4..6].try_into().expect("four bytes checked"))
        != AUTH_PROTOCOL_VERSION
    {
        return Err(AuthCodecError::InvalidVersion);
    }
    let body_len = usize::from(u16::from_le_bytes(frame[6..8].try_into().expect("two bytes checked")));
    let body = frame
        .get(AUTH_HEADER_LENGTH..AUTH_HEADER_LENGTH + body_len)
        .ok_or(AuthCodecError::Truncated)?;
    let mut cursor = 0_usize;
    let status = AuthStatus::from_u8(*body.first().ok_or(AuthCodecError::Truncated)?);
    cursor += 1;
    let nickname = read_length_prefixed(body, &mut cursor)?;
    let message = read_length_prefixed(body, &mut cursor)?;
    if cursor != body.len() {
        return Err(AuthCodecError::ReservedLengthMismatch);
    }
    let nickname = std::str::from_utf8(nickname).map_err(|_| AuthCodecError::InvalidUtf8)?;
    let message = std::str::from_utf8(message).map_err(|_| AuthCodecError::InvalidUtf8)?;
    Ok(AuthResponse {
        status,
        nickname: nickname.to_owned(),
        message: message.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip() {
        let request = AuthRequest {
            operation: AuthOperation::Register,
            username: "alice".to_owned(),
            password: "s3cret".to_owned(),
            nickname: "다오".to_owned(),
        };
        let frame = encode_auth_request(&request).unwrap();
        assert_eq!(&frame[0..4], b"P5XA");
        let decoded = decode_auth_request(&frame).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn response_round_trip() {
        let response = AuthResponse {
            status: AuthStatus::Ok,
            nickname: "다오".to_owned(),
            message: String::new(),
        };
        let frame = encode_auth_response(&response).unwrap();
        assert_eq!(&frame[0..4], b"P5XA");
        let decoded = decode_auth_response(&frame).unwrap();
        assert_eq!(decoded, response);
    }

    #[test]
    fn rejects_bad_magic_and_oversized_body() {
        assert_eq!(
            decode_auth_request(b"XXXX\x01\x00\x04\x00junk").unwrap_err(),
            AuthCodecError::InvalidMagic
        );
        let request = AuthRequest {
            operation: AuthOperation::Register,
            username: "a".repeat(33),
            password: "p".to_owned(),
            nickname: "n".to_owned(),
        };
        assert_eq!(
            encode_auth_request(&request).unwrap_err(),
            AuthCodecError::FrameTooLong
        );
    }
}