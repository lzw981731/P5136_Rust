//! Launcher account registry and login-ticket authority.
//!
//! Accounts live in the profile root as `accounts.json`.  Passwords are
//! stored as salted SHA-256 digests.  Successful authentication provisions a
//! short-lived in-memory ticket bound to the account's rider nickname; the
//! login session path requires that ticket before admitting `PqLogin`.

use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};

use p5136_core::nickname::normalize_nickname;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

pub const ACCOUNTS_FILE_NAME: &str = "accounts.json";
pub const TICKET_LIFETIME: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AccountRecord {
    pub username: String,
    pub nickname: String,
    pub password_salt: String,
    pub password_hash: String,
    pub created_unix_seconds: i64,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct AccountsFile {
    pub accounts: Vec<AccountRecord>,
}

#[derive(Debug)]
pub enum AccountError {
    Io(io::Error),
    Json(serde_json::Error),
    UsernameTaken,
    NicknameTaken,
    NicknameInvalid(String),
    UsernameInvalid(String),
    PasswordTooShort,
    RegistrationDisabled,
    InvalidCredentials,
}

impl std::fmt::Display for AccountError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "accounts I/O failure: {error}"),
            Self::Json(error) => write!(formatter, "accounts JSON failure: {error}"),
            Self::UsernameTaken => write!(formatter, "that account name is already registered"),
            Self::NicknameTaken => {
                write!(formatter, "that rider nickname is already bound to an account")
            }
            Self::NicknameInvalid(reason) => write!(formatter, "invalid rider nickname: {reason}"),
            Self::UsernameInvalid(reason) => write!(formatter, "invalid account name: {reason}"),
            Self::PasswordTooShort => write!(formatter, "the password must be at least 6 characters"),
            Self::RegistrationDisabled => write!(formatter, "registration is disabled on this server"),
            Self::InvalidCredentials => write!(formatter, "the account name or password is incorrect"),
        }
    }
}

impl std::error::Error for AccountError {}

impl From<io::Error> for AccountError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for AccountError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

const MIN_PASSWORD_LENGTH: usize = 6;

/// Account table persisted under the profile root, guarded by one process-wide
/// mutex.  The login-session and sidecar auth paths share this coordinator.
#[derive(Clone)]
pub struct AccountStore {
    path: PathBuf,
    state: Arc<tokio::sync::Mutex<AccountsFile>>,
}

impl std::fmt::Debug for AccountStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AccountStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl AccountStore {
    pub async fn open(profile_root: &Path) -> Result<Self, AccountError> {
        tokio::fs::create_dir_all(profile_root).await?;
        let path = profile_root.join(ACCOUNTS_FILE_NAME);
        let accounts = match tokio::fs::read(&path).await {
            Ok(bytes) => serde_json::from_slice::<AccountsFile>(&bytes)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => AccountsFile::default(),
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            path,
            state: Arc::new(Mutex::new(accounts)),
        })
    }

    async fn persist(&self) -> Result<(), AccountError> {
        let state = self.state.lock().await;
        let bytes = serde_json::to_vec_pretty(&*state)?;
        let temporary = self.path.with_extension("json.tmp");
        tokio::fs::write(&temporary, &bytes).await?;
        tokio::fs::rename(&temporary, &self.path).await?;
        Ok(())
    }

    /// Registers a new account.  The nickname is the rider's in-game name and
    /// is bound to the account for the lifetime of the account.
    pub async fn register(
        &self,
        username: &str,
        password: &str,
        nickname: &str,
        registration_enabled: bool,
    ) -> Result<AccountRecord, AccountError> {
        if !registration_enabled {
            return Err(AccountError::RegistrationDisabled);
        }
        let username = validate_username(username)?;
        let nickname = validate_nickname(nickname)?;
        if password.chars().count() < MIN_PASSWORD_LENGTH {
            return Err(AccountError::PasswordTooShort);
        }
        let canonical_username = canonical_username_key(&username);
        let canonical_nickname = canonical_nickname_key(&nickname);
        {
            let state = self.state.lock().await;
            for account in &state.accounts {
                if canonical_username_key(&account.username) == canonical_username {
                    return Err(AccountError::UsernameTaken);
                }
                if canonical_nickname_key(&account.nickname) == canonical_nickname {
                    return Err(AccountError::NicknameTaken);
                }
            }
        }
        let (salt, hash) = hash_password(password);
        let record = AccountRecord {
            username,
            nickname,
            password_salt: salt,
            password_hash: hash,
            created_unix_seconds: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)),
        };
        {
            let mut state = self.state.lock().await;
            state.accounts.push(record.clone());
        }
        self.persist().await?;
        Ok(record)
    }

    /// Looks up an account by (case-folded) account name.
    pub async fn find_by_username(&self, username: &str) -> Option<AccountRecord> {
        let desired = canonical_username_key(username);
        let state = self.state.lock().await;
        state
            .accounts
            .iter()
            .find(|account| canonical_username_key(&account.username) == desired)
            .cloned()
    }

    /// Verifies a login.  Returns the bound account when successful.
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<AccountRecord, AccountError> {
        let account = self
            .find_by_username(username)
            .await
            .ok_or(AccountError::InvalidCredentials)?;
        if !verify_password(password, &account.password_salt, &account.password_hash) {
            return Err(AccountError::InvalidCredentials);
        }
        Ok(account)
    }
}

/// Issued by `authenticate`-success and required by the login session.
#[derive(Debug, Clone)]
pub struct LoginTicket {
    pub nickname: String,
    pub username: String,
    pub issued: Instant,
}

/// In-memory ticket authority.  A successful launcher login provisions a
/// ticket; `handle_login` consumes it by nickname.
#[derive(Debug, Default, Clone)]
pub struct TicketStore {
    tickets: Arc<StdMutex<HashMap<String, LoginTicket>>>,
    allow_remote_profile_creation: bool,
}

impl TicketStore {
    pub fn new() -> Self {
        Self {
            tickets: Arc::new(StdMutex::new(HashMap::new())),
            allow_remote_profile_creation: false,
        }
    }

    /// Mirrors the existing profile-creation escape hatch so existing LAN
    /// workflows (loopback or opted-in) are not regressed by the ticket gate.
    pub fn with_legacy_creation(mut self, enabled: bool) -> Self {
        self.allow_remote_profile_creation = enabled;
        self
    }

    pub fn provision(&self, username: &str, nickname: &str) {
        let key = canonical_nickname_key(nickname);
        let mut tickets = self
            .tickets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tickets.insert(
            key,
            LoginTicket {
                nickname: nickname.to_owned(),
                username: username.to_owned(),
                issued: Instant::now(),
            },
        );
        self.rotate_locked(&mut tickets);
    }

    pub fn consume(&self, nickname: &str) -> Option<LoginTicket> {
        let key = canonical_nickname_key(nickname);
        let mut tickets = self
            .tickets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.rotate_locked(&mut tickets);
        tickets.remove(&key)
    }

    #[cfg(test)]
    pub fn ticket_count(&self) -> usize {
        let mut tickets = self
            .tickets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.rotate_locked(&mut tickets);
        tickets.len()
    }

    fn rotate_locked(&self, tickets: &mut HashMap<String, LoginTicket>) {
        let now = Instant::now();
        tickets.retain(|_, ticket| now.duration_since(ticket.issued) < TICKET_LIFETIME);
    }
}

pub(crate) fn canonical_username_key(input: &str) -> String {
    unicode_casefold(input)
}

pub(crate) fn canonical_nickname_key(input: &str) -> String {
    p5136_core::nickname::canonical_nickname_key(input)
}

fn unicode_casefold(input: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    input.nfkc().collect::<String>().to_lowercase()
}

fn validate_username(input: &str) -> Result<String, AccountError> {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 32 {
        return Err(AccountError::UsernameInvalid(
            "the account name must be 1-32 characters".into(),
        ));
    }
    if trimmed
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(AccountError::UsernameInvalid(
            "the account name cannot contain whitespace".into(),
        ));
    }
    Ok(trimmed.to_owned())
}

fn validate_nickname(input: &str) -> Result<String, AccountError> {
    normalize_nickname(input).map_err(|error| AccountError::NicknameInvalid(error.to_string()))
}

fn hash_password(password: &str) -> (String, String) {
    let salt: String = {
        let mut random = [0_u8; 16];
        for byte in &mut random {
            *byte = rand_byte();
        }
        hex_encode(&random)
    };
    let hash = digest(password, &salt);
    (salt, hash)
}

fn verify_password(password: &str, salt: &str, expected_hash: &str) -> bool {
    let actual = digest(password, salt);
    constant_time_eq(actual.as_bytes(), expected_hash.as_bytes())
}

fn digest(password: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(b"\x00");
    hasher.update(password.as_bytes());
    hex_encode(&hasher.finalize())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn rand_byte() -> u8 {
    // Deterministic-free simple PRNG seeded from time + address entropy.
    // The salt only needs to prevent rainbow tables; the ticket gate is the
    // primary boundary and this private server does not face a live attacker.
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seed = COUNTER.fetch_add(1, Ordering::Relaxed)
        ^ std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos() as u64)
        ^ (std::process::id() as u64)
            .rotate_left(21)
        ^ (std::time::Instant::now().elapsed().as_nanos() as u64).rotate_left(7);
    let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    state ^= state >> 33;
    (state >> 24) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn register_and_authenticate_round_trip() {
        let root = tempfile::tempdir().unwrap();
        let store = AccountStore::open(root.path()).await.unwrap();
        store
            .register("Alice", "hunter2!", "다오", true)
            .await
            .unwrap();
        let account = store.authenticate("alice", "hunter2!").await.unwrap();
        assert_eq!(account.nickname, "다오");
        assert!(store.authenticate("alice", "wrong").await.is_err());
        assert!(store
            .register("Bob", "secret", "다오", true)
            .await
            .is_err());
        // Duplicate account name rejected.
        assert!(store
            .register("ALICE", "xpassword", "Batman", true)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn registration_can_be_disabled() {
        let root = tempfile::tempdir().unwrap();
        let store = AccountStore::open(root.path()).await.unwrap();
        assert!(store
            .register("Carol", "password", "RiderA", false)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn ticket_is_consumed_exactly_once() {
        let tickets = TicketStore::new();
        tickets.provision("alice", "다오");
        assert_eq!(tickets.ticket_count(), 1);
        assert!(tickets.consume("다오").is_some());
        assert_eq!(tickets.ticket_count(), 0);
        assert!(tickets.consume("다오").is_none());
    }
}