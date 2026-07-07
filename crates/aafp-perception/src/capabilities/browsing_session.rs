//! Stateful browsing sessions (Track Y8).
//!
//! Maintains state across multiple web requests for a single browsing
//! context: cookies, local storage, navigation history (with back/forward),
//! and per-session timeouts. A [`SessionManager`] tracks multiple concurrent
//! sessions and evicts expired ones.
//!
//! This capability complements [`super::web_browse`] by providing the
//! *stateful* layer that real browsers maintain between page loads.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
use std::sync::Arc;
use std::sync::RwLock;

use sha2::{Digest, Sha256};

use super::Clock;
use crate::PerceptionError;

// ---------------------------------------------------------------------------
// SessionId
// ---------------------------------------------------------------------------

/// A unique 32-byte identifier for a browsing session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; 32]);

impl SessionId {
    /// Create a session ID from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the inner byte array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Hex-encode the session ID for logging.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Generate a deterministic-but-unique session ID from a timestamp and
/// counter. Uses SHA-256 so that IDs are uniformly distributed and hard
/// to guess.
fn generate_session_id(timestamp_ms: u64, counter: u64) -> SessionId {
    let mut hasher = Sha256::new();
    hasher.update(timestamp_ms.to_be_bytes());
    hasher.update(counter.to_be_bytes());
    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    SessionId(id)
}

// ---------------------------------------------------------------------------
// SessionConfig
// ---------------------------------------------------------------------------

/// Configuration for the browsing-session manager.
#[derive(Clone, Debug)]
pub struct SessionConfig {
    /// Session inactivity timeout in milliseconds. A session that has not
    /// been active for this duration is considered expired.
    pub timeout_ms: u64,
    /// Maximum number of history entries per session. Older entries are
    /// evicted from the front when this limit is exceeded.
    pub max_history: usize,
    /// Maximum number of concurrent sessions. When this limit is reached,
    /// `create_session` evicts expired sessions first, then refuses if
    /// still at capacity.
    pub max_sessions: usize,
    /// Default user-agent string for new sessions.
    pub default_user_agent: String,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 30 * 60 * 1000, // 30 minutes
            max_history: 100,
            max_sessions: 64,
            default_user_agent: "AAFP-Agent/0.1".into(),
        }
    }
}

// ---------------------------------------------------------------------------
// BrowsingSession
// ---------------------------------------------------------------------------

/// A single stateful browsing session.
///
/// Maintains cookies, local storage, and navigation history (with
/// back/forward support) across multiple web requests.
#[derive(Clone, Debug)]
pub struct BrowsingSession {
    /// Unique session identifier.
    pub id: SessionId,
    /// Cookie jar: cookie name → cookie value.
    cookies: HashMap<String, String>,
    /// Local storage: key → value.
    local_storage: HashMap<String, String>,
    /// Full navigation history (all visited URLs, oldest first).
    history: Vec<String>,
    /// Index into `history` for the current position (0-based).
    /// `None` when no navigation has occurred yet.
    history_index: Option<usize>,
    /// The current URL (mirrors `history[history_index]` for convenience).
    current_url: Option<String>,
    /// User-agent string sent with requests in this session.
    pub user_agent: String,
    /// Unix-millisecond timestamp when the session was created.
    pub created_at: u64,
    /// Unix-millisecond timestamp of the last activity.
    pub last_active_at: u64,
    /// Inactivity timeout in milliseconds.
    session_timeout_ms: u64,
    /// Maximum history entries before front-eviction.
    max_history: usize,
}

impl BrowsingSession {
    /// Create a new browsing session with the given ID and config.
    fn new(id: SessionId, config: &SessionConfig, now_ms: u64) -> Self {
        Self {
            id,
            cookies: HashMap::new(),
            local_storage: HashMap::new(),
            history: Vec::new(),
            history_index: None,
            current_url: None,
            user_agent: config.default_user_agent.clone(),
            created_at: now_ms,
            last_active_at: now_ms,
            session_timeout_ms: config.timeout_ms,
            max_history: config.max_history,
        }
    }

    /// Create a session with explicit parameters (for testing).
    pub fn with_params(
        id: SessionId,
        user_agent: String,
        now_ms: u64,
        timeout_ms: u64,
        max_history: usize,
    ) -> Self {
        Self {
            id,
            cookies: HashMap::new(),
            local_storage: HashMap::new(),
            history: Vec::new(),
            history_index: None,
            current_url: None,
            user_agent,
            created_at: now_ms,
            last_active_at: now_ms,
            session_timeout_ms: timeout_ms,
            max_history,
        }
    }

    /// Navigate to a URL. Updates history (truncating any forward entries)
    /// and sets the current URL. Returns the new current URL.
    pub fn navigate(&mut self, url: &str, now_ms: u64) -> Result<String, PerceptionError> {
        if url.is_empty() {
            return Err(PerceptionError::InvalidField {
                field: "url",
                message: "url must not be empty".into(),
            });
        }

        // Truncate forward history if we are not at the end.
        if let Some(idx) = self.history_index {
            self.history.truncate(idx + 1);
        }

        // Append the new URL.
        self.history.push(url.to_string());

        // Evict from the front if history exceeds the limit.
        if self.history.len() > self.max_history {
            let excess = self.history.len() - self.max_history;
            self.history.drain(0..excess);
        }

        // The current position is always the last entry after a new navigation.
        let final_idx = self.history.len() - 1;
        self.history_index = Some(final_idx);
        self.current_url = Some(url.to_string());
        self.last_active_at = now_ms;

        Ok(url.to_string())
    }

    /// Navigate back in history. Returns the new current URL, or `None`
    /// if there is no page to go back to.
    pub fn back(&mut self, now_ms: u64) -> Option<String> {
        let idx = self.history_index?;
        if idx == 0 {
            return None; // Already at the earliest page.
        }
        let new_idx = idx - 1;
        self.history_index = Some(new_idx);
        self.current_url = self.history.get(new_idx).cloned();
        self.last_active_at = now_ms;
        self.current_url.clone()
    }

    /// Navigate forward in history. Returns the new current URL, or `None`
    /// if there is no page to go forward to.
    pub fn forward(&mut self, now_ms: u64) -> Option<String> {
        let idx = self.history_index?;
        let new_idx = idx + 1;
        if new_idx >= self.history.len() {
            return None; // Already at the latest page.
        }
        self.history_index = Some(new_idx);
        self.current_url = self.history.get(new_idx).cloned();
        self.last_active_at = now_ms;
        self.current_url.clone()
    }

    /// Return whether `back()` would succeed (i.e., there is a previous
    /// page in history).
    pub fn can_go_back(&self) -> bool {
        match self.history_index {
            Some(idx) => idx > 0,
            None => false,
        }
    }

    /// Return whether `forward()` would succeed (i.e., there is a next
    /// page in history).
    pub fn can_go_forward(&self) -> bool {
        match self.history_index {
            Some(idx) => idx + 1 < self.history.len(),
            None => false,
        }
    }

    /// Get a cookie value by name.
    pub fn get_cookie(&self, name: &str) -> Option<&str> {
        self.cookies.get(name).map(|s| s.as_str())
    }

    /// Set a cookie. Overwrites any existing value with the same name.
    pub fn set_cookie(&mut self, name: &str, value: &str, now_ms: u64) {
        self.cookies.insert(name.to_string(), value.to_string());
        self.last_active_at = now_ms;
    }

    /// Remove a cookie. Returns the previous value if present.
    pub fn remove_cookie(&mut self, name: &str) -> Option<String> {
        self.cookies.remove(name)
    }

    /// Get all cookies as a map.
    pub fn get_cookies(&self) -> &HashMap<String, String> {
        &self.cookies
    }

    /// Get a local-storage value by key.
    pub fn get_local_storage(&self, key: &str) -> Option<&str> {
        self.local_storage.get(key).map(|s| s.as_str())
    }

    /// Set a local-storage value. Overwrites any existing value.
    pub fn set_local_storage(&mut self, key: &str, value: &str, now_ms: u64) {
        self.local_storage
            .insert(key.to_string(), value.to_string());
        self.last_active_at = now_ms;
    }

    /// Remove a local-storage value. Returns the previous value if present.
    pub fn remove_local_storage(&mut self, key: &str) -> Option<String> {
        self.local_storage.remove(key)
    }

    /// Get all local-storage entries as a map.
    pub fn get_local_storage_map(&self) -> &HashMap<String, String> {
        &self.local_storage
    }

    /// Return the current URL, or `None` if no navigation has occurred.
    pub fn current_url(&self) -> Option<&str> {
        self.current_url.as_deref()
    }

    /// Return the full navigation history (oldest first).
    pub fn history(&self) -> &[String] {
        &self.history
    }

    /// Return the current history index (0-based), or `None` if no
    /// navigation has occurred.
    pub fn history_index(&self) -> Option<usize> {
        self.history_index
    }

    /// Check if this session has expired based on inactivity timeout.
    /// Uses the provided `now_ms` timestamp.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.last_active_at) >= self.session_timeout_ms
    }

    /// Touch the session to update `last_active_at`.
    pub fn touch(&mut self, now_ms: u64) {
        self.last_active_at = now_ms;
    }

    /// Clear all session state (cookies, local storage, history).
    pub fn clear(&mut self) {
        self.cookies.clear();
        self.local_storage.clear();
        self.history.clear();
        self.history_index = None;
        self.current_url = None;
    }
}

// ---------------------------------------------------------------------------
// SessionManager
// ---------------------------------------------------------------------------

/// Manages multiple concurrent browsing sessions with timeout-based
/// eviction.
pub struct SessionManager {
    sessions: RwLock<HashMap<SessionId, BrowsingSession>>,
    config: SessionConfig,
    clock: Clock,
    counter: AtomicU64,
}

impl SessionManager {
    /// Create a new session manager with the default system clock.
    pub fn new(config: SessionConfig) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            config,
            clock: super::default_clock(),
            counter: AtomicU64::new(0),
        }
    }

    /// Create a new session manager with an injected clock (for testing).
    pub fn with_clock(config: SessionConfig, clock: Clock) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            config,
            clock,
            counter: AtomicU64::new(0),
        }
    }

    /// Return a reference to the manager's configuration.
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Create a new browsing session. Returns the session ID.
    ///
    /// If the number of active sessions is at capacity, expired sessions
    /// are evicted first. If still at capacity, an error is returned.
    pub fn create_session(&self) -> Result<SessionId, PerceptionError> {
        let now_ms = (self.clock)();
        self.cleanup_expired_at(now_ms);

        {
            let sessions = self.sessions.read().expect("sessions lock poisoned");
            if sessions.len() >= self.config.max_sessions {
                return Err(PerceptionError::InvalidField {
                    field: "session",
                    message: format!("max sessions ({}) exceeded", self.config.max_sessions),
                });
            }
        }

        let counter = self.counter.fetch_add(1, Ordering::SeqCst);
        let id = generate_session_id(now_ms, counter);
        let session = BrowsingSession::new(id, &self.config, now_ms);

        let mut sessions = self.sessions.write().expect("sessions lock poisoned");
        sessions.insert(id, session);
        Ok(id)
    }

    /// Retrieve a clone of a session by ID.
    pub fn get_session(&self, id: &SessionId) -> Option<BrowsingSession> {
        let sessions = self.sessions.read().expect("sessions lock poisoned");
        sessions.get(id).cloned()
    }

    /// Close and remove a session by ID. Returns `true` if the session
    /// existed.
    pub fn close_session(&self, id: &SessionId) -> bool {
        let mut sessions = self.sessions.write().expect("sessions lock poisoned");
        sessions.remove(id).is_some()
    }

    /// Navigate a session to a URL. Updates history and last-active time.
    pub fn navigate(&self, id: &SessionId, url: &str) -> Result<String, PerceptionError> {
        let now_ms = (self.clock)();
        let mut sessions = self.sessions.write().expect("sessions lock poisoned");
        let session = sessions
            .get_mut(id)
            .ok_or_else(|| PerceptionError::NotFound(format!("session: {}", id)))?;
        if session.is_expired(now_ms) {
            return Err(PerceptionError::Timeout);
        }
        session.navigate(url, now_ms)
    }

    /// Get a cookie from a session.
    pub fn get_cookie(&self, id: &SessionId, name: &str) -> Option<String> {
        let sessions = self.sessions.read().expect("sessions lock poisoned");
        sessions
            .get(id)
            .and_then(|s| s.get_cookie(name).map(|s| s.to_string()))
    }

    /// Set a cookie on a session.
    pub fn set_cookie(
        &self,
        id: &SessionId,
        name: &str,
        value: &str,
    ) -> Result<(), PerceptionError> {
        let now_ms = (self.clock)();
        let mut sessions = self.sessions.write().expect("sessions lock poisoned");
        let session = sessions
            .get_mut(id)
            .ok_or_else(|| PerceptionError::NotFound(format!("session: {}", id)))?;
        if session.is_expired(now_ms) {
            return Err(PerceptionError::Timeout);
        }
        session.set_cookie(name, value, now_ms);
        Ok(())
    }

    /// Get a local-storage value from a session.
    pub fn get_local_storage(&self, id: &SessionId, key: &str) -> Option<String> {
        let sessions = self.sessions.read().expect("sessions lock poisoned");
        sessions
            .get(id)
            .and_then(|s| s.get_local_storage(key).map(|s| s.to_string()))
    }

    /// Set a local-storage value on a session.
    pub fn set_local_storage(
        &self,
        id: &SessionId,
        key: &str,
        value: &str,
    ) -> Result<(), PerceptionError> {
        let now_ms = (self.clock)();
        let mut sessions = self.sessions.write().expect("sessions lock poisoned");
        let session = sessions
            .get_mut(id)
            .ok_or_else(|| PerceptionError::NotFound(format!("session: {}", id)))?;
        if session.is_expired(now_ms) {
            return Err(PerceptionError::Timeout);
        }
        session.set_local_storage(key, value, now_ms);
        Ok(())
    }

    /// Navigate back in a session's history.
    pub fn back(&self, id: &SessionId) -> Result<Option<String>, PerceptionError> {
        let now_ms = (self.clock)();
        let mut sessions = self.sessions.write().expect("sessions lock poisoned");
        let session = sessions
            .get_mut(id)
            .ok_or_else(|| PerceptionError::NotFound(format!("session: {}", id)))?;
        if session.is_expired(now_ms) {
            return Err(PerceptionError::Timeout);
        }
        Ok(session.back(now_ms))
    }

    /// Navigate forward in a session's history.
    pub fn forward(&self, id: &SessionId) -> Result<Option<String>, PerceptionError> {
        let now_ms = (self.clock)();
        let mut sessions = self.sessions.write().expect("sessions lock poisoned");
        let session = sessions
            .get_mut(id)
            .ok_or_else(|| PerceptionError::NotFound(format!("session: {}", id)))?;
        if session.is_expired(now_ms) {
            return Err(PerceptionError::Timeout);
        }
        Ok(session.forward(now_ms))
    }

    /// Check if a session has expired.
    pub fn is_expired(&self, id: &SessionId) -> Result<bool, PerceptionError> {
        let now_ms = (self.clock)();
        let sessions = self.sessions.read().expect("sessions lock poisoned");
        let session = sessions
            .get(id)
            .ok_or_else(|| PerceptionError::NotFound(format!("session: {}", id)))?;
        Ok(session.is_expired(now_ms))
    }

    /// Return the number of active sessions.
    pub fn session_count(&self) -> usize {
        let sessions = self.sessions.read().expect("sessions lock poisoned");
        sessions.len()
    }

    /// Remove all expired sessions. Uses the manager's clock.
    pub fn cleanup_expired(&self) {
        let now_ms = (self.clock)();
        self.cleanup_expired_at(now_ms);
    }

    /// Remove all expired sessions using the given timestamp.
    fn cleanup_expired_at(&self, now_ms: u64) {
        let mut sessions = self.sessions.write().expect("sessions lock poisoned");
        sessions.retain(|_, s| !s.is_expired(now_ms));
    }

    /// Return all active session IDs.
    pub fn session_ids(&self) -> Vec<SessionId> {
        let sessions = self.sessions.read().expect("sessions lock poisoned");
        sessions.keys().copied().collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn mock_clock() -> (Clock, Arc<AtomicU64>) {
        let cell = Arc::new(AtomicU64::new(1_700_000_000_000));
        let cell2 = Arc::clone(&cell);
        let clock: Clock = Arc::new(move || cell2.load(Ordering::SeqCst));
        (clock, cell)
    }

    fn test_config() -> SessionConfig {
        SessionConfig {
            timeout_ms: 60_000,
            max_history: 10,
            max_sessions: 5,
            default_user_agent: "TestAgent/1.0".into(),
        }
    }

    // 1. SessionId creation and hex encoding
    #[test]
    fn test_session_id_from_bytes() {
        let bytes = [42u8; 32];
        let id = SessionId::from_bytes(bytes);
        assert_eq!(id.as_bytes(), &[42u8; 32]);
        assert_eq!(id.to_hex(), hex::encode(bytes));
    }

    // 2. SessionId equality and hashing
    #[test]
    fn test_session_id_equality() {
        let a = SessionId([1; 32]);
        let b = SessionId([1; 32]);
        let c = SessionId([2; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // 3. SessionId display
    #[test]
    fn test_session_id_display() {
        let id = SessionId([0xab; 32]);
        let s = format!("{}", id);
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // 4. Create a session via SessionManager
    #[test]
    fn test_create_session() {
        let (clock, _) = mock_clock();
        let mgr = SessionManager::with_clock(test_config(), clock);
        let id = mgr.create_session().expect("create");
        assert!(mgr.get_session(&id).is_some());
        assert_eq!(mgr.session_count(), 1);
    }

    // 5. Get a session that does not exist
    #[test]
    fn test_get_session_not_found() {
        let (clock, _) = mock_clock();
        let mgr = SessionManager::with_clock(test_config(), clock);
        let fake_id = SessionId([99; 32]);
        assert!(mgr.get_session(&fake_id).is_none());
    }

    // 6. Close a session
    #[test]
    fn test_close_session() {
        let (clock, _) = mock_clock();
        let mgr = SessionManager::with_clock(test_config(), clock);
        let id = mgr.create_session().expect("create");
        assert!(mgr.close_session(&id));
        assert!(mgr.get_session(&id).is_none());
        assert_eq!(mgr.session_count(), 0);
    }

    // 7. Close a non-existent session
    #[test]
    fn test_close_session_not_found() {
        let (clock, _) = mock_clock();
        let mgr = SessionManager::with_clock(test_config(), clock);
        let fake_id = SessionId([99; 32]);
        assert!(!mgr.close_session(&fake_id));
    }

    // 8. Navigate updates history and current_url
    #[test]
    fn test_navigate_updates_history() {
        let (clock, _) = mock_clock();
        let mgr = SessionManager::with_clock(test_config(), clock);
        let id = mgr.create_session().expect("create");
        mgr.navigate(&id, "https://example.com/page1")
            .expect("navigate");
        let session = mgr.get_session(&id).expect("session");
        assert_eq!(session.current_url(), Some("https://example.com/page1"));
        assert_eq!(session.history().len(), 1);
        assert_eq!(session.history_index(), Some(0));
    }

    // 9. Navigate to empty URL fails
    #[test]
    fn test_navigate_empty_url_fails() {
        let (clock, _) = mock_clock();
        let mgr = SessionManager::with_clock(test_config(), clock);
        let id = mgr.create_session().expect("create");
        let err = mgr.navigate(&id, "").unwrap_err();
        assert!(matches!(
            err,
            PerceptionError::InvalidField { field: "url", .. }
        ));
    }

    // 10. Navigate to non-existent session fails
    #[test]
    fn test_navigate_session_not_found() {
        let (clock, _) = mock_clock();
        let mgr = SessionManager::with_clock(test_config(), clock);
        let fake_id = SessionId([99; 32]);
        let err = mgr.navigate(&fake_id, "https://example.com").unwrap_err();
        assert!(matches!(err, PerceptionError::NotFound(_)));
    }

    // 11. Back and forward navigation
    #[test]
    fn test_back_forward_navigation() {
        let (clock, _) = mock_clock();
        let mgr = SessionManager::with_clock(test_config(), clock);
        let id = mgr.create_session().expect("create");
        mgr.navigate(&id, "https://a.com").expect("nav1");
        mgr.navigate(&id, "https://b.com").expect("nav2");
        mgr.navigate(&id, "https://c.com").expect("nav3");

        // Currently at c.com
        let session = mgr.get_session(&id).expect("session");
        assert_eq!(session.current_url(), Some("https://c.com"));

        // Go back to b.com
        let back_url = mgr.back(&id).expect("back").expect("some url");
        assert_eq!(back_url, "https://b.com");

        // Go back to a.com
        let back_url = mgr.back(&id).expect("back").expect("some url");
        assert_eq!(back_url, "https://a.com");

        // Can't go back further
        let result = mgr.back(&id).expect("back ok");
        assert!(result.is_none());

        // Go forward to b.com
        let fwd_url = mgr.forward(&id).expect("forward").expect("some url");
        assert_eq!(fwd_url, "https://b.com");
    }

    // 12. Navigate after back truncates forward history
    #[test]
    fn test_navigate_after_back_truncates() {
        let (clock, _) = mock_clock();
        let mgr = SessionManager::with_clock(test_config(), clock);
        let id = mgr.create_session().expect("create");
        mgr.navigate(&id, "https://a.com").expect("nav1");
        mgr.navigate(&id, "https://b.com").expect("nav2");
        mgr.navigate(&id, "https://c.com").expect("nav3");

        // Back to b.com
        mgr.back(&id).expect("back");

        // Navigate to d.com — should truncate c.com
        mgr.navigate(&id, "https://d.com").expect("nav4");

        let session = mgr.get_session(&id).expect("session");
        assert_eq!(session.history().len(), 3); // a, b, d
        assert_eq!(session.current_url(), Some("https://d.com"));
        assert!(!session.can_go_forward());
    }

    // 13. can_go_back / can_go_forward
    #[test]
    fn test_can_go_back_forward() {
        let (clock, _) = mock_clock();
        let mgr = SessionManager::with_clock(test_config(), clock);
        let id = mgr.create_session().expect("create");

        // No navigation yet
        let session = mgr.get_session(&id).expect("session");
        assert!(!session.can_go_back());
        assert!(!session.can_go_forward());

        mgr.navigate(&id, "https://a.com").expect("nav1");
        let session = mgr.get_session(&id).expect("session");
        assert!(!session.can_go_back());
        assert!(!session.can_go_forward());

        mgr.navigate(&id, "https://b.com").expect("nav2");
        let session = mgr.get_session(&id).expect("session");
        assert!(session.can_go_back());
        assert!(!session.can_go_forward());
    }

    // 14. Cookie management via SessionManager
    #[test]
    fn test_cookie_management_via_manager() {
        let (clock, _) = mock_clock();
        let mgr = SessionManager::with_clock(test_config(), clock);
        let id = mgr.create_session().expect("create");
        mgr.set_cookie(&id, "session_id", "abc123").expect("set");
        assert_eq!(
            mgr.get_cookie(&id, "session_id"),
            Some("abc123".to_string())
        );
        assert_eq!(mgr.get_cookie(&id, "nonexistent"), None);
    }

    // 15. Cookie management directly on BrowsingSession
    #[test]
    fn test_cookie_management_direct() {
        let id = SessionId([1; 32]);
        let mut session = BrowsingSession::with_params(id, "TestAgent".into(), 1000, 60_000, 10);
        session.set_cookie("token", "xyz", 2000);
        assert_eq!(session.get_cookie("token"), Some("xyz"));
        assert_eq!(session.get_cookie("missing"), None);
        let removed = session.remove_cookie("token");
        assert_eq!(removed, Some("xyz".to_string()));
        assert_eq!(session.get_cookie("token"), None);
    }

    // 16. Local storage management via SessionManager
    #[test]
    fn test_local_storage_via_manager() {
        let (clock, _) = mock_clock();
        let mgr = SessionManager::with_clock(test_config(), clock);
        let id = mgr.create_session().expect("create");
        mgr.set_local_storage(&id, "theme", "dark").expect("set");
        assert_eq!(
            mgr.get_local_storage(&id, "theme"),
            Some("dark".to_string())
        );
        assert_eq!(mgr.get_local_storage(&id, "missing"), None);
    }

    // 17. Local storage management directly on BrowsingSession
    #[test]
    fn test_local_storage_direct() {
        let id = SessionId([2; 32]);
        let mut session = BrowsingSession::with_params(id, "TestAgent".into(), 1000, 60_000, 10);
        session.set_local_storage("key", "value", 2000);
        assert_eq!(session.get_local_storage("key"), Some("value"));
        let removed = session.remove_local_storage("key");
        assert_eq!(removed, Some("value".to_string()));
        assert_eq!(session.get_local_storage("key"), None);
    }

    // 18. Session expiration
    #[test]
    fn test_session_expired() {
        let (clock, cell) = mock_clock();
        let mgr = SessionManager::with_clock(test_config(), clock);
        let id = mgr.create_session().expect("create");

        // Not expired initially
        assert!(!mgr.is_expired(&id).expect("check"));

        // Advance past timeout
        cell.store(1_700_000_000_000 + 60_001, Ordering::SeqCst);
        assert!(mgr.is_expired(&id).expect("check"));
    }

    // 19. Cleanup expired sessions
    #[test]
    fn test_cleanup_expired() {
        let (clock, cell) = mock_clock();
        let mgr = SessionManager::with_clock(test_config(), clock);
        let id1 = mgr.create_session().expect("create1");
        let _id2 = mgr.create_session().expect("create2");
        assert_eq!(mgr.session_count(), 2);

        // Advance past timeout
        cell.store(1_700_000_000_000 + 60_001, Ordering::SeqCst);
        mgr.cleanup_expired();
        assert_eq!(mgr.session_count(), 0);
        assert!(mgr.get_session(&id1).is_none());
    }

    // 20. Expired session refuses navigation
    #[test]
    fn test_navigate_expired_session() {
        let (clock, cell) = mock_clock();
        let mgr = SessionManager::with_clock(test_config(), clock);
        let id = mgr.create_session().expect("create");
        cell.store(1_700_000_000_000 + 60_001, Ordering::SeqCst);
        let err = mgr.navigate(&id, "https://example.com").unwrap_err();
        assert!(matches!(err, PerceptionError::Timeout));
    }

    // 21. Max sessions limit
    #[test]
    fn test_max_sessions_limit() {
        let (clock, _) = mock_clock();
        let config = SessionConfig {
            timeout_ms: 60_000,
            max_history: 10,
            max_sessions: 2,
            default_user_agent: "Test".into(),
        };
        let mgr = SessionManager::with_clock(config, clock);
        let _id1 = mgr.create_session().expect("create1");
        let _id2 = mgr.create_session().expect("create2");
        let err = mgr.create_session().unwrap_err();
        assert!(matches!(
            err,
            PerceptionError::InvalidField {
                field: "session",
                ..
            }
        ));
    }

    // 22. Creating a session after cleanup succeeds
    #[test]
    fn test_create_after_cleanup() {
        let (clock, cell) = mock_clock();
        let config = SessionConfig {
            timeout_ms: 60_000,
            max_history: 10,
            max_sessions: 1,
            default_user_agent: "Test".into(),
        };
        let mgr = SessionManager::with_clock(config, clock);
        let _id1 = mgr.create_session().expect("create1");
        // At capacity
        assert!(mgr.create_session().is_err());
        // Expire the session
        cell.store(1_700_000_000_000 + 60_001, Ordering::SeqCst);
        // create_session evicts expired first
        let _id2 = mgr.create_session().expect("create after cleanup");
        assert_eq!(mgr.session_count(), 1);
    }

    // 23. History eviction when max_history is exceeded
    #[test]
    fn test_history_eviction() {
        let (clock, _) = mock_clock();
        let config = SessionConfig {
            timeout_ms: 60_000,
            max_history: 3,
            max_sessions: 5,
            default_user_agent: "Test".into(),
        };
        let mgr = SessionManager::with_clock(config, clock);
        let id = mgr.create_session().expect("create");
        mgr.navigate(&id, "https://a.com").expect("nav");
        mgr.navigate(&id, "https://b.com").expect("nav");
        mgr.navigate(&id, "https://c.com").expect("nav");
        mgr.navigate(&id, "https://d.com").expect("nav");

        let session = mgr.get_session(&id).expect("session");
        assert_eq!(session.history().len(), 3); // max_history = 3
                                                // The oldest entry (a.com) should have been evicted.
        assert!(!session.history().contains(&"https://a.com".to_string()));
        assert!(session.history().contains(&"https://d.com".to_string()));
    }

    // 24. Session IDs listing
    #[test]
    fn test_session_ids() {
        let (clock, _) = mock_clock();
        let mgr = SessionManager::with_clock(test_config(), clock);
        let id1 = mgr.create_session().expect("create1");
        let id2 = mgr.create_session().expect("create2");
        let ids = mgr.session_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
    }

    // 25. Clear session state
    #[test]
    fn test_clear_session() {
        let id = SessionId([5; 32]);
        let mut session = BrowsingSession::with_params(id, "TestAgent".into(), 1000, 60_000, 10);
        session.set_cookie("a", "b", 1000);
        session.set_local_storage("x", "y", 1000);
        session.navigate("https://example.com", 1000).expect("nav");
        session.clear();
        assert_eq!(session.get_cookie("a"), None);
        assert_eq!(session.get_local_storage("x"), None);
        assert_eq!(session.current_url(), None);
        assert!(session.history().is_empty());
    }

    // 26. Touch updates last_active_at
    #[test]
    fn test_touch_session() {
        let id = SessionId([6; 32]);
        let mut session = BrowsingSession::with_params(id, "TestAgent".into(), 1000, 60_000, 10);
        assert_eq!(session.last_active_at, 1000);
        session.touch(5000);
        assert_eq!(session.last_active_at, 5000);
        assert!(!session.is_expired(5000));
        assert!(session.is_expired(5000 + 60_001));
    }

    // 27. User agent is set from config
    #[test]
    fn test_user_agent_from_config() {
        let (clock, _) = mock_clock();
        let mgr = SessionManager::with_clock(test_config(), clock);
        let id = mgr.create_session().expect("create");
        let session = mgr.get_session(&id).expect("session");
        assert_eq!(session.user_agent, "TestAgent/1.0");
    }

    // 28. Generate session ID uniqueness
    #[test]
    fn test_session_id_uniqueness() {
        let id1 = generate_session_id(1000, 1);
        let id2 = generate_session_id(1000, 2);
        let id3 = generate_session_id(1001, 1);
        assert_ne!(id1, id2);
        assert_ne!(id1, id3);
        assert_ne!(id2, id3);
    }

    // 29. Multiple sessions are independent
    #[test]
    fn test_session_independence() {
        let (clock, _) = mock_clock();
        let mgr = SessionManager::with_clock(test_config(), clock);
        let id1 = mgr.create_session().expect("create1");
        let id2 = mgr.create_session().expect("create2");
        mgr.set_cookie(&id1, "shared", "value1").expect("set");
        mgr.set_cookie(&id2, "shared", "value2").expect("set");
        assert_eq!(mgr.get_cookie(&id1, "shared"), Some("value1".to_string()));
        assert_eq!(mgr.get_cookie(&id2, "shared"), Some("value2".to_string()));
    }

    // 30. Forward at the end of history returns None
    #[test]
    fn test_forward_at_end() {
        let (clock, _) = mock_clock();
        let mgr = SessionManager::with_clock(test_config(), clock);
        let id = mgr.create_session().expect("create");
        mgr.navigate(&id, "https://a.com").expect("nav");
        let result = mgr.forward(&id).expect("forward ok");
        assert!(result.is_none());
    }

    // 31. Back on a single-page session returns None
    #[test]
    fn test_back_single_page() {
        let (clock, _) = mock_clock();
        let mgr = SessionManager::with_clock(test_config(), clock);
        let id = mgr.create_session().expect("create");
        mgr.navigate(&id, "https://a.com").expect("nav");
        let result = mgr.back(&id).expect("back ok");
        assert!(result.is_none());
    }

    // 32. Get cookies and local storage maps
    #[test]
    fn test_get_cookies_and_storage_maps() {
        let id = SessionId([7; 32]);
        let mut session = BrowsingSession::with_params(id, "TestAgent".into(), 1000, 60_000, 10);
        session.set_cookie("c1", "v1", 1000);
        session.set_local_storage("ls1", "lsv1", 1000);
        assert_eq!(session.get_cookies().len(), 1);
        assert_eq!(session.get_local_storage_map().len(), 1);
    }
}
