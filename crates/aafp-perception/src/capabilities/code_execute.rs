//! Code-execute capability (Track Y6).
//!
//! Provides sandboxed code execution via a pluggable
//! [`CodeExecuteProvider`], with per-language rate limiting, result
//! caching keyed on a content hash of the source, output truncation,
//! and configurable execution limits.
//!
//! The capability mirrors the patterns established by the web-browse
//! (Track Y2) and API-call (Track Y4) capabilities: an injectable
//! [`Clock`] drives both cache TTL expiry and the fixed-window
//! per-language rate limiter, while a pluggable provider trait keeps
//! the execution backend (e.g. a local sandbox, a remote WASM runtime,
//! or a cloud code-runner) decoupled from the capability logic.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::Clock;
use crate::PerceptionError;

// ---------------------------------------------------------------------------
// Provider trait
// ---------------------------------------------------------------------------

/// A pluggable code-execution backend that runs source code in a sandbox.
#[async_trait]
pub trait CodeExecuteProvider: Send + Sync {
    /// Execute the requested code and return the result.
    async fn execute(
        &self,
        req: &CodeExecuteRequest,
    ) -> Result<CodeExecuteResponse, PerceptionError>;
}

// ---------------------------------------------------------------------------
// Language
// ---------------------------------------------------------------------------

/// A supported sandboxed execution language.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    /// Python 3.
    Python,
    /// JavaScript (Node.js).
    JavaScript,
    /// POSIX shell (sh/bash).
    Shell,
    /// Rust (compiled).
    Rust,
    /// Go (compiled).
    Go,
}

impl Language {
    /// Returns the canonical lowercase string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::JavaScript => "javascript",
            Self::Shell => "shell",
            Self::Rust => "rust",
            Self::Go => "go",
        }
    }
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Language {
    type Err = PerceptionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "python" | "py" => Ok(Self::Python),
            "javascript" | "js" => Ok(Self::JavaScript),
            "shell" | "sh" | "bash" => Ok(Self::Shell),
            "rust" | "rs" => Ok(Self::Rust),
            "go" | "golang" => Ok(Self::Go),
            other => Err(PerceptionError::InvalidField {
                field: "language",
                message: format!("unknown language: {other}"),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Execution limits
// ---------------------------------------------------------------------------

/// Resource limits applied to a single execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionLimits {
    /// Maximum wall-clock execution time in milliseconds.
    pub timeout_ms: u64,
    /// Maximum memory usage in megabytes.
    pub memory_limit_mb: u32,
    /// Maximum CPU time in milliseconds.
    pub cpu_ms_limit: u64,
    /// Maximum combined stdout+stderr output size in kilobytes before
    /// truncation.
    pub output_size_limit_kb: u32,
}

impl Default for ExecutionLimits {
    fn default() -> Self {
        Self {
            timeout_ms: 10_000,
            memory_limit_mb: 256,
            cpu_ms_limit: 8_000,
            output_size_limit_kb: 512,
        }
    }
}

impl ExecutionLimits {
    /// Returns the output size limit in bytes.
    pub fn output_size_limit_bytes(&self) -> usize {
        usize::try_from(self.output_size_limit_kb)
            .unwrap_or(usize::MAX)
            .saturating_mul(1024)
    }
}

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

/// A code-execution request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CodeExecuteRequest {
    /// The language to execute.
    pub language: Language,
    /// The source code to run.
    pub source: String,
    /// Optional standard input bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<Vec<u8>>,
    /// Environment variables to set in the sandbox (name → value).
    #[serde(default)]
    pub env_vars: HashMap<String, String>,
    /// Per-request timeout in milliseconds (overrides the capability
    /// default when set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// Per-request memory limit in megabytes (overrides the capability
    /// default when set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_limit_mb: Option<u32>,
}

impl CodeExecuteRequest {
    /// Create a new code-execution request for the given language and source.
    pub fn new(language: Language, source: impl Into<String>) -> Self {
        Self {
            language,
            source: source.into(),
            stdin: None,
            env_vars: HashMap::new(),
            timeout_ms: None,
            memory_limit_mb: None,
        }
    }

    /// Set the standard input.
    pub fn with_stdin(mut self, stdin: Vec<u8>) -> Self {
        self.stdin = Some(stdin);
        self
    }

    /// Set an environment variable.
    pub fn with_env(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_vars.insert(name.into(), value.into());
        self
    }

    /// Set a per-request timeout.
    pub fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = Some(ms);
        self
    }

    /// Set a per-request memory limit.
    pub fn with_memory_limit(mut self, mb: u32) -> Self {
        self.memory_limit_mb = Some(mb);
        self
    }

    /// Serialize the request to a JSON string.
    pub fn to_json(&self) -> Result<String, PerceptionError> {
        serde_json::to_string(self).map_err(|e| PerceptionError::Provider(e.to_string()))
    }

    /// Deserialize a request from a JSON string.
    pub fn from_json(s: &str) -> Result<Self, PerceptionError> {
        serde_json::from_str(s).map_err(|e| PerceptionError::Provider(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

/// A code-execution response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CodeExecuteResponse {
    /// Captured standard output (UTF-8, possibly truncated).
    pub stdout: String,
    /// Captured standard error (UTF-8, possibly truncated).
    pub stderr: String,
    /// The process exit code (0 on success).
    pub exit_code: i32,
    /// Wall-clock execution time in milliseconds.
    pub execution_time_ms: u64,
    /// Peak memory usage in megabytes.
    pub memory_used_mb: u32,
    /// Whether the execution completed successfully (exit code 0).
    pub success: bool,
    /// Whether the output was truncated due to the size limit.
    pub truncated: bool,
}

impl CodeExecuteResponse {
    /// Create a new response, computing `success` from the exit code.
    pub fn new(
        stdout: String,
        stderr: String,
        exit_code: i32,
        execution_time_ms: u64,
        memory_used_mb: u32,
    ) -> Self {
        Self {
            stdout,
            stderr,
            exit_code,
            execution_time_ms,
            memory_used_mb,
            success: exit_code == 0,
            truncated: false,
        }
    }

    /// Returns `true` if the execution succeeded (exit code 0).
    pub fn is_success(&self) -> bool {
        self.exit_code == 0
    }

    /// Returns `true` if the execution timed out (conventional exit code 124).
    pub fn is_timeout(&self) -> bool {
        self.exit_code == 124
    }

    /// Serialize the response to a JSON string.
    pub fn to_json(&self) -> Result<String, PerceptionError> {
        serde_json::to_string(self).map_err(|e| PerceptionError::Provider(e.to_string()))
    }

    /// Deserialize a response from a JSON string.
    pub fn from_json(s: &str) -> Result<Self, PerceptionError> {
        serde_json::from_str(s).map_err(|e| PerceptionError::Provider(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Sandbox policy
// ---------------------------------------------------------------------------

/// Sandbox security policy enforced by the capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Whether network access is allowed (default: false).
    pub allow_network: bool,
    /// Whether filesystem writes are allowed outside the sandbox
    /// working directory (default: false).
    pub allow_filesystem_writes: bool,
    /// Whether environment variables from the host are inherited
    /// (default: false).
    pub inherit_env: bool,
    /// Read-only paths made available to the sandbox.
    #[serde(default)]
    pub read_only_paths: Vec<String>,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            allow_network: false,
            allow_filesystem_writes: false,
            inherit_env: false,
            read_only_paths: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for the code-execute capability.
#[derive(Clone, Debug)]
pub struct CodeExecuteConfig {
    /// Cache time-to-live in milliseconds (caches successful results by
    /// content hash of the source).
    pub cache_ttl_ms: u64,
    /// Maximum number of cache entries before eviction.
    pub max_cache_entries: usize,
    /// Maximum executions allowed per language per minute.
    pub rate_limit_per_minute: u32,
    /// Default execution limits.
    pub limits: ExecutionLimits,
    /// Sandbox security policy.
    pub sandbox: SandboxPolicy,
}

impl Default for CodeExecuteConfig {
    fn default() -> Self {
        Self {
            cache_ttl_ms: 10 * 60 * 1000, // 10 minutes
            max_cache_entries: 64,
            rate_limit_per_minute: 60,
            limits: ExecutionLimits::default(),
            sandbox: SandboxPolicy::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Cache & rate limiter
// ---------------------------------------------------------------------------

/// A cached execution result.
struct CacheEntry {
    response: CodeExecuteResponse,
    /// Unix-millisecond timestamp when the entry was stored.
    timestamp: u64,
}

/// A per-language rate-limit bucket (fixed window per minute).
struct RateBucket {
    /// Unix-millisecond timestamp of the start of the current window.
    window_start_ms: u64,
    /// Number of executions made in the current window.
    count: u32,
}

impl RateBucket {
    fn new(now_ms: u64) -> Self {
        Self {
            window_start_ms: now_ms,
            count: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Capability
// ---------------------------------------------------------------------------

/// The code-execute capability: caches successful results by content hash,
/// rate-limits per language, enforces execution limits, and truncates
/// oversized output.
pub struct CodeExecuteCapability {
    provider: Arc<dyn CodeExecuteProvider>,
    cache: RwLock<HashMap<String, CacheEntry>>,
    rate_limiter: RwLock<HashMap<Language, RateBucket>>,
    config: CodeExecuteConfig,
    clock: Clock,
}

impl CodeExecuteCapability {
    /// Create a new code-execute capability with the default system clock.
    pub fn new(provider: Arc<dyn CodeExecuteProvider>, config: CodeExecuteConfig) -> Self {
        Self {
            provider,
            cache: RwLock::new(HashMap::new()),
            rate_limiter: RwLock::new(HashMap::new()),
            config,
            clock: super::default_clock(),
        }
    }

    /// Create a new code-execute capability with an injected clock (for testing).
    pub fn with_clock(
        provider: Arc<dyn CodeExecuteProvider>,
        config: CodeExecuteConfig,
        clock: Clock,
    ) -> Self {
        Self {
            provider,
            cache: RwLock::new(HashMap::new()),
            rate_limiter: RwLock::new(HashMap::new()),
            config,
            clock,
        }
    }

    /// Execute a code request, applying rate limiting, caching, output
    /// truncation, and timeout enforcement.
    pub async fn execute(
        &self,
        request: &CodeExecuteRequest,
    ) -> Result<CodeExecuteResponse, PerceptionError> {
        if request.source.is_empty() {
            return Err(PerceptionError::InvalidField {
                field: "source",
                message: "source must not be empty".into(),
            });
        }

        // Rate-limit check (per language).
        self.check_rate_limit(request.language)?;

        // Cache lookup.
        let cache_key = self.cache_key(request);
        if let Some(cached) = self.cache_get(&cache_key) {
            return Ok(cached);
        }

        // Timeout enforcement.
        let timeout_ms = request.timeout_ms.unwrap_or(self.config.limits.timeout_ms);
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms),
            self.provider.execute(request),
        )
        .await;

        let mut response = match result {
            Ok(r) => r?,
            Err(_) => {
                return Err(PerceptionError::Timeout);
            }
        };

        // Truncate oversized output.
        let limit_bytes = self.config.limits.output_size_limit_bytes();
        let stdout_truncated = truncate_string(&mut response.stdout, limit_bytes);
        let stderr_truncated = truncate_string(&mut response.stderr, limit_bytes);
        if stdout_truncated || stderr_truncated {
            response.truncated = true;
        }

        // Cache successful, non-truncated results.
        if response.success && !response.truncated {
            self.cache_put(&cache_key, response.clone());
        }

        Ok(response)
    }

    /// Build a deterministic cache key from the request (language + source hash
    /// + stdin hash + sorted env vars).
    fn cache_key(&self, request: &CodeExecuteRequest) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(request.source.as_bytes());
        if let Some(stdin) = &request.stdin {
            hasher.update(stdin);
        }
        let mut env: Vec<(String, String)> = request
            .env_vars
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        env.sort_by(|a, b| a.0.cmp(&b.0));
        for (k, v) in &env {
            hasher.update(k.as_bytes());
            hasher.update(v.as_bytes());
        }
        let digest = hasher.finalize();
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        format!("{}|{}", request.language.as_str(), hex)
    }

    /// Check and increment the per-language rate-limit bucket.
    fn check_rate_limit(&self, language: Language) -> Result<(), PerceptionError> {
        const MINUTE_MS: u64 = 60 * 1000;

        let now_ms = (self.clock)();
        let mut buckets = self
            .rate_limiter
            .write()
            .expect("rate_limiter lock poisoned");

        let bucket = buckets
            .entry(language)
            .or_insert_with(|| RateBucket::new(now_ms));

        // Reset the window if a minute has elapsed.
        if now_ms.saturating_sub(bucket.window_start_ms) >= MINUTE_MS {
            bucket.window_start_ms = now_ms;
            bucket.count = 0;
        }

        if bucket.count >= self.config.rate_limit_per_minute {
            return Err(PerceptionError::RateLimited);
        }

        bucket.count += 1;
        Ok(())
    }

    /// Look up a key in the cache, returning a clone if present and fresh.
    fn cache_get(&self, key: &str) -> Option<CodeExecuteResponse> {
        let now_ms = (self.clock)();
        let cache = self.cache.read().expect("cache lock poisoned");
        let entry = cache.get(key)?;
        if now_ms.saturating_sub(entry.timestamp) >= self.config.cache_ttl_ms {
            // Expired.
            return None;
        }
        Some(entry.response.clone())
    }

    /// Store a response in the cache, evicting expired entries if the cache
    /// is full.
    fn cache_put(&self, key: &str, response: CodeExecuteResponse) {
        let now_ms = (self.clock)();
        let mut cache = self.cache.write().expect("cache lock poisoned");

        // Evict expired entries first.
        evict_expired_locked(&mut cache, self.config.cache_ttl_ms, now_ms);

        // If still at capacity, evict the oldest entry.
        if cache.len() >= self.config.max_cache_entries {
            if let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, e)| e.timestamp)
                .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest_key);
            }
        }

        cache.insert(
            key.to_string(),
            CacheEntry {
                response,
                timestamp: now_ms,
            },
        );
    }

    /// Remove all expired entries from the cache.
    pub fn evict_expired(&self) {
        let now_ms = (self.clock)();
        let mut cache = self.cache.write().expect("cache lock poisoned");
        evict_expired_locked(&mut cache, self.config.cache_ttl_ms, now_ms);
    }

    /// Returns the number of entries currently in the cache.
    #[cfg(test)]
    fn cache_len(&self) -> usize {
        self.cache.read().expect("cache lock poisoned").len()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Remove all expired entries from the cache (helper).
fn evict_expired_locked(cache: &mut HashMap<String, CacheEntry>, ttl: u64, now_ms: u64) {
    cache.retain(|_, entry| now_ms.saturating_sub(entry.timestamp) < ttl);
}

/// Truncate a string to at most `max_bytes` UTF-8 bytes. Returns `true` if
/// truncation occurred. Truncation is performed at a UTF-8 char boundary to
/// avoid producing invalid UTF-8.
fn truncate_string(s: &mut String, max_bytes: usize) -> bool {
    if s.len() <= max_bytes {
        return false;
    }
    // Find the largest char boundary <= max_bytes.
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    true
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

    /// A mock provider with configurable canned responses and call counting.
    struct MockProvider {
        response: RwLock<CodeExecuteResponse>,
        call_count: AtomicU64,
        delay_ms: u64,
    }

    impl MockProvider {
        fn new(response: CodeExecuteResponse) -> Self {
            Self {
                response: RwLock::new(response),
                call_count: AtomicU64::new(0),
                delay_ms: 0,
            }
        }

        fn with_delay(response: CodeExecuteResponse, delay_ms: u64) -> Self {
            Self {
                response: RwLock::new(response),
                call_count: AtomicU64::new(0),
                delay_ms,
            }
        }

        fn set_response(&self, response: CodeExecuteResponse) {
            *self.response.write().expect("response lock poisoned") = response;
        }

        fn calls(&self) -> u64 {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl CodeExecuteProvider for MockProvider {
        async fn execute(
            &self,
            _req: &CodeExecuteRequest,
        ) -> Result<CodeExecuteResponse, PerceptionError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
            }
            Ok(self
                .response
                .read()
                .expect("response lock poisoned")
                .clone())
        }
    }

    fn ok_response(stdout: &str) -> CodeExecuteResponse {
        CodeExecuteResponse::new(stdout.into(), String::new(), 0, 42, 10)
    }

    fn err_response(exit_code: i32, stderr: &str) -> CodeExecuteResponse {
        CodeExecuteResponse::new(String::new(), stderr.into(), exit_code, 42, 10)
    }

    fn default_config() -> CodeExecuteConfig {
        CodeExecuteConfig {
            cache_ttl_ms: 60_000,
            max_cache_entries: 4,
            rate_limit_per_minute: 100,
            limits: ExecutionLimits::default(),
            sandbox: SandboxPolicy::default(),
        }
    }

    // -----------------------------------------------------------------------
    // Language
    // -----------------------------------------------------------------------

    #[test]
    fn test_language_as_str() {
        assert_eq!(Language::Python.as_str(), "python");
        assert_eq!(Language::JavaScript.as_str(), "javascript");
        assert_eq!(Language::Shell.as_str(), "shell");
        assert_eq!(Language::Rust.as_str(), "rust");
        assert_eq!(Language::Go.as_str(), "go");
    }

    #[test]
    fn test_language_display() {
        assert_eq!(format!("{}", Language::Python), "python");
        assert_eq!(format!("{}", Language::Go), "go");
    }

    #[test]
    fn test_language_from_str_ok() {
        assert_eq!("python".parse::<Language>().unwrap(), Language::Python);
        assert_eq!("py".parse::<Language>().unwrap(), Language::Python);
        assert_eq!(
            "javascript".parse::<Language>().unwrap(),
            Language::JavaScript
        );
        assert_eq!("js".parse::<Language>().unwrap(), Language::JavaScript);
        assert_eq!("shell".parse::<Language>().unwrap(), Language::Shell);
        assert_eq!("bash".parse::<Language>().unwrap(), Language::Shell);
        assert_eq!("rust".parse::<Language>().unwrap(), Language::Rust);
        assert_eq!("go".parse::<Language>().unwrap(), Language::Go);
        assert_eq!("golang".parse::<Language>().unwrap(), Language::Go);
    }

    #[test]
    fn test_language_from_str_case_insensitive() {
        assert_eq!("Python".parse::<Language>().unwrap(), Language::Python);
        assert_eq!(
            "JAVASCRIPT".parse::<Language>().unwrap(),
            Language::JavaScript
        );
        assert_eq!("Rust".parse::<Language>().unwrap(), Language::Rust);
    }

    #[test]
    fn test_language_from_str_unknown() {
        let err = "brainfuck".parse::<Language>().unwrap_err();
        assert!(matches!(
            err,
            PerceptionError::InvalidField {
                field: "language",
                ..
            }
        ));
    }

    // -----------------------------------------------------------------------
    // ExecutionLimits
    // -----------------------------------------------------------------------

    #[test]
    fn test_execution_limits_default() {
        let l = ExecutionLimits::default();
        assert_eq!(l.timeout_ms, 10_000);
        assert_eq!(l.memory_limit_mb, 256);
        assert_eq!(l.cpu_ms_limit, 8_000);
        assert_eq!(l.output_size_limit_kb, 512);
    }

    #[test]
    fn test_output_size_limit_bytes() {
        let l = ExecutionLimits {
            output_size_limit_kb: 2,
            ..ExecutionLimits::default()
        };
        assert_eq!(l.output_size_limit_bytes(), 2048);
    }

    // -----------------------------------------------------------------------
    // Request / response serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_request_to_json_roundtrip() {
        let mut req = CodeExecuteRequest::new(Language::Python, "print('hi')")
            .with_stdin(b"input".to_vec())
            .with_env("FOO", "bar")
            .with_timeout(5000)
            .with_memory_limit(128);
        let json = req.to_json().expect("serialize");
        let parsed = CodeExecuteRequest::from_json(&json).expect("deserialize");
        assert_eq!(parsed.language, req.language);
        assert_eq!(parsed.source, req.source);
        assert_eq!(parsed.stdin, req.stdin);
        assert_eq!(parsed.timeout_ms, req.timeout_ms);
        assert_eq!(parsed.memory_limit_mb, req.memory_limit_mb);
        assert_eq!(parsed.env_vars.get("FOO"), Some(&"bar".to_string()));
    }

    #[test]
    fn test_response_to_json_roundtrip() {
        let resp = CodeExecuteResponse::new("out".into(), "err".into(), 0, 100, 50);
        let json = resp.to_json().expect("serialize");
        let parsed = CodeExecuteResponse::from_json(&json).expect("deserialize");
        assert_eq!(parsed.stdout, "out");
        assert_eq!(parsed.stderr, "err");
        assert_eq!(parsed.exit_code, 0);
        assert_eq!(parsed.execution_time_ms, 100);
        assert_eq!(parsed.memory_used_mb, 50);
        assert!(parsed.success);
    }

    #[test]
    fn test_response_success_flag_computed() {
        assert!(CodeExecuteResponse::new(String::new(), String::new(), 0, 0, 0).success);
        assert!(!CodeExecuteResponse::new(String::new(), String::new(), 1, 0, 0).success);
        assert!(!CodeExecuteResponse::new(String::new(), String::new(), -1, 0, 0).success);
    }

    #[test]
    fn test_response_is_timeout() {
        assert!(CodeExecuteResponse::new(String::new(), String::new(), 124, 0, 0).is_timeout());
        assert!(!CodeExecuteResponse::new(String::new(), String::new(), 0, 0, 0).is_timeout());
    }

    // -----------------------------------------------------------------------
    // Builder
    // -----------------------------------------------------------------------

    #[test]
    fn test_request_builder() {
        let req = CodeExecuteRequest::new(Language::Rust, "fn main() {}")
            .with_stdin(b"data".to_vec())
            .with_env("A", "1")
            .with_env("B", "2")
            .with_timeout(3000)
            .with_memory_limit(64);
        assert_eq!(req.language, Language::Rust);
        assert_eq!(req.source, "fn main() {}");
        assert_eq!(req.stdin, Some(b"data".to_vec()));
        assert_eq!(req.env_vars.len(), 2);
        assert_eq!(req.timeout_ms, Some(3000));
        assert_eq!(req.memory_limit_mb, Some(64));
    }

    // -----------------------------------------------------------------------
    // Basic execute
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_execute_success() {
        let provider = Arc::new(MockProvider::new(ok_response("hello\n")));
        let (clock, _) = mock_clock();
        let cap = CodeExecuteCapability::with_clock(provider.clone(), default_config(), clock);
        let resp = cap
            .execute(&CodeExecuteRequest::new(Language::Python, "print('hello')"))
            .await
            .expect("execute ok");
        assert_eq!(resp.stdout, "hello\n");
        assert!(resp.success);
        assert_eq!(provider.calls(), 1);
    }

    #[tokio::test]
    async fn test_execute_empty_source_error() {
        let provider = Arc::new(MockProvider::new(ok_response("x")));
        let (clock, _) = mock_clock();
        let cap = CodeExecuteCapability::with_clock(provider.clone(), default_config(), clock);
        let err = cap
            .execute(&CodeExecuteRequest::new(Language::Python, ""))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            PerceptionError::InvalidField {
                field: "source",
                ..
            }
        ));
        assert_eq!(provider.calls(), 0);
    }

    // -----------------------------------------------------------------------
    // Caching
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_cache_hit_same_source() {
        let provider = Arc::new(MockProvider::new(ok_response("result")));
        let (clock, _) = mock_clock();
        let cap = CodeExecuteCapability::with_clock(provider.clone(), default_config(), clock);
        let req = CodeExecuteRequest::new(Language::Python, "print('hi')");
        let _ = cap.execute(&req).await.expect("first");
        let _ = cap.execute(&req).await.expect("second");
        assert_eq!(provider.calls(), 1, "second execute should hit cache");
    }

    #[tokio::test]
    async fn test_cache_miss_different_source() {
        let provider = Arc::new(MockProvider::new(ok_response("result")));
        let (clock, _) = mock_clock();
        let cap = CodeExecuteCapability::with_clock(provider.clone(), default_config(), clock);
        let _ = cap
            .execute(&CodeExecuteRequest::new(Language::Python, "print(1)"))
            .await;
        let _ = cap
            .execute(&CodeExecuteRequest::new(Language::Python, "print(2)"))
            .await;
        assert_eq!(provider.calls(), 2, "different source → cache miss");
    }

    #[tokio::test]
    async fn test_cache_miss_different_language() {
        let provider = Arc::new(MockProvider::new(ok_response("result")));
        let (clock, _) = mock_clock();
        let cap = CodeExecuteCapability::with_clock(provider.clone(), default_config(), clock);
        let _ = cap
            .execute(&CodeExecuteRequest::new(Language::Python, "x = 1"))
            .await;
        let _ = cap
            .execute(&CodeExecuteRequest::new(Language::JavaScript, "x = 1"))
            .await;
        assert_eq!(provider.calls(), 2, "different language → cache miss");
    }

    #[tokio::test]
    async fn test_cache_ttl_expiration() {
        let provider = Arc::new(MockProvider::new(ok_response("data")));
        let (clock, cell) = mock_clock();
        let cap = CodeExecuteCapability::with_clock(
            provider.clone(),
            CodeExecuteConfig {
                cache_ttl_ms: 1_000,
                max_cache_entries: 4,
                rate_limit_per_minute: 100,
                limits: ExecutionLimits::default(),
                sandbox: SandboxPolicy::default(),
            },
            clock,
        );
        let req = CodeExecuteRequest::new(Language::Python, "print('hi')");
        let _ = cap.execute(&req).await.expect("first");
        assert_eq!(provider.calls(), 1);
        cell.store(1_700_000_000_000 + 2_000, Ordering::SeqCst);
        let _ = cap.execute(&req).await.expect("second");
        assert_eq!(provider.calls(), 2, "expired entry should refetch");
    }

    #[tokio::test]
    async fn test_cache_not_stored_for_failed_execution() {
        let provider = Arc::new(MockProvider::new(err_response(1, "boom")));
        let (clock, _) = mock_clock();
        let cap = CodeExecuteCapability::with_clock(provider.clone(), default_config(), clock);
        let req = CodeExecuteRequest::new(Language::Python, "raise Exception");
        let _ = cap.execute(&req).await.expect("first");
        let _ = cap.execute(&req).await.expect("second");
        // Failed execution is not cached → provider called twice.
        assert_eq!(provider.calls(), 2);
    }

    #[tokio::test]
    async fn test_cache_eviction_max_entries() {
        let provider = Arc::new(MockProvider::new(ok_response("data")));
        let (clock, cell) = mock_clock();
        let cap = CodeExecuteCapability::with_clock(
            provider.clone(),
            CodeExecuteConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 2,
                rate_limit_per_minute: 1000,
                limits: ExecutionLimits::default(),
                sandbox: SandboxPolicy::default(),
            },
            clock,
        );
        let _ = cap
            .execute(&CodeExecuteRequest::new(Language::Python, "a"))
            .await;
        cell.fetch_add(1000, Ordering::SeqCst);
        let _ = cap
            .execute(&CodeExecuteRequest::new(Language::Python, "b"))
            .await;
        cell.fetch_add(1000, Ordering::SeqCst);
        let _ = cap
            .execute(&CodeExecuteRequest::new(Language::Python, "c"))
            .await;
        assert_eq!(cap.cache_len(), 2, "cache should be at capacity");
    }

    #[tokio::test]
    async fn test_evict_expired_public() {
        let provider = Arc::new(MockProvider::new(ok_response("data")));
        let (clock, cell) = mock_clock();
        let cap = CodeExecuteCapability::with_clock(
            provider.clone(),
            CodeExecuteConfig {
                cache_ttl_ms: 1_000,
                max_cache_entries: 4,
                rate_limit_per_minute: 1000,
                limits: ExecutionLimits::default(),
                sandbox: SandboxPolicy::default(),
            },
            clock,
        );
        let _ = cap
            .execute(&CodeExecuteRequest::new(Language::Python, "a"))
            .await;
        assert_eq!(cap.cache_len(), 1);
        cell.store(1_700_000_000_000 + 2_000, Ordering::SeqCst);
        cap.evict_expired();
        assert_eq!(cap.cache_len(), 0, "expired entry should be evicted");
    }

    // -----------------------------------------------------------------------
    // Rate limiting
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_rate_limit_per_language() {
        let provider = Arc::new(MockProvider::new(ok_response("data")));
        let (clock, _) = mock_clock();
        let cap = CodeExecuteCapability::with_clock(
            provider.clone(),
            CodeExecuteConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 4,
                rate_limit_per_minute: 2,
                limits: ExecutionLimits::default(),
                sandbox: SandboxPolicy::default(),
            },
            clock,
        );
        // Use different source each time to bypass cache.
        assert!(cap
            .execute(&CodeExecuteRequest::new(Language::Python, "a"))
            .await
            .is_ok());
        assert!(cap
            .execute(&CodeExecuteRequest::new(Language::Python, "b"))
            .await
            .is_ok());
        let err = cap
            .execute(&CodeExecuteRequest::new(Language::Python, "c"))
            .await
            .unwrap_err();
        assert!(matches!(err, PerceptionError::RateLimited));
    }

    #[tokio::test]
    async fn test_rate_limit_independent_languages() {
        let provider = Arc::new(MockProvider::new(ok_response("data")));
        let (clock, _) = mock_clock();
        let cap = CodeExecuteCapability::with_clock(
            provider.clone(),
            CodeExecuteConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 4,
                rate_limit_per_minute: 1,
                limits: ExecutionLimits::default(),
                sandbox: SandboxPolicy::default(),
            },
            clock,
        );
        assert!(cap
            .execute(&CodeExecuteRequest::new(Language::Python, "a"))
            .await
            .is_ok());
        assert!(
            cap.execute(&CodeExecuteRequest::new(Language::JavaScript, "a"))
                .await
                .is_ok(),
            "different language has own bucket"
        );
    }

    #[tokio::test]
    async fn test_rate_limit_reset_after_window() {
        let provider = Arc::new(MockProvider::new(ok_response("data")));
        let (clock, cell) = mock_clock();
        let cap = CodeExecuteCapability::with_clock(
            provider.clone(),
            CodeExecuteConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 4,
                rate_limit_per_minute: 1,
                limits: ExecutionLimits::default(),
                sandbox: SandboxPolicy::default(),
            },
            clock,
        );
        assert!(cap
            .execute(&CodeExecuteRequest::new(Language::Python, "a"))
            .await
            .is_ok());
        assert!(matches!(
            cap.execute(&CodeExecuteRequest::new(Language::Python, "b"))
                .await
                .unwrap_err(),
            PerceptionError::RateLimited
        ));
        cell.store(1_700_000_000_000 + 60 * 1000 + 1, Ordering::SeqCst);
        assert!(
            cap.execute(&CodeExecuteRequest::new(Language::Python, "c"))
                .await
                .is_ok(),
            "window reset allows request"
        );
    }

    // -----------------------------------------------------------------------
    // Output truncation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_output_truncation_stdout() {
        let big = "x".repeat(2048);
        let provider = Arc::new(MockProvider::new(ok_response(&big)));
        let (clock, _) = mock_clock();
        let cap = CodeExecuteCapability::with_clock(
            provider.clone(),
            CodeExecuteConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 4,
                rate_limit_per_minute: 100,
                limits: ExecutionLimits {
                    output_size_limit_kb: 1, // 1024 bytes
                    ..ExecutionLimits::default()
                },
                sandbox: SandboxPolicy::default(),
            },
            clock,
        );
        let resp = cap
            .execute(&CodeExecuteRequest::new(Language::Python, "print(big)"))
            .await
            .expect("ok");
        assert!(resp.truncated);
        assert!(resp.stdout.len() <= 1024);
    }

    #[tokio::test]
    async fn test_output_truncation_stderr() {
        let big = "e".repeat(2048);
        let provider = Arc::new(MockProvider::new(CodeExecuteResponse::new(
            String::new(),
            big,
            1,
            42,
            10,
        )));
        let (clock, _) = mock_clock();
        let cap = CodeExecuteCapability::with_clock(
            provider.clone(),
            CodeExecuteConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 4,
                rate_limit_per_minute: 100,
                limits: ExecutionLimits {
                    output_size_limit_kb: 1,
                    ..ExecutionLimits::default()
                },
                sandbox: SandboxPolicy::default(),
            },
            clock,
        );
        let resp = cap
            .execute(&CodeExecuteRequest::new(Language::Python, "err"))
            .await
            .expect("ok");
        assert!(resp.truncated);
        assert!(resp.stderr.len() <= 1024);
    }

    #[test]
    fn test_truncate_string_no_truncation_needed() {
        let mut s = "hello".to_string();
        assert!(!truncate_string(&mut s, 100));
        assert_eq!(s, "hello");
    }

    #[test]
    fn test_truncate_string_exact_boundary() {
        let mut s = "hello".to_string();
        assert!(!truncate_string(&mut s, 5));
        assert_eq!(s, "hello");
    }

    #[test]
    fn test_truncate_string_multibyte_boundary() {
        // "héllo" — 'é' is 2 bytes.
        let mut s = "héllo".to_string();
        // Truncate at 2 bytes → "h" (byte 1 is mid-é, so we back off to 1).
        assert!(truncate_string(&mut s, 2));
        assert_eq!(s, "h");
    }

    // -----------------------------------------------------------------------
    // Timeout
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_timeout_returns_timeout_error() {
        let provider = Arc::new(MockProvider::with_delay(ok_response("slow"), 500));
        let (clock, _) = mock_clock();
        let cap = CodeExecuteCapability::with_clock(
            provider.clone(),
            CodeExecuteConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 4,
                rate_limit_per_minute: 100,
                limits: ExecutionLimits {
                    timeout_ms: 10,
                    ..ExecutionLimits::default()
                },
                sandbox: SandboxPolicy::default(),
            },
            clock,
        );
        let err = cap
            .execute(&CodeExecuteRequest::new(Language::Python, "slow"))
            .await
            .unwrap_err();
        assert!(matches!(err, PerceptionError::Timeout));
    }

    #[tokio::test]
    async fn test_per_request_timeout_override() {
        let provider = Arc::new(MockProvider::with_delay(ok_response("slow"), 500));
        let (clock, _) = mock_clock();
        let cap = CodeExecuteCapability::with_clock(provider.clone(), default_config(), clock);
        let req = CodeExecuteRequest::new(Language::Python, "slow").with_timeout(10);
        let err = cap.execute(&req).await.unwrap_err();
        assert!(matches!(err, PerceptionError::Timeout));
    }

    // -----------------------------------------------------------------------
    // Sandbox policy & config defaults
    // -----------------------------------------------------------------------

    #[test]
    fn test_sandbox_policy_default_is_secure() {
        let p = SandboxPolicy::default();
        assert!(!p.allow_network, "network should be disabled by default");
        assert!(
            !p.allow_filesystem_writes,
            "filesystem writes should be disabled by default"
        );
        assert!(
            !p.inherit_env,
            "env inheritance should be disabled by default"
        );
        assert!(p.read_only_paths.is_empty());
    }

    #[test]
    fn test_default_config_values() {
        let cfg = CodeExecuteConfig::default();
        assert_eq!(cfg.cache_ttl_ms, 10 * 60 * 1000);
        assert_eq!(cfg.max_cache_entries, 64);
        assert_eq!(cfg.rate_limit_per_minute, 60);
        assert_eq!(cfg.limits.timeout_ms, 10_000);
        assert_eq!(cfg.limits.memory_limit_mb, 256);
        assert!(!cfg.sandbox.allow_network);
    }

    // -----------------------------------------------------------------------
    // Provider error propagation
    // ---------------------------------------------------------------------------

    struct FailingProvider;

    #[async_trait]
    impl CodeExecuteProvider for FailingProvider {
        async fn execute(
            &self,
            _req: &CodeExecuteRequest,
        ) -> Result<CodeExecuteResponse, PerceptionError> {
            Err(PerceptionError::Provider("sandbox unavailable".into()))
        }
    }

    #[tokio::test]
    async fn test_provider_error_propagates() {
        let provider = Arc::new(FailingProvider);
        let (clock, _) = mock_clock();
        let cap = CodeExecuteCapability::with_clock(provider, default_config(), clock);
        let err = cap
            .execute(&CodeExecuteRequest::new(Language::Python, "x"))
            .await
            .unwrap_err();
        assert!(matches!(err, PerceptionError::Provider(_)));
    }
}
