//! API-call capability (Track Y4).
//!
//! Provides agent-native HTTP API calls via a pluggable
//! [`ApiCallProvider`], with TTL-based GET response caching, per-host
//! rate limiting, timeout support, and configurable retry on 5xx
//! errors.
//!
//! The capability mirrors the patterns established by the web-browse
//! (Track Y2) and search (Track Y2) capabilities: an injectable
//! [`Clock`] drives both cache TTL expiry and the fixed-window
//! per-host rate limiter, while a pluggable provider trait keeps the
//! HTTP backend decoupled from the capability logic.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::Clock;
use crate::PerceptionError;

// ---------------------------------------------------------------------------
// Provider trait
// ---------------------------------------------------------------------------

/// A pluggable API-call backend that executes HTTP requests.
#[async_trait]
pub trait ApiCallProvider: Send + Sync {
    /// Execute a single HTTP request and return the response.
    async fn call(&self, req: &ApiCallRequest) -> Result<ApiCallResponse, PerceptionError>;
}

// ---------------------------------------------------------------------------
// HTTP method
// ---------------------------------------------------------------------------

/// An HTTP method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    /// HTTP GET.
    Get,
    /// HTTP POST.
    Post,
    /// HTTP PUT.
    Put,
    /// HTTP DELETE.
    Delete,
    /// HTTP PATCH.
    Patch,
}

impl HttpMethod {
    /// Returns the canonical uppercase string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
        }
    }

    /// Returns `true` if the method is cacheable (only GET is cacheable).
    pub fn is_cacheable(self) -> bool {
        matches!(self, Self::Get)
    }
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for HttpMethod {
    type Err = PerceptionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "GET" => Ok(Self::Get),
            "POST" => Ok(Self::Post),
            "PUT" => Ok(Self::Put),
            "DELETE" => Ok(Self::Delete),
            "PATCH" => Ok(Self::Patch),
            other => Err(PerceptionError::InvalidField {
                field: "method",
                message: format!("unknown HTTP method: {other}"),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

/// An API-call request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiCallRequest {
    /// The endpoint URL.
    pub endpoint: String,
    /// The HTTP method.
    pub method: HttpMethod,
    /// HTTP request headers (name → value).
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Optional request body (bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<Vec<u8>>,
    /// Query/path parameters to interpolate or append.
    #[serde(default)]
    pub params: HashMap<String, String>,
    /// Optional bearer/inline auth token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    /// Per-request timeout in milliseconds (overrides the capability default
    /// when set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

impl ApiCallRequest {
    /// Create a new GET request for the given endpoint.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            method: HttpMethod::Get,
            headers: HashMap::new(),
            body: None,
            params: HashMap::new(),
            auth_token: None,
            timeout_ms: None,
        }
    }

    /// Set the HTTP method.
    pub fn with_method(mut self, method: HttpMethod) -> Self {
        self.method = method;
        self
    }

    /// Set the request body.
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    /// Set the auth token.
    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    /// Add a header.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Add a query parameter.
    pub fn with_param(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.params.insert(name.into(), value.into());
        self
    }

    /// Set a per-request timeout.
    pub fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = Some(ms);
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

/// An API-call response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiCallResponse {
    /// HTTP status code.
    pub status_code: u16,
    /// Response headers (name → value).
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Response body (bytes).
    #[serde(default)]
    pub body: Vec<u8>,
    /// Round-trip latency in milliseconds.
    pub latency_ms: u64,
    /// Whether the response is considered successful (2xx).
    pub success: bool,
}

impl ApiCallResponse {
    /// Create a new response, computing `success` from the status code.
    pub fn new(
        status_code: u16,
        headers: HashMap<String, String>,
        body: Vec<u8>,
        latency_ms: u64,
    ) -> Self {
        Self {
            status_code,
            headers,
            body,
            latency_ms,
            success: is_success(status_code),
        }
    }

    /// Returns `true` if the status code is a 2xx success.
    pub fn is_success(&self) -> bool {
        is_success(self.status_code)
    }

    /// Returns `true` if the status code is a 5xx server error.
    pub fn is_server_error(&self) -> bool {
        is_server_error(self.status_code)
    }

    /// Returns the response body as a UTF-8 string, if valid.
    pub fn body_text(&self) -> Option<String> {
        String::from_utf8(self.body.clone()).ok()
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

/// Returns `true` if `code` is a 2xx success code.
fn is_success(code: u16) -> bool {
    (200..300).contains(&code)
}

/// Returns `true` if `code` is a 5xx server error.
fn is_server_error(code: u16) -> bool {
    (500..600).contains(&code)
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for the API-call capability.
#[derive(Clone, Debug)]
pub struct ApiCallConfig {
    /// Cache time-to-live in milliseconds (applies only to GET responses).
    pub cache_ttl_ms: u64,
    /// Maximum number of cache entries before eviction.
    pub max_cache_entries: usize,
    /// Maximum requests allowed per host per hour.
    pub rate_limit_per_hour: u32,
    /// Default request timeout in milliseconds.
    pub timeout_ms: u64,
    /// Maximum number of retries on 5xx server errors (0 = no retry).
    pub max_retries: u32,
    /// Base backoff in milliseconds for retry delays (doubled per attempt).
    pub retry_backoff_ms: u64,
}

impl Default for ApiCallConfig {
    fn default() -> Self {
        Self {
            cache_ttl_ms: 5 * 60 * 1000, // 5 minutes
            max_cache_entries: 128,
            rate_limit_per_hour: 1000,
            timeout_ms: 30_000,
            max_retries: 3,
            retry_backoff_ms: 200,
        }
    }
}

// ---------------------------------------------------------------------------
// Cache & rate limiter
// ---------------------------------------------------------------------------

/// A cached GET response.
struct CacheEntry {
    response: ApiCallResponse,
    /// Unix-millisecond timestamp when the entry was stored.
    timestamp: u64,
}

/// A per-host rate-limit bucket (fixed window per hour).
struct RateBucket {
    /// Unix-millisecond timestamp of the start of the current window.
    window_start_ms: u64,
    /// Number of requests made in the current window.
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

/// The API-call capability: caches GET responses, rate-limits per host,
/// enforces timeouts, and retries on 5xx errors.
pub struct ApiCallCapability {
    provider: Arc<dyn ApiCallProvider>,
    cache: RwLock<HashMap<String, CacheEntry>>,
    rate_limiter: RwLock<HashMap<String, RateBucket>>,
    config: ApiCallConfig,
    clock: Clock,
}

impl ApiCallCapability {
    /// Create a new API-call capability with the default system clock.
    pub fn new(provider: Arc<dyn ApiCallProvider>, config: ApiCallConfig) -> Self {
        Self {
            provider,
            cache: RwLock::new(HashMap::new()),
            rate_limiter: RwLock::new(HashMap::new()),
            config,
            clock: super::default_clock(),
        }
    }

    /// Create a new API-call capability with an injected clock (for testing).
    pub fn with_clock(
        provider: Arc<dyn ApiCallProvider>,
        config: ApiCallConfig,
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

    /// Execute an API request, applying rate limiting, caching (for GET),
    /// timeout enforcement, and retry on 5xx errors.
    pub async fn call(&self, request: &ApiCallRequest) -> Result<ApiCallResponse, PerceptionError> {
        if request.endpoint.is_empty() {
            return Err(PerceptionError::InvalidField {
                field: "endpoint",
                message: "endpoint must not be empty".into(),
            });
        }

        // Rate-limit check (per host).
        self.check_rate_limit(&request.endpoint)?;

        // Cache lookup for cacheable GET requests.
        if request.method.is_cacheable() {
            let cache_key = self.cache_key(request);
            if let Some(cached) = self.cache_get(&cache_key) {
                return Ok(cached);
            }
        }

        // Execute with retry on 5xx.
        let response = self.call_with_retry(request).await?;

        // Store successful GET responses in the cache.
        if request.method.is_cacheable() && response.success {
            let cache_key = self.cache_key(request);
            self.cache_put(&cache_key, response.clone());
        }

        Ok(response)
    }

    /// Execute the request via the provider, retrying on 5xx errors up to
    /// `max_retries` times with exponential backoff.
    async fn call_with_retry(
        &self,
        request: &ApiCallRequest,
    ) -> Result<ApiCallResponse, PerceptionError> {
        let mut last_err: Option<PerceptionError> = None;
        let max_attempts = self.config.max_retries.saturating_add(1);
        for attempt in 0..max_attempts {
            if attempt > 0 {
                // Exponential backoff: base * 2^(attempt-1).
                let backoff = self
                    .config
                    .retry_backoff_ms
                    .saturating_mul(1u64.checked_shl(attempt - 1).unwrap_or_default());
                tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
            }

            // Timeout enforcement.
            let timeout_ms = request.timeout_ms.unwrap_or(self.config.timeout_ms);
            let result = match tokio::time::timeout(
                std::time::Duration::from_millis(timeout_ms),
                self.provider.call(request),
            )
            .await
            {
                Ok(r) => r,
                Err(_) => {
                    last_err = Some(PerceptionError::Timeout);
                    continue;
                }
            };

            match result {
                Ok(resp) => {
                    if resp.is_server_error() && attempt + 1 < max_attempts {
                        last_err = Some(PerceptionError::Provider(format!(
                            "server error {} (will retry)",
                            resp.status_code
                        )));
                        continue;
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            }
        }
        Err(last_err
            .unwrap_or_else(|| PerceptionError::Provider("all retry attempts exhausted".into())))
    }

    /// Build a deterministic cache key from the request.
    fn cache_key(&self, request: &ApiCallRequest) -> String {
        // Normalize params into a sorted, stable string.
        let mut params: Vec<(String, String)> = request
            .params
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        params.sort_by(|a, b| a.0.cmp(&b.0));
        let params_str = params
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        format!("GET|{}|{}", request.endpoint, params_str)
    }

    /// Check and increment the per-host rate-limit bucket.
    fn check_rate_limit(&self, endpoint: &str) -> Result<(), PerceptionError> {
        const HOUR_MS: u64 = 60 * 60 * 1000;

        let host = extract_host(endpoint).unwrap_or_else(|| endpoint.to_string());
        let now_ms = (self.clock)();
        let mut buckets = self
            .rate_limiter
            .write()
            .expect("rate_limiter lock poisoned");

        let bucket = buckets
            .entry(host)
            .or_insert_with(|| RateBucket::new(now_ms));

        // Reset the window if an hour has elapsed.
        if now_ms.saturating_sub(bucket.window_start_ms) >= HOUR_MS {
            bucket.window_start_ms = now_ms;
            bucket.count = 0;
        }

        if bucket.count >= self.config.rate_limit_per_hour {
            return Err(PerceptionError::RateLimited);
        }

        bucket.count += 1;
        Ok(())
    }

    /// Look up a key in the cache, returning a clone if present and fresh.
    fn cache_get(&self, key: &str) -> Option<ApiCallResponse> {
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
    fn cache_put(&self, key: &str, response: ApiCallResponse) {
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

/// Remove all expired entries from the cache (helper).
fn evict_expired_locked(cache: &mut HashMap<String, CacheEntry>, ttl: u64, now_ms: u64) {
    cache.retain(|_, entry| now_ms.saturating_sub(entry.timestamp) < ttl);
}

/// Extract the host portion of a URL (lowercased).
fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let host = after_scheme.split('/').next()?;
    let host = host.split(':').next()?; // strip port
    if host.is_empty() {
        None
    } else {
        Some(host.to_lowercase())
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

    /// A mock provider with configurable canned responses and call counting.
    struct MockProvider {
        responses: RwLock<Vec<ApiCallResponse>>,
        call_count: AtomicU64,
        fail_count: AtomicU64,
        fail_first: AtomicU64,
    }

    impl MockProvider {
        fn new(responses: Vec<ApiCallResponse>) -> Self {
            Self {
                responses: RwLock::new(responses),
                call_count: AtomicU64::new(0),
                fail_count: AtomicU64::new(0),
                fail_first: AtomicU64::new(0),
            }
        }

        fn single(resp: ApiCallResponse) -> Self {
            Self::new(vec![resp])
        }

        /// Fail the first `n` calls with a provider error, then succeed.
        fn fail_first(n: u64) -> Self {
            Self {
                responses: RwLock::new(vec![ok_response(200, "ok")]),
                call_count: AtomicU64::new(0),
                fail_count: AtomicU64::new(0),
                fail_first: AtomicU64::new(n),
            }
        }

        fn calls(&self) -> u64 {
            self.call_count.load(Ordering::SeqCst)
        }

        fn failures(&self) -> u64 {
            self.fail_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ApiCallProvider for MockProvider {
        async fn call(&self, _req: &ApiCallRequest) -> Result<ApiCallResponse, PerceptionError> {
            let n = self.call_count.fetch_add(1, Ordering::SeqCst);
            if n < self.fail_first.load(Ordering::SeqCst) {
                self.fail_count.fetch_add(1, Ordering::SeqCst);
                return Err(PerceptionError::Provider("mock failure".into()));
            }
            let resp = {
                let mut responses = self.responses.write().expect("responses lock poisoned");
                if responses.len() > 1 {
                    responses.remove(0)
                } else {
                    responses
                        .first()
                        .cloned()
                        .unwrap_or_else(|| ok_response(200, "ok"))
                }
            };
            Ok(resp)
        }
    }

    fn ok_response(code: u16, body: &str) -> ApiCallResponse {
        ApiCallResponse::new(code, HashMap::new(), body.as_bytes().to_vec(), 42)
    }

    fn server_error_response(code: u16) -> ApiCallResponse {
        ApiCallResponse::new(code, HashMap::new(), b"error".to_vec(), 10)
    }

    fn default_config() -> ApiCallConfig {
        ApiCallConfig {
            cache_ttl_ms: 60_000,
            max_cache_entries: 4,
            rate_limit_per_hour: 100,
            timeout_ms: 5_000,
            max_retries: 3,
            retry_backoff_ms: 1,
        }
    }

    fn no_retry_config() -> ApiCallConfig {
        ApiCallConfig {
            cache_ttl_ms: 60_000,
            max_cache_entries: 4,
            rate_limit_per_hour: 100,
            timeout_ms: 5_000,
            max_retries: 0,
            retry_backoff_ms: 1,
        }
    }

    // -----------------------------------------------------------------------
    // HttpMethod
    // -----------------------------------------------------------------------

    #[test]
    fn test_http_method_as_str() {
        assert_eq!(HttpMethod::Get.as_str(), "GET");
        assert_eq!(HttpMethod::Post.as_str(), "POST");
        assert_eq!(HttpMethod::Put.as_str(), "PUT");
        assert_eq!(HttpMethod::Delete.as_str(), "DELETE");
        assert_eq!(HttpMethod::Patch.as_str(), "PATCH");
    }

    #[test]
    fn test_http_method_is_cacheable() {
        assert!(HttpMethod::Get.is_cacheable());
        assert!(!HttpMethod::Post.is_cacheable());
        assert!(!HttpMethod::Put.is_cacheable());
        assert!(!HttpMethod::Delete.is_cacheable());
        assert!(!HttpMethod::Patch.is_cacheable());
    }

    #[test]
    fn test_http_method_display() {
        assert_eq!(format!("{}", HttpMethod::Get), "GET");
        assert_eq!(format!("{}", HttpMethod::Post), "POST");
    }

    #[test]
    fn test_http_method_from_str_ok() {
        let m: HttpMethod = "get".parse().unwrap();
        assert_eq!(m, HttpMethod::Get);
        let m: HttpMethod = "POST".parse().unwrap();
        assert_eq!(m, HttpMethod::Post);
        let m: HttpMethod = "Patch".parse().unwrap();
        assert_eq!(m, HttpMethod::Patch);
    }

    #[test]
    fn test_http_method_from_str_unknown() {
        let err = "BOGUS".parse::<HttpMethod>().unwrap_err();
        assert!(matches!(
            err,
            PerceptionError::InvalidField {
                field: "method",
                ..
            }
        ));
    }

    // -----------------------------------------------------------------------
    // Request / response serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_request_to_json_roundtrip() {
        let mut req = ApiCallRequest::new("https://api.example.com/v1/users")
            .with_method(HttpMethod::Post)
            .with_body(b"{\"x\":1}".to_vec())
            .with_auth_token("secret")
            .with_header("content-type", "application/json")
            .with_param("page", "1");
        req.timeout_ms = Some(1000);
        let json = req.to_json().expect("serialize");
        let parsed = ApiCallRequest::from_json(&json).expect("deserialize");
        assert_eq!(parsed.endpoint, req.endpoint);
        assert_eq!(parsed.method, HttpMethod::Post);
        assert_eq!(parsed.body, req.body);
        assert_eq!(parsed.auth_token, req.auth_token);
        assert_eq!(parsed.timeout_ms, req.timeout_ms);
        assert_eq!(
            parsed.headers.get("content-type"),
            Some(&"application/json".to_string())
        );
        assert_eq!(parsed.params.get("page"), Some(&"1".to_string()));
    }

    #[test]
    fn test_response_to_json_roundtrip() {
        let mut headers = HashMap::new();
        headers.insert("content-type".into(), "application/json".into());
        let resp = ApiCallResponse::new(201, headers, b"created".to_vec(), 123);
        let json = resp.to_json().expect("serialize");
        let parsed = ApiCallResponse::from_json(&json).expect("deserialize");
        assert_eq!(parsed.status_code, 201);
        assert_eq!(parsed.latency_ms, 123);
        assert_eq!(parsed.body_text(), Some("created".into()));
        assert!(parsed.success);
    }

    #[test]
    fn test_response_success_flag_computed() {
        assert!(ApiCallResponse::new(200, HashMap::new(), vec![], 0).success);
        assert!(ApiCallResponse::new(299, HashMap::new(), vec![], 0).success);
        assert!(!ApiCallResponse::new(404, HashMap::new(), vec![], 0).success);
        assert!(!ApiCallResponse::new(500, HashMap::new(), vec![], 0).success);
    }

    #[test]
    fn test_response_is_server_error() {
        assert!(server_error_response(500).is_server_error());
        assert!(server_error_response(503).is_server_error());
        assert!(!server_error_response(404).is_server_error());
        assert!(!ok_response(200, "ok").is_server_error());
    }

    #[test]
    fn test_response_body_text_invalid_utf8() {
        let resp = ApiCallResponse::new(200, HashMap::new(), vec![0xFF, 0xFE], 0);
        assert!(resp.body_text().is_none());
    }

    // -----------------------------------------------------------------------
    // Basic call
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_call_get_success() {
        let provider = Arc::new(MockProvider::single(ok_response(200, "hello")));
        let (clock, _) = mock_clock();
        let cap = ApiCallCapability::with_clock(provider.clone(), default_config(), clock);
        let resp = cap
            .call(&ApiCallRequest::new("https://api.example.com/data"))
            .await
            .expect("call ok");
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.body_text(), Some("hello".into()));
        assert_eq!(provider.calls(), 1);
    }

    #[tokio::test]
    async fn test_call_post_not_cached() {
        let provider = Arc::new(MockProvider::single(ok_response(201, "created")));
        let (clock, _) = mock_clock();
        let cap = ApiCallCapability::with_clock(provider.clone(), default_config(), clock);
        let req =
            ApiCallRequest::new("https://api.example.com/items").with_method(HttpMethod::Post);
        let _ = cap.call(&req).await.expect("first");
        let _ = cap.call(&req).await.expect("second");
        // POST is not cacheable → provider called twice.
        assert_eq!(provider.calls(), 2);
    }

    #[tokio::test]
    async fn test_call_empty_endpoint_error() {
        let provider = Arc::new(MockProvider::single(ok_response(200, "x")));
        let (clock, _) = mock_clock();
        let cap = ApiCallCapability::with_clock(provider.clone(), default_config(), clock);
        let err = cap.call(&ApiCallRequest::new("")).await.unwrap_err();
        assert!(matches!(
            err,
            PerceptionError::InvalidField {
                field: "endpoint",
                ..
            }
        ));
        assert_eq!(provider.calls(), 0);
    }

    // -----------------------------------------------------------------------
    // Caching
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_cache_hit_get() {
        let provider = Arc::new(MockProvider::single(ok_response(200, "data")));
        let (clock, _) = mock_clock();
        let cap = ApiCallCapability::with_clock(provider.clone(), default_config(), clock);
        let req = ApiCallRequest::new("https://api.example.com/data");
        let _ = cap.call(&req).await.expect("first");
        let _ = cap.call(&req).await.expect("second");
        assert_eq!(provider.calls(), 1, "second GET should hit cache");
    }

    #[tokio::test]
    async fn test_cache_miss_different_params() {
        let provider = Arc::new(MockProvider::single(ok_response(200, "data")));
        let (clock, _) = mock_clock();
        let cap = ApiCallCapability::with_clock(provider.clone(), default_config(), clock);
        let r1 = ApiCallRequest::new("https://api.example.com/data").with_param("page", "1");
        let r2 = ApiCallRequest::new("https://api.example.com/data").with_param("page", "2");
        let _ = cap.call(&r1).await.expect("first");
        let _ = cap.call(&r2).await.expect("second");
        assert_eq!(provider.calls(), 2, "different params → cache miss");
    }

    #[tokio::test]
    async fn test_cache_ttl_expiration() {
        let provider = Arc::new(MockProvider::single(ok_response(200, "data")));
        let (clock, cell) = mock_clock();
        let cap = ApiCallCapability::with_clock(
            provider.clone(),
            ApiCallConfig {
                cache_ttl_ms: 1_000,
                max_cache_entries: 4,
                rate_limit_per_hour: 100,
                timeout_ms: 5_000,
                max_retries: 0,
                retry_backoff_ms: 1,
            },
            clock,
        );
        let req = ApiCallRequest::new("https://api.example.com/data");
        let _ = cap.call(&req).await.expect("first");
        assert_eq!(provider.calls(), 1);
        cell.store(1_700_000_000_000 + 2_000, Ordering::SeqCst);
        let _ = cap.call(&req).await.expect("second");
        assert_eq!(provider.calls(), 2, "expired entry should refetch");
    }

    #[tokio::test]
    async fn test_cache_not_stored_for_non_2xx() {
        let provider = Arc::new(MockProvider::single(ok_response(404, "not found")));
        let (clock, _) = mock_clock();
        let cap = ApiCallCapability::with_clock(provider.clone(), default_config(), clock);
        let req = ApiCallRequest::new("https://api.example.com/missing");
        let _ = cap.call(&req).await.expect("first");
        let _ = cap.call(&req).await.expect("second");
        // 404 is not successful → not cached → provider called twice.
        assert_eq!(provider.calls(), 2);
    }

    #[tokio::test]
    async fn test_cache_eviction_max_entries() {
        let provider = Arc::new(MockProvider::single(ok_response(200, "data")));
        let (clock, cell) = mock_clock();
        let cap = ApiCallCapability::with_clock(
            provider.clone(),
            ApiCallConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 2,
                rate_limit_per_hour: 1000,
                timeout_ms: 5_000,
                max_retries: 0,
                retry_backoff_ms: 1,
            },
            clock,
        );
        let _ = cap.call(&ApiCallRequest::new("https://a.com/x")).await;
        cell.fetch_add(1000, Ordering::SeqCst);
        let _ = cap.call(&ApiCallRequest::new("https://b.com/x")).await;
        cell.fetch_add(1000, Ordering::SeqCst);
        let _ = cap.call(&ApiCallRequest::new("https://c.com/x")).await;
        assert_eq!(cap.cache_len(), 2, "cache should be at capacity");
    }

    #[tokio::test]
    async fn test_evict_expired_public() {
        let provider = Arc::new(MockProvider::single(ok_response(200, "data")));
        let (clock, cell) = mock_clock();
        let cap = ApiCallCapability::with_clock(
            provider.clone(),
            ApiCallConfig {
                cache_ttl_ms: 1_000,
                max_cache_entries: 4,
                rate_limit_per_hour: 1000,
                timeout_ms: 5_000,
                max_retries: 0,
                retry_backoff_ms: 1,
            },
            clock,
        );
        let _ = cap.call(&ApiCallRequest::new("https://a.com/x")).await;
        assert_eq!(cap.cache_len(), 1);
        cell.store(1_700_000_000_000 + 2_000, Ordering::SeqCst);
        cap.evict_expired();
        assert_eq!(cap.cache_len(), 0, "expired entry should be evicted");
    }

    // -----------------------------------------------------------------------
    // Rate limiting
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_rate_limit_per_host() {
        let provider = Arc::new(MockProvider::single(ok_response(200, "data")));
        let (clock, _) = mock_clock();
        let cap = ApiCallCapability::with_clock(
            provider.clone(),
            ApiCallConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 4,
                rate_limit_per_hour: 2,
                timeout_ms: 5_000,
                max_retries: 0,
                retry_backoff_ms: 1,
            },
            clock,
        );
        // Use POST to bypass caching so each call hits the rate limiter.
        let req = ApiCallRequest::new("https://api.example.com/x").with_method(HttpMethod::Post);
        assert!(cap.call(&req).await.is_ok());
        assert!(cap.call(&req).await.is_ok());
        let err = cap.call(&req).await.unwrap_err();
        assert!(matches!(err, PerceptionError::RateLimited));
    }

    #[tokio::test]
    async fn test_rate_limit_independent_hosts() {
        let provider = Arc::new(MockProvider::single(ok_response(200, "data")));
        let (clock, _) = mock_clock();
        let cap = ApiCallCapability::with_clock(
            provider.clone(),
            ApiCallConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 4,
                rate_limit_per_hour: 1,
                timeout_ms: 5_000,
                max_retries: 0,
                retry_backoff_ms: 1,
            },
            clock,
        );
        let r1 = ApiCallRequest::new("https://a.com/x").with_method(HttpMethod::Post);
        let r2 = ApiCallRequest::new("https://b.com/x").with_method(HttpMethod::Post);
        assert!(cap.call(&r1).await.is_ok());
        assert!(cap.call(&r2).await.is_ok(), "different host has own bucket");
    }

    #[tokio::test]
    async fn test_rate_limit_reset_after_window() {
        let provider = Arc::new(MockProvider::single(ok_response(200, "data")));
        let (clock, cell) = mock_clock();
        let cap = ApiCallCapability::with_clock(
            provider.clone(),
            ApiCallConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 4,
                rate_limit_per_hour: 1,
                timeout_ms: 5_000,
                max_retries: 0,
                retry_backoff_ms: 1,
            },
            clock,
        );
        let req = ApiCallRequest::new("https://a.com/x").with_method(HttpMethod::Post);
        assert!(cap.call(&req).await.is_ok());
        assert!(matches!(
            cap.call(&req).await.unwrap_err(),
            PerceptionError::RateLimited
        ));
        cell.store(1_700_000_000_000 + 60 * 60 * 1000 + 1, Ordering::SeqCst);
        assert!(cap.call(&req).await.is_ok(), "window reset allows request");
    }

    // -----------------------------------------------------------------------
    // Retry on 5xx
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_retry_on_5xx_then_success() {
        // First call returns 503, second returns 200.
        let provider = Arc::new(MockProvider::new(vec![
            server_error_response(503),
            ok_response(200, "ok"),
        ]));
        let (clock, _) = mock_clock();
        let cap = ApiCallCapability::with_clock(provider.clone(), default_config(), clock);
        let req = ApiCallRequest::new("https://a.com/x").with_method(HttpMethod::Post);
        let resp = cap.call(&req).await.expect("should succeed after retry");
        assert_eq!(resp.status_code, 200);
        assert_eq!(provider.calls(), 2);
    }

    #[tokio::test]
    async fn test_retry_exhausted_on_persistent_5xx() {
        // Always returns 503.
        let provider = Arc::new(MockProvider::single(server_error_response(503)));
        let (clock, _) = mock_clock();
        let cap = ApiCallCapability::with_clock(provider.clone(), default_config(), clock);
        let req = ApiCallRequest::new("https://a.com/x").with_method(HttpMethod::Post);
        let resp = cap.call(&req).await.expect("last attempt returns response");
        assert_eq!(resp.status_code, 503);
        // max_retries=3 → 4 total attempts.
        assert_eq!(provider.calls(), 4);
    }

    #[tokio::test]
    async fn test_no_retry_when_max_retries_zero() {
        let provider = Arc::new(MockProvider::single(server_error_response(500)));
        let (clock, _) = mock_clock();
        let cap = ApiCallCapability::with_clock(provider.clone(), no_retry_config(), clock);
        let req = ApiCallRequest::new("https://a.com/x").with_method(HttpMethod::Post);
        let resp = cap.call(&req).await.expect("returns 500 without retry");
        assert_eq!(resp.status_code, 500);
        assert_eq!(provider.calls(), 1);
    }

    #[tokio::test]
    async fn test_retry_on_provider_error_then_success() {
        // First call fails with provider error, second succeeds.
        let provider = Arc::new(MockProvider::fail_first(1));
        let (clock, _) = mock_clock();
        let cap = ApiCallCapability::with_clock(provider.clone(), default_config(), clock);
        let req = ApiCallRequest::new("https://a.com/x").with_method(HttpMethod::Post);
        let resp = cap.call(&req).await.expect("should succeed after retry");
        assert_eq!(resp.status_code, 200);
        assert_eq!(provider.calls(), 2);
        assert_eq!(provider.failures(), 1);
    }

    #[tokio::test]
    async fn test_no_retry_on_4xx() {
        // 404 should not be retried.
        let provider = Arc::new(MockProvider::single(ok_response(404, "not found")));
        let (clock, _) = mock_clock();
        let cap = ApiCallCapability::with_clock(provider.clone(), default_config(), clock);
        let req = ApiCallRequest::new("https://a.com/x").with_method(HttpMethod::Post);
        let resp = cap.call(&req).await.expect("returns 404");
        assert_eq!(resp.status_code, 404);
        assert_eq!(provider.calls(), 1, "4xx should not be retried");
    }

    // -----------------------------------------------------------------------
    // Timeout
    // -----------------------------------------------------------------------

    /// A provider that sleeps before responding.
    struct SlowProvider {
        delay_ms: u64,
    }

    #[async_trait]
    impl ApiCallProvider for SlowProvider {
        async fn call(&self, _req: &ApiCallRequest) -> Result<ApiCallResponse, PerceptionError> {
            tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
            Ok(ok_response(200, "slow"))
        }
    }

    #[tokio::test]
    async fn test_timeout_returns_timeout_error() {
        let provider = Arc::new(SlowProvider { delay_ms: 500 });
        let (clock, _) = mock_clock();
        let cap = ApiCallCapability::with_clock(
            provider.clone(),
            ApiCallConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 4,
                rate_limit_per_hour: 1000,
                timeout_ms: 10,
                max_retries: 0,
                retry_backoff_ms: 1,
            },
            clock,
        );
        let req = ApiCallRequest::new("https://a.com/x").with_method(HttpMethod::Post);
        let err = cap.call(&req).await.unwrap_err();
        assert!(matches!(err, PerceptionError::Timeout));
    }

    #[tokio::test]
    async fn test_per_request_timeout_override() {
        let provider = Arc::new(SlowProvider { delay_ms: 500 });
        let (clock, _) = mock_clock();
        // Default timeout is large, but the request overrides it to 10ms.
        let cap = ApiCallCapability::with_clock(provider.clone(), default_config(), clock);
        let req = ApiCallRequest::new("https://a.com/x")
            .with_method(HttpMethod::Post)
            .with_timeout(10);
        let err = cap.call(&req).await.unwrap_err();
        assert!(matches!(err, PerceptionError::Timeout));
    }

    // -----------------------------------------------------------------------
    // Builder
    // -----------------------------------------------------------------------

    #[test]
    fn test_request_builder() {
        let req = ApiCallRequest::new("https://api.example.com/x")
            .with_method(HttpMethod::Put)
            .with_body(b"data".to_vec())
            .with_auth_token("tok")
            .with_header("x-custom", "val")
            .with_param("q", "1")
            .with_timeout(5000);
        assert_eq!(req.method, HttpMethod::Put);
        assert_eq!(req.body, Some(b"data".to_vec()));
        assert_eq!(req.auth_token, Some("tok".into()));
        assert_eq!(req.headers.get("x-custom"), Some(&"val".into()));
        assert_eq!(req.params.get("q"), Some(&"1".into()));
        assert_eq!(req.timeout_ms, Some(5000));
    }

    #[test]
    fn test_default_config_values() {
        let cfg = ApiCallConfig::default();
        assert_eq!(cfg.cache_ttl_ms, 5 * 60 * 1000);
        assert_eq!(cfg.max_cache_entries, 128);
        assert_eq!(cfg.rate_limit_per_hour, 1000);
        assert_eq!(cfg.timeout_ms, 30_000);
        assert_eq!(cfg.max_retries, 3);
    }
}
