//! API-discover capability (Track Y5).
//!
//! Provides agent-native discovery of API specifications (OpenAPI 3.x,
//! GraphQL, gRPC, AsyncAPI) via a pluggable [`ApiDiscoverProvider`],
//! with TTL-based caching of discovered specs.
//!
//! The capability mirrors the patterns established by the web-browse
//! (Track Y2) and document-read (Track Y3) capabilities: an injectable
//! [`Clock`] drives cache TTL expiry, while a pluggable provider trait
//! keeps the discovery backend decoupled from the capability logic.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::Clock;
use crate::PerceptionError;

// ---------------------------------------------------------------------------
// Provider trait
// ---------------------------------------------------------------------------

/// A pluggable API-discovery backend that fetches and parses API specs.
#[async_trait]
pub trait ApiDiscoverProvider: Send + Sync {
    /// Discover the API specification at the requested URL.
    async fn discover(&self, req: &DiscoverRequest) -> Result<ApiSpec, PerceptionError>;
}

// ---------------------------------------------------------------------------
// Spec format
// ---------------------------------------------------------------------------

/// The format of an API specification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpecFormat {
    /// OpenAPI 3.x specification (JSON or YAML).
    OpenApi3,
    /// GraphQL schema/introspection.
    GraphQL,
    /// gRPC service reflection/proto.
    Grpc,
    /// AsyncAPI specification.
    AsyncApi,
}

impl SpecFormat {
    /// Returns the canonical lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenApi3 => "openapi3",
            Self::GraphQL => "graphql",
            Self::Grpc => "grpc",
            Self::AsyncApi => "asyncapi",
        }
    }

    /// Detect a spec format from a source URL, content-type, or extension.
    pub fn detect(source: &str) -> Option<Self> {
        let lower = source.to_ascii_lowercase();
        if lower.contains("openapi")
            || lower.ends_with(".openapi.json")
            || lower.ends_with(".openapi.yaml")
        {
            return Some(Self::OpenApi3);
        }
        if lower.contains("swagger") {
            return Some(Self::OpenApi3);
        }
        if lower.contains("graphql") || lower.ends_with(".graphql") || lower.ends_with(".gql") {
            return Some(Self::GraphQL);
        }
        if lower.contains("grpc") || lower.ends_with(".proto") {
            return Some(Self::Grpc);
        }
        if lower.contains("asyncapi") || lower.ends_with(".asyncapi.json") {
            return Some(Self::AsyncApi);
        }
        None
    }
}

// ---------------------------------------------------------------------------
// API endpoint & schema
// ---------------------------------------------------------------------------

/// A single discovered API endpoint.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApiEndpoint {
    /// The endpoint path (e.g. `/users/{id}`).
    pub path: String,
    /// The HTTP method (e.g. `GET`, `POST`).
    pub method: String,
    /// Parameter definitions (name → description/schema).
    #[serde(default)]
    pub parameters: HashMap<String, String>,
    /// The response schema (JSON schema string or reference).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_schema: Option<String>,
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl ApiEndpoint {
    /// Create a new endpoint with the given path and method.
    pub fn new(path: impl Into<String>, method: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            method: method.into(),
            parameters: HashMap::new(),
            response_schema: None,
            description: None,
        }
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Set the response schema.
    pub fn with_response_schema(mut self, schema: impl Into<String>) -> Self {
        self.response_schema = Some(schema.into());
        self
    }

    /// Add a parameter.
    pub fn with_parameter(mut self, name: impl Into<String>, schema: impl Into<String>) -> Self {
        self.parameters.insert(name.into(), schema.into());
        self
    }
}

/// A discovered API specification.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApiSpec {
    /// Discovered endpoints.
    pub endpoints: Vec<ApiEndpoint>,
    /// Named schemas (name → JSON schema string).
    #[serde(default)]
    pub schemas: HashMap<String, String>,
    /// Supported authentication methods.
    #[serde(default)]
    pub auth_methods: Vec<String>,
    /// API version string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Base URL for the API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// The detected spec format.
    pub format: SpecFormat,
    /// The source URL the spec was discovered from.
    pub source_url: String,
}

impl ApiSpec {
    /// Create a new empty spec for the given source and format.
    pub fn new(source_url: impl Into<String>, format: SpecFormat) -> Self {
        Self {
            endpoints: Vec::new(),
            schemas: HashMap::new(),
            auth_methods: Vec::new(),
            version: None,
            base_url: None,
            format,
            source_url: source_url.into(),
        }
    }

    /// Returns `true` if the spec has no endpoints and no schemas.
    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty() && self.schemas.is_empty()
    }

    /// Find all endpoints matching the given path prefix.
    pub fn endpoints_by_path_prefix(&self, prefix: &str) -> Vec<&ApiEndpoint> {
        self.endpoints
            .iter()
            .filter(|e| e.path.starts_with(prefix))
            .collect()
    }

    /// Find all endpoints using the given HTTP method.
    pub fn endpoints_by_method(&self, method: &str) -> Vec<&ApiEndpoint> {
        let upper = method.to_ascii_uppercase();
        self.endpoints
            .iter()
            .filter(|e| e.method.to_ascii_uppercase() == upper)
            .collect()
    }

    /// Serialize the spec to a JSON string.
    pub fn to_json(&self) -> Result<String, PerceptionError> {
        serde_json::to_string(self).map_err(|e| PerceptionError::Provider(e.to_string()))
    }

    /// Deserialize a spec from a JSON string.
    pub fn from_json(s: &str) -> Result<Self, PerceptionError> {
        serde_json::from_str(s).map_err(|e| PerceptionError::Provider(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

/// A discovery request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoverRequest {
    /// The URL to discover the API spec from.
    pub url: String,
    /// Optional format hint. When `None`, the format is auto-detected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format_hint: Option<SpecFormat>,
    /// Optional auth token for protected spec endpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
}

impl DiscoverRequest {
    /// Create a new discovery request for the given URL.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            format_hint: None,
            auth_token: None,
        }
    }

    /// Set the format hint.
    pub fn with_format(mut self, format: SpecFormat) -> Self {
        self.format_hint = Some(format);
        self
    }

    /// Set the auth token.
    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    /// Resolve the effective format: the explicit hint, or the detected one.
    pub fn effective_format(&self) -> Option<SpecFormat> {
        self.format_hint.or_else(|| SpecFormat::detect(&self.url))
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for the API-discover capability.
#[derive(Clone, Debug)]
pub struct ApiDiscoverConfig {
    /// Cache time-to-live in milliseconds.
    pub cache_ttl_ms: u64,
    /// Maximum number of cache entries before eviction.
    pub max_cache_entries: usize,
    /// Discovery timeout in milliseconds.
    pub timeout_ms: u64,
}

impl Default for ApiDiscoverConfig {
    fn default() -> Self {
        Self {
            cache_ttl_ms: 60 * 60 * 1000, // 1 hour (specs change rarely)
            max_cache_entries: 64,
            timeout_ms: 30_000,
        }
    }
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

/// A cached discovered spec.
struct CacheEntry {
    spec: ApiSpec,
    /// Unix-millisecond timestamp when the entry was stored.
    timestamp: u64,
}

// ---------------------------------------------------------------------------
// Capability
// ---------------------------------------------------------------------------

/// The API-discover capability: discovers and caches API specifications.
pub struct ApiDiscoverCapability {
    provider: Arc<dyn ApiDiscoverProvider>,
    cache: RwLock<HashMap<String, CacheEntry>>,
    config: ApiDiscoverConfig,
    clock: Clock,
}

impl ApiDiscoverCapability {
    /// Create a new API-discover capability with the default system clock.
    pub fn new(provider: Arc<dyn ApiDiscoverProvider>, config: ApiDiscoverConfig) -> Self {
        Self {
            provider,
            cache: RwLock::new(HashMap::new()),
            config,
            clock: super::default_clock(),
        }
    }

    /// Create a new API-discover capability with an injected clock (for testing).
    pub fn with_clock(
        provider: Arc<dyn ApiDiscoverProvider>,
        config: ApiDiscoverConfig,
        clock: Clock,
    ) -> Self {
        Self {
            provider,
            cache: RwLock::new(HashMap::new()),
            config,
            clock,
        }
    }

    /// Discover an API specification, consulting the cache first.
    pub async fn discover(&self, request: &DiscoverRequest) -> Result<ApiSpec, PerceptionError> {
        if request.url.is_empty() {
            return Err(PerceptionError::InvalidField {
                field: "url",
                message: "url must not be empty".into(),
            });
        }

        // Cache lookup keyed by URL + format.
        let cache_key = self.cache_key(request);
        if let Some(cached) = self.cache_get(&cache_key) {
            return Ok(cached);
        }

        // Fetch from the provider with timeout enforcement.
        let spec = match tokio::time::timeout(
            std::time::Duration::from_millis(self.config.timeout_ms),
            self.provider.discover(request),
        )
        .await
        {
            Ok(r) => r?,
            Err(_) => return Err(PerceptionError::Timeout),
        };

        // Store in cache.
        self.cache_put(&cache_key, spec.clone());

        Ok(spec)
    }

    /// Build a deterministic cache key from the request.
    fn cache_key(&self, request: &DiscoverRequest) -> String {
        let format = request
            .effective_format()
            .map(SpecFormat::as_str)
            .unwrap_or("auto");
        format!("{}|{}", request.url, format)
    }

    /// Look up a key in the cache, returning a clone if present and fresh.
    fn cache_get(&self, key: &str) -> Option<ApiSpec> {
        let now_ms = (self.clock)();
        let cache = self.cache.read().expect("cache lock poisoned");
        let entry = cache.get(key)?;
        if now_ms.saturating_sub(entry.timestamp) >= self.config.cache_ttl_ms {
            // Expired.
            return None;
        }
        Some(entry.spec.clone())
    }

    /// Store a spec in the cache, evicting expired entries if the cache
    /// is full.
    fn cache_put(&self, key: &str, spec: ApiSpec) {
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
                spec,
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

// ---------------------------------------------------------------------------
// OpenAPI 3.x parsing (basic structure)
// ---------------------------------------------------------------------------

/// Parse a basic OpenAPI 3.x JSON document into an [`ApiSpec`].
///
/// This performs a lightweight structural parse: it extracts the API
/// version, base URL (servers[0].url), security schemes (auth methods),
/// named schemas, and endpoint paths with their HTTP methods. Full JSON
/// schema validation is delegated to the provider backend.
pub fn parse_openapi3(source_url: &str, json: &str) -> Result<ApiSpec, PerceptionError> {
    let root: serde_json::Value =
        serde_json::from_str(json).map_err(|e| PerceptionError::Provider(e.to_string()))?;

    let mut spec = ApiSpec::new(source_url, SpecFormat::OpenApi3);

    // Version.
    if let Some(version) = root
        .get("info")
        .and_then(|i| i.get("version"))
        .and_then(|v| v.as_str())
    {
        spec.version = Some(version.to_string());
    }

    // Base URL from servers[0].url.
    if let Some(url) = root
        .get("servers")
        .and_then(|s| s.as_array())
        .and_then(|arr| arr.first())
        .and_then(|srv| srv.get("url"))
        .and_then(|u| u.as_str())
    {
        spec.base_url = Some(url.to_string());
    }

    // Security schemes → auth methods.
    if let Some(schemes) = root
        .get("components")
        .and_then(|c| c.get("securitySchemes"))
        .and_then(|s| s.as_object())
    {
        for (name, _scheme) in schemes {
            spec.auth_methods.push(name.clone());
        }
    }

    // Named schemas.
    if let Some(schemas) = root
        .get("components")
        .and_then(|c| c.get("schemas"))
        .and_then(|s| s.as_object())
    {
        for (name, schema) in schemas {
            spec.schemas.insert(name.clone(), schema.to_string());
        }
    }

    // Paths → endpoints.
    if let Some(paths) = root.get("paths").and_then(|p| p.as_object()) {
        for (path, item) in paths {
            if let Some(obj) = item.as_object() {
                for method in ["get", "post", "put", "delete", "patch"] {
                    if obj.contains_key(method) {
                        let mut ep = ApiEndpoint::new(path.clone(), method.to_ascii_uppercase());
                        if let Some(op) = obj.get(method).and_then(|o| o.as_object()) {
                            if let Some(desc) = op.get("description").and_then(|d| d.as_str()) {
                                ep = ep.with_description(desc);
                            } else if let Some(summary) = op.get("summary").and_then(|d| d.as_str())
                            {
                                ep = ep.with_description(summary);
                            }
                            // Parameters.
                            if let Some(params) = op.get("parameters").and_then(|p| p.as_array()) {
                                for param in params {
                                    let pname = param
                                        .get("name")
                                        .and_then(|n| n.as_str())
                                        .unwrap_or("unknown");
                                    let ptype = param
                                        .get("schema")
                                        .map(|s| s.to_string())
                                        .unwrap_or_else(|| "string".to_string());
                                    ep = ep.with_parameter(pname, ptype);
                                }
                            }
                            // Response schema (200/2xx).
                            if let Some(responses) = op.get("responses").and_then(|r| r.as_object())
                            {
                                if let Some(resp) =
                                    responses.get("200").or_else(|| responses.get("default"))
                                {
                                    if let Some(schema) = resp
                                        .get("content")
                                        .and_then(|c| c.get("application/json"))
                                        .and_then(|j| j.get("schema"))
                                    {
                                        ep = ep.with_response_schema(schema.to_string());
                                    }
                                }
                            }
                        }
                        spec.endpoints.push(ep);
                    }
                }
            }
        }
    }

    Ok(spec)
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

    fn sample_spec(url: &str) -> ApiSpec {
        let mut spec = ApiSpec::new(url, SpecFormat::OpenApi3);
        spec.version = Some("1.0.0".into());
        spec.base_url = Some("https://api.example.com".into());
        spec.endpoints.push(
            ApiEndpoint::new("/users", "GET")
                .with_description("List users")
                .with_parameter("limit", "integer"),
        );
        spec.endpoints.push(ApiEndpoint::new("/users/{id}", "GET"));
        spec.schemas
            .insert("User".into(), "{\"type\":\"object\"}".into());
        spec.auth_methods.push("bearerAuth".into());
        spec
    }

    /// A mock provider returning a canned spec.
    struct MockProvider {
        spec: ApiSpec,
        call_count: AtomicU64,
        fail: bool,
    }

    impl MockProvider {
        fn new(spec: ApiSpec) -> Self {
            Self {
                spec,
                call_count: AtomicU64::new(0),
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                spec: ApiSpec::new("x", SpecFormat::OpenApi3),
                call_count: AtomicU64::new(0),
                fail: true,
            }
        }

        fn calls(&self) -> u64 {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ApiDiscoverProvider for MockProvider {
        async fn discover(&self, _req: &DiscoverRequest) -> Result<ApiSpec, PerceptionError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(PerceptionError::Provider("mock discover failed".into()));
            }
            Ok(self.spec.clone())
        }
    }

    fn default_config() -> ApiDiscoverConfig {
        ApiDiscoverConfig {
            cache_ttl_ms: 60_000,
            max_cache_entries: 4,
            timeout_ms: 5_000,
        }
    }

    // -----------------------------------------------------------------------
    // SpecFormat
    // -----------------------------------------------------------------------

    #[test]
    fn test_spec_format_as_str() {
        assert_eq!(SpecFormat::OpenApi3.as_str(), "openapi3");
        assert_eq!(SpecFormat::GraphQL.as_str(), "graphql");
        assert_eq!(SpecFormat::Grpc.as_str(), "grpc");
        assert_eq!(SpecFormat::AsyncApi.as_str(), "asyncapi");
    }

    #[test]
    fn test_spec_format_detect_openapi() {
        assert_eq!(
            SpecFormat::detect("https://api.example.com/openapi.json"),
            Some(SpecFormat::OpenApi3)
        );
        assert_eq!(
            SpecFormat::detect("https://api.example.com/swagger.json"),
            Some(SpecFormat::OpenApi3)
        );
    }

    #[test]
    fn test_spec_format_detect_graphql() {
        assert_eq!(
            SpecFormat::detect("https://api.example.com/schema.graphql"),
            Some(SpecFormat::GraphQL)
        );
        assert_eq!(
            SpecFormat::detect("https://api.example.com/api.gql"),
            Some(SpecFormat::GraphQL)
        );
    }

    #[test]
    fn test_spec_format_detect_grpc() {
        assert_eq!(
            SpecFormat::detect("https://api.example.com/service.proto"),
            Some(SpecFormat::Grpc)
        );
    }

    #[test]
    fn test_spec_format_detect_asyncapi() {
        assert_eq!(
            SpecFormat::detect("https://api.example.com/asyncapi.json"),
            Some(SpecFormat::AsyncApi)
        );
    }

    #[test]
    fn test_spec_format_detect_unknown() {
        assert_eq!(
            SpecFormat::detect("https://api.example.com/data.json"),
            None
        );
        assert_eq!(SpecFormat::detect("https://example.com"), None);
    }

    // -----------------------------------------------------------------------
    // ApiEndpoint
    // -----------------------------------------------------------------------

    #[test]
    fn test_api_endpoint_builder() {
        let ep = ApiEndpoint::new("/users/{id}", "GET")
            .with_description("Get a user")
            .with_response_schema("{\"$ref\":\"#/components/schemas/User\"}")
            .with_parameter("id", "integer");
        assert_eq!(ep.path, "/users/{id}");
        assert_eq!(ep.method, "GET");
        assert_eq!(ep.description, Some("Get a user".into()));
        assert_eq!(ep.parameters.get("id"), Some(&"integer".into()));
        assert!(ep.response_schema.is_some());
    }

    // -----------------------------------------------------------------------
    // ApiSpec
    // -----------------------------------------------------------------------

    #[test]
    fn test_api_spec_new() {
        let spec = ApiSpec::new("https://api.example.com/openapi.json", SpecFormat::OpenApi3);
        assert_eq!(spec.format, SpecFormat::OpenApi3);
        assert_eq!(spec.source_url, "https://api.example.com/openapi.json");
        assert!(spec.is_empty());
        assert!(spec.endpoints.is_empty());
        assert!(spec.schemas.is_empty());
    }

    #[test]
    fn test_api_spec_is_empty() {
        let mut spec = ApiSpec::new("u", SpecFormat::OpenApi3);
        assert!(spec.is_empty());
        spec.endpoints.push(ApiEndpoint::new("/x", "GET"));
        assert!(!spec.is_empty());
    }

    #[test]
    fn test_api_spec_endpoints_by_path_prefix() {
        let spec = sample_spec("u");
        let users = spec.endpoints_by_path_prefix("/users");
        assert_eq!(users.len(), 2);
        let other = spec.endpoints_by_path_prefix("/orders");
        assert!(other.is_empty());
    }

    #[test]
    fn test_api_spec_endpoints_by_method() {
        let spec = sample_spec("u");
        let gets = spec.endpoints_by_method("GET");
        assert_eq!(gets.len(), 2);
        let posts = spec.endpoints_by_method("POST");
        assert!(posts.is_empty());
        // Case-insensitive.
        assert_eq!(spec.endpoints_by_method("get").len(), 2);
    }

    #[test]
    fn test_api_spec_json_roundtrip() {
        let spec = sample_spec("https://api.example.com/openapi.json");
        let json = spec.to_json().expect("serialize");
        let parsed = ApiSpec::from_json(&json).expect("deserialize");
        assert_eq!(parsed, spec);
    }

    // -----------------------------------------------------------------------
    // DiscoverRequest
    // -----------------------------------------------------------------------

    #[test]
    fn test_discover_request_builder() {
        let req = DiscoverRequest::new("https://api.example.com/openapi.json")
            .with_format(SpecFormat::OpenApi3)
            .with_auth_token("tok");
        assert_eq!(req.url, "https://api.example.com/openapi.json");
        assert_eq!(req.format_hint, Some(SpecFormat::OpenApi3));
        assert_eq!(req.auth_token, Some("tok".into()));
    }

    #[test]
    fn test_discover_request_effective_format_hint() {
        let req = DiscoverRequest::new("https://api.example.com/data.json")
            .with_format(SpecFormat::GraphQL);
        assert_eq!(req.effective_format(), Some(SpecFormat::GraphQL));
    }

    #[test]
    fn test_discover_request_effective_format_detected() {
        let req = DiscoverRequest::new("https://api.example.com/openapi.json");
        assert_eq!(req.effective_format(), Some(SpecFormat::OpenApi3));
    }

    #[test]
    fn test_discover_request_effective_format_none() {
        let req = DiscoverRequest::new("https://api.example.com/unknown");
        assert_eq!(req.effective_format(), None);
    }

    // -----------------------------------------------------------------------
    // Capability: basic discover
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_discover_success() {
        let provider = Arc::new(MockProvider::new(sample_spec("u")));
        let (clock, _) = mock_clock();
        let cap = ApiDiscoverCapability::with_clock(provider.clone(), default_config(), clock);
        let spec = cap
            .discover(&DiscoverRequest::new(
                "https://api.example.com/openapi.json",
            ))
            .await
            .expect("discover ok");
        assert_eq!(spec.endpoints.len(), 2);
        assert_eq!(spec.version, Some("1.0.0".into()));
        assert_eq!(provider.calls(), 1);
    }

    #[tokio::test]
    async fn test_discover_empty_url_error() {
        let provider = Arc::new(MockProvider::new(sample_spec("u")));
        let (clock, _) = mock_clock();
        let cap = ApiDiscoverCapability::with_clock(provider.clone(), default_config(), clock);
        let err = cap.discover(&DiscoverRequest::new("")).await.unwrap_err();
        assert!(matches!(
            err,
            PerceptionError::InvalidField { field: "url", .. }
        ));
        assert_eq!(provider.calls(), 0);
    }

    #[tokio::test]
    async fn test_discover_provider_error() {
        let provider = Arc::new(MockProvider::failing());
        let (clock, _) = mock_clock();
        let cap = ApiDiscoverCapability::with_clock(provider.clone(), default_config(), clock);
        let err = cap
            .discover(&DiscoverRequest::new(
                "https://api.example.com/openapi.json",
            ))
            .await
            .unwrap_err();
        assert!(matches!(err, PerceptionError::Provider(_)));
    }

    // -----------------------------------------------------------------------
    // Caching
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_cache_hit() {
        let provider = Arc::new(MockProvider::new(sample_spec("u")));
        let (clock, _) = mock_clock();
        let cap = ApiDiscoverCapability::with_clock(provider.clone(), default_config(), clock);
        let req = DiscoverRequest::new("https://api.example.com/openapi.json");
        let _ = cap.discover(&req).await.expect("first");
        let _ = cap.discover(&req).await.expect("second");
        assert_eq!(provider.calls(), 1, "second discover should hit cache");
    }

    #[tokio::test]
    async fn test_cache_miss_different_url() {
        let provider = Arc::new(MockProvider::new(sample_spec("u")));
        let (clock, _) = mock_clock();
        let cap = ApiDiscoverCapability::with_clock(provider.clone(), default_config(), clock);
        let _ = cap
            .discover(&DiscoverRequest::new("https://a.com/openapi.json"))
            .await;
        let _ = cap
            .discover(&DiscoverRequest::new("https://b.com/openapi.json"))
            .await;
        assert_eq!(provider.calls(), 2);
    }

    #[tokio::test]
    async fn test_cache_miss_different_format() {
        let provider = Arc::new(MockProvider::new(sample_spec("u")));
        let (clock, _) = mock_clock();
        let cap = ApiDiscoverCapability::with_clock(provider.clone(), default_config(), clock);
        let r1 =
            DiscoverRequest::new("https://api.example.com/x").with_format(SpecFormat::OpenApi3);
        let r2 = DiscoverRequest::new("https://api.example.com/x").with_format(SpecFormat::GraphQL);
        let _ = cap.discover(&r1).await;
        let _ = cap.discover(&r2).await;
        assert_eq!(provider.calls(), 2, "different format → cache miss");
    }

    #[tokio::test]
    async fn test_cache_ttl_expiration() {
        let provider = Arc::new(MockProvider::new(sample_spec("u")));
        let (clock, cell) = mock_clock();
        let cap = ApiDiscoverCapability::with_clock(
            provider.clone(),
            ApiDiscoverConfig {
                cache_ttl_ms: 1_000,
                max_cache_entries: 4,
                timeout_ms: 5_000,
            },
            clock,
        );
        let req = DiscoverRequest::new("https://api.example.com/openapi.json");
        let _ = cap.discover(&req).await.expect("first");
        assert_eq!(provider.calls(), 1);
        cell.store(1_700_000_000_000 + 2_000, Ordering::SeqCst);
        let _ = cap.discover(&req).await.expect("second");
        assert_eq!(provider.calls(), 2, "expired entry should refetch");
    }

    #[tokio::test]
    async fn test_cache_eviction_max_entries() {
        let provider = Arc::new(MockProvider::new(sample_spec("u")));
        let (clock, cell) = mock_clock();
        let cap = ApiDiscoverCapability::with_clock(
            provider.clone(),
            ApiDiscoverConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 2,
                timeout_ms: 5_000,
            },
            clock,
        );
        let _ = cap.discover(&DiscoverRequest::new("https://a.com/x")).await;
        cell.fetch_add(1000, Ordering::SeqCst);
        let _ = cap.discover(&DiscoverRequest::new("https://b.com/x")).await;
        cell.fetch_add(1000, Ordering::SeqCst);
        let _ = cap.discover(&DiscoverRequest::new("https://c.com/x")).await;
        assert_eq!(cap.cache_len(), 2, "cache should be at capacity");
    }

    #[tokio::test]
    async fn test_evict_expired_public() {
        let provider = Arc::new(MockProvider::new(sample_spec("u")));
        let (clock, cell) = mock_clock();
        let cap = ApiDiscoverCapability::with_clock(
            provider.clone(),
            ApiDiscoverConfig {
                cache_ttl_ms: 1_000,
                max_cache_entries: 4,
                timeout_ms: 5_000,
            },
            clock,
        );
        let _ = cap.discover(&DiscoverRequest::new("https://a.com/x")).await;
        assert_eq!(cap.cache_len(), 1);
        cell.store(1_700_000_000_000 + 2_000, Ordering::SeqCst);
        cap.evict_expired();
        assert_eq!(cap.cache_len(), 0);
    }

    // -----------------------------------------------------------------------
    // Timeout
    // -----------------------------------------------------------------------

    /// A provider that sleeps before responding.
    struct SlowProvider;

    #[async_trait]
    impl ApiDiscoverProvider for SlowProvider {
        async fn discover(&self, _req: &DiscoverRequest) -> Result<ApiSpec, PerceptionError> {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            Ok(ApiSpec::new("u", SpecFormat::OpenApi3))
        }
    }

    #[tokio::test]
    async fn test_timeout_returns_timeout_error() {
        let provider = Arc::new(SlowProvider);
        let (clock, _) = mock_clock();
        let cap = ApiDiscoverCapability::with_clock(
            provider.clone(),
            ApiDiscoverConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 4,
                timeout_ms: 10,
            },
            clock,
        );
        let err = cap
            .discover(&DiscoverRequest::new("https://a.com/x"))
            .await
            .unwrap_err();
        assert!(matches!(err, PerceptionError::Timeout));
    }

    // -----------------------------------------------------------------------
    // OpenAPI 3.x parsing
    // -----------------------------------------------------------------------

    fn sample_openapi_json() -> String {
        r##"{
            "openapi": "3.0.0",
            "info": { "title": "Sample API", "version": "2.1.0" },
            "servers": [ { "url": "https://api.example.com/v2" } ],
            "components": {
                "securitySchemes": {
                    "bearerAuth": { "type": "http", "scheme": "bearer" },
                    "apiKey": { "type": "apiKey", "in": "header" }
                },
                "schemas": {
                    "User": { "type": "object", "properties": { "id": { "type": "integer" } } },
                    "Error": { "type": "object" }
                }
            },
            "paths": {
                "/users": {
                    "get": {
                        "summary": "List users",
                        "parameters": [ { "name": "limit", "schema": { "type": "integer" } } ],
                        "responses": {
                            "200": {
                                "content": {
                                    "application/json": {
                                        "schema": { "$ref": "#/components/schemas/User" }
                                    }
                                }
                            }
                        }
                    },
                    "post": {
                        "description": "Create a user",
                        "responses": { "201": { "description": "Created" } }
                    }
                },
                "/users/{id}": {
                    "get": {
                        "parameters": [ { "name": "id", "schema": { "type": "integer" } } ],
                        "responses": { "200": { "description": "OK" } }
                    },
                    "delete": {
                        "responses": { "204": { "description": "No content" } }
                    }
                }
            }
        }"##
        .to_string()
    }

    #[test]
    fn test_parse_openapi3_basic() {
        let spec = parse_openapi3(
            "https://api.example.com/openapi.json",
            &sample_openapi_json(),
        )
        .expect("parse ok");
        assert_eq!(spec.format, SpecFormat::OpenApi3);
        assert_eq!(spec.source_url, "https://api.example.com/openapi.json");
        assert_eq!(spec.version, Some("2.1.0".into()));
        assert_eq!(spec.base_url, Some("https://api.example.com/v2".into()));
    }

    #[test]
    fn test_parse_openapi3_endpoints() {
        let spec = parse_openapi3("u", &sample_openapi_json()).expect("parse ok");
        assert_eq!(spec.endpoints.len(), 4);
        let gets = spec.endpoints_by_method("GET");
        assert_eq!(gets.len(), 2);
        let posts = spec.endpoints_by_method("POST");
        assert_eq!(posts.len(), 1);
        let deletes = spec.endpoints_by_method("DELETE");
        assert_eq!(deletes.len(), 1);
    }

    #[test]
    fn test_parse_openapi3_endpoint_details() {
        let spec = parse_openapi3("u", &sample_openapi_json()).expect("parse ok");
        let users_get = spec
            .endpoints
            .iter()
            .find(|e| e.path == "/users" && e.method == "GET")
            .expect("found");
        assert_eq!(users_get.description, Some("List users".into()));
        assert!(users_get.parameters.contains_key("limit"));
        assert!(users_get.response_schema.is_some());
    }

    #[test]
    fn test_parse_openapi3_schemas() {
        let spec = parse_openapi3("u", &sample_openapi_json()).expect("parse ok");
        assert_eq!(spec.schemas.len(), 2);
        assert!(spec.schemas.contains_key("User"));
        assert!(spec.schemas.contains_key("Error"));
    }

    #[test]
    fn test_parse_openapi3_auth_methods() {
        let spec = parse_openapi3("u", &sample_openapi_json()).expect("parse ok");
        assert_eq!(spec.auth_methods.len(), 2);
        assert!(spec.auth_methods.contains(&"bearerAuth".into()));
        assert!(spec.auth_methods.contains(&"apiKey".into()));
    }

    #[test]
    fn test_parse_openapi3_invalid_json() {
        let err = parse_openapi3("u", "not json").unwrap_err();
        assert!(matches!(err, PerceptionError::Provider(_)));
    }

    #[test]
    fn test_parse_openapi3_empty_paths() {
        let json = r#"{ "openapi": "3.0.0", "info": { "version": "1.0" } }"#;
        let spec = parse_openapi3("u", json).expect("parse ok");
        assert!(spec.endpoints.is_empty());
        assert_eq!(spec.version, Some("1.0".into()));
        assert!(spec.base_url.is_none());
    }

    #[test]
    fn test_parse_openapi3_post_description_fallback() {
        let spec = parse_openapi3("u", &sample_openapi_json()).expect("parse ok");
        let post = spec
            .endpoints
            .iter()
            .find(|e| e.path == "/users" && e.method == "POST")
            .expect("found");
        assert_eq!(post.description, Some("Create a user".into()));
    }

    #[test]
    fn test_default_config_values() {
        let cfg = ApiDiscoverConfig::default();
        assert_eq!(cfg.cache_ttl_ms, 60 * 60 * 1000);
        assert_eq!(cfg.max_cache_entries, 64);
        assert_eq!(cfg.timeout_ms, 30_000);
    }
}
