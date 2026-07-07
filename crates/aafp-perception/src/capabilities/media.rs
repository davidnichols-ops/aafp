//! Media capability (Track Y7): OCR and transcription.
//!
//! Provides agent-native optical character recognition (OCR) and audio
//! transcription via a pluggable [`MediaProvider`], with a TTL-based
//! result cache keyed on a content hash of the media bytes and
//! per-operation rate limiting.
//!
//! The capability mirrors the patterns established by the web-browse
//! (Track Y2) and API-call (Track Y4) capabilities: an injectable
//! [`Clock`] drives both cache TTL expiry and the fixed-window
//! per-operation rate limiter, while a pluggable provider trait keeps
//! the OCR/transcription backend (e.g. a local model, a cloud API, or
//! a remote inference service) decoupled from the capability logic.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::Clock;
use crate::PerceptionError;

// ---------------------------------------------------------------------------
// Provider trait
// ---------------------------------------------------------------------------

/// A pluggable media backend that performs OCR and transcription.
#[async_trait]
pub trait MediaProvider: Send + Sync {
    /// Transcribe audio bytes into text.
    async fn transcribe(
        &self,
        req: &TranscribeRequest,
    ) -> Result<TranscribeResponse, PerceptionError>;

    /// Perform optical character recognition on image bytes.
    async fn ocr(&self, req: &OcrRequest) -> Result<OcrResponse, PerceptionError>;
}

// ---------------------------------------------------------------------------
// Media formats
// ---------------------------------------------------------------------------

/// An audio container format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AudioFormat {
    /// WAV (RIFF/WAVE).
    Wav,
    /// MP3.
    Mp3,
    /// OGG (Vorbis/Opus).
    Ogg,
    /// FLAC.
    Flac,
}

impl AudioFormat {
    /// Returns the canonical uppercase string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wav => "WAV",
            Self::Mp3 => "MP3",
            Self::Ogg => "OGG",
            Self::Flac => "FLAC",
        }
    }
}

impl std::fmt::Display for AudioFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for AudioFormat {
    type Err = PerceptionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "WAV" | "WAVE" => Ok(Self::Wav),
            "MP3" => Ok(Self::Mp3),
            "OGG" => Ok(Self::Ogg),
            "FLAC" => Ok(Self::Flac),
            other => Err(PerceptionError::InvalidField {
                field: "format",
                message: format!("unknown audio format: {other}"),
            }),
        }
    }
}

/// An image container format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ImageFormat {
    /// PNG.
    Png,
    /// JPEG.
    Jpeg,
    /// WebP.
    Webp,
    /// TIFF.
    Tiff,
}

impl ImageFormat {
    /// Returns the canonical uppercase string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Png => "PNG",
            Self::Jpeg => "JPEG",
            Self::Webp => "WEBP",
            Self::Tiff => "TIFF",
        }
    }
}

impl std::fmt::Display for ImageFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ImageFormat {
    type Err = PerceptionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "PNG" => Ok(Self::Png),
            "JPEG" | "JPG" => Ok(Self::Jpeg),
            "WEBP" => Ok(Self::Webp),
            "TIFF" | "TIF" => Ok(Self::Tiff),
            other => Err(PerceptionError::InvalidField {
                field: "format",
                message: format!("unknown image format: {other}"),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Transcription
// ---------------------------------------------------------------------------

/// A timestamped text segment within a transcription.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TextSegment {
    /// The transcribed text for this segment.
    pub text: String,
    /// Segment start time in seconds.
    pub start_time: f64,
    /// Segment end time in seconds.
    pub end_time: f64,
    /// Confidence score in `[0.0, 1.0]`.
    pub confidence: f32,
}

impl TextSegment {
    /// Create a new text segment.
    pub fn new(text: impl Into<String>, start_time: f64, end_time: f64, confidence: f32) -> Self {
        Self {
            text: text.into(),
            start_time,
            end_time,
            confidence,
        }
    }

    /// Returns the segment duration in seconds.
    pub fn duration(&self) -> f64 {
        self.end_time - self.start_time
    }
}

/// A transcription request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TranscribeRequest {
    /// Raw audio bytes.
    pub audio_data: Vec<u8>,
    /// Audio container format.
    pub format: AudioFormat,
    /// Optional BCP-47 language hint (e.g. `"en-US"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language_hint: Option<String>,
    /// Optional model identifier hint (e.g. `"whisper-large-v3"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_hint: Option<String>,
}

impl TranscribeRequest {
    /// Create a new transcription request.
    pub fn new(audio_data: Vec<u8>, format: AudioFormat) -> Self {
        Self {
            audio_data,
            format,
            language_hint: None,
            model_hint: None,
        }
    }

    /// Set the language hint.
    pub fn with_language(mut self, lang: impl Into<String>) -> Self {
        self.language_hint = Some(lang.into());
        self
    }

    /// Set the model hint.
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model_hint = Some(model.into());
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

/// A transcription response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TranscribeResponse {
    /// The full transcribed text.
    pub text: String,
    /// Timestamped segments (may be empty if the provider does not
    /// produce segment-level timing).
    #[serde(default)]
    pub segments: Vec<TextSegment>,
    /// Overall confidence score in `[0.0, 1.0]`.
    pub confidence: f32,
    /// The detected language (BCP-47 tag, if known).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language_detected: Option<String>,
    /// Total audio duration in seconds.
    pub duration_secs: f64,
}

impl TranscribeResponse {
    /// Create a new transcription response.
    pub fn new(text: impl Into<String>, confidence: f32, duration_secs: f64) -> Self {
        Self {
            text: text.into(),
            segments: Vec::new(),
            confidence,
            language_detected: None,
            duration_secs,
        }
    }

    /// Returns `true` if the response includes segment-level timing.
    pub fn has_segments(&self) -> bool {
        !self.segments.is_empty()
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
// OCR
// ---------------------------------------------------------------------------

/// A text block with a bounding box within an image.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TextBlock {
    /// The recognized text for this block.
    pub text: String,
    /// X coordinate of the bounding box top-left corner (in pixels).
    pub x: u32,
    /// Y coordinate of the bounding box top-left corner (in pixels).
    pub y: u32,
    /// Width of the bounding box (in pixels).
    pub width: u32,
    /// Height of the bounding box (in pixels).
    pub height: u32,
    /// Confidence score in `[0.0, 1.0]`.
    pub confidence: f32,
}

impl TextBlock {
    /// Create a new text block.
    pub fn new(
        text: impl Into<String>,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        confidence: f32,
    ) -> Self {
        Self {
            text: text.into(),
            x,
            y,
            width,
            height,
            confidence,
        }
    }

    /// Returns the area of the bounding box in square pixels.
    pub fn area(&self) -> u64 {
        u64::from(self.width) * u64::from(self.height)
    }
}

/// An OCR request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OcrRequest {
    /// Raw image bytes.
    pub image_data: Vec<u8>,
    /// Image container format.
    pub format: ImageFormat,
    /// Optional BCP-47 language hint (e.g. `"eng"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language_hint: Option<String>,
    /// Optional DPI hint for the image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpi_hint: Option<u32>,
}

impl OcrRequest {
    /// Create a new OCR request.
    pub fn new(image_data: Vec<u8>, format: ImageFormat) -> Self {
        Self {
            image_data,
            format,
            language_hint: None,
            dpi_hint: None,
        }
    }

    /// Set the language hint.
    pub fn with_language(mut self, lang: impl Into<String>) -> Self {
        self.language_hint = Some(lang.into());
        self
    }

    /// Set the DPI hint.
    pub fn with_dpi(mut self, dpi: u32) -> Self {
        self.dpi_hint = Some(dpi);
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

/// An OCR response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OcrResponse {
    /// The full recognized text.
    pub text: String,
    /// Text blocks with bounding boxes (may be empty if the provider
    /// does not produce block-level layout).
    #[serde(default)]
    pub blocks: Vec<TextBlock>,
    /// Overall confidence score in `[0.0, 1.0]`.
    pub confidence: f32,
    /// Number of pages recognized (default 1).
    pub page_count: u32,
}

impl OcrResponse {
    /// Create a new OCR response.
    pub fn new(text: impl Into<String>, confidence: f32) -> Self {
        Self {
            text: text.into(),
            blocks: Vec::new(),
            confidence,
            page_count: 1,
        }
    }

    /// Returns `true` if the response includes block-level layout.
    pub fn has_blocks(&self) -> bool {
        !self.blocks.is_empty()
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
// Config
// ---------------------------------------------------------------------------

/// Configuration for the media capability.
#[derive(Clone, Debug)]
pub struct MediaConfig {
    /// Cache time-to-live in milliseconds (caches results by content hash
    /// of the media bytes).
    pub cache_ttl_ms: u64,
    /// Maximum number of cache entries before eviction.
    pub max_cache_entries: usize,
    /// Maximum transcriptions allowed per minute.
    pub transcribe_rate_limit_per_minute: u32,
    /// Maximum OCR operations allowed per minute.
    pub ocr_rate_limit_per_minute: u32,
    /// Default operation timeout in milliseconds.
    pub timeout_ms: u64,
}

impl Default for MediaConfig {
    fn default() -> Self {
        Self {
            cache_ttl_ms: 30 * 60 * 1000, // 30 minutes
            max_cache_entries: 128,
            transcribe_rate_limit_per_minute: 30,
            ocr_rate_limit_per_minute: 60,
            timeout_ms: 60_000,
        }
    }
}

// ---------------------------------------------------------------------------
// Cache & rate limiter
// ---------------------------------------------------------------------------

/// A cached media result (either transcription or OCR).
#[derive(Clone, Debug)]
enum CachedResult {
    Transcribe(TranscribeResponse),
    Ocr(OcrResponse),
}

/// A cached entry.
struct CacheEntry {
    result: CachedResult,
    /// Unix-millisecond timestamp when the entry was stored.
    timestamp: u64,
}

/// A fixed-window rate-limit bucket.
struct RateBucket {
    /// Unix-millisecond timestamp of the start of the current window.
    window_start_ms: u64,
    /// Number of operations made in the current window.
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

/// The media capability: caches OCR and transcription results by content
/// hash, rate-limits per operation type, and enforces timeouts.
pub struct MediaCapability {
    provider: Arc<dyn MediaProvider>,
    cache: RwLock<HashMap<String, CacheEntry>>,
    rate_limiter: RwLock<HashMap<RateBucketKey, RateBucket>>,
    config: MediaConfig,
    clock: Clock,
}

/// Key for the per-operation rate limiter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum RateBucketKey {
    Transcribe,
    Ocr,
}

impl MediaCapability {
    /// Create a new media capability with the default system clock.
    pub fn new(provider: Arc<dyn MediaProvider>, config: MediaConfig) -> Self {
        Self {
            provider,
            cache: RwLock::new(HashMap::new()),
            rate_limiter: RwLock::new(HashMap::new()),
            config,
            clock: super::default_clock(),
        }
    }

    /// Create a new media capability with an injected clock (for testing).
    pub fn with_clock(provider: Arc<dyn MediaProvider>, config: MediaConfig, clock: Clock) -> Self {
        Self {
            provider,
            cache: RwLock::new(HashMap::new()),
            rate_limiter: RwLock::new(HashMap::new()),
            config,
            clock,
        }
    }

    /// Transcribe audio bytes, applying rate limiting, caching, and
    /// timeout enforcement.
    pub async fn transcribe(
        &self,
        request: &TranscribeRequest,
    ) -> Result<TranscribeResponse, PerceptionError> {
        if request.audio_data.is_empty() {
            return Err(PerceptionError::InvalidField {
                field: "audio_data",
                message: "audio_data must not be empty".into(),
            });
        }

        // Rate-limit check.
        self.check_rate_limit(
            RateBucketKey::Transcribe,
            self.config.transcribe_rate_limit_per_minute,
        )?;

        // Cache lookup.
        let cache_key = self.transcribe_cache_key(request);
        if let Some(cached) = self.cache_get(&cache_key) {
            if let CachedResult::Transcribe(resp) = cached {
                return Ok(resp);
            }
        }

        // Timeout enforcement.
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(self.config.timeout_ms),
            self.provider.transcribe(request),
        )
        .await;

        let response = match result {
            Ok(r) => r?,
            Err(_) => return Err(PerceptionError::Timeout),
        };

        // Cache the result.
        self.cache_put(&cache_key, CachedResult::Transcribe(response.clone()));

        Ok(response)
    }

    /// Perform OCR on image bytes, applying rate limiting, caching, and
    /// timeout enforcement.
    pub async fn ocr(&self, request: &OcrRequest) -> Result<OcrResponse, PerceptionError> {
        if request.image_data.is_empty() {
            return Err(PerceptionError::InvalidField {
                field: "image_data",
                message: "image_data must not be empty".into(),
            });
        }

        // Rate-limit check.
        self.check_rate_limit(RateBucketKey::Ocr, self.config.ocr_rate_limit_per_minute)?;

        // Cache lookup.
        let cache_key = self.ocr_cache_key(request);
        if let Some(cached) = self.cache_get(&cache_key) {
            if let CachedResult::Ocr(resp) = cached {
                return Ok(resp);
            }
        }

        // Timeout enforcement.
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(self.config.timeout_ms),
            self.provider.ocr(request),
        )
        .await;

        let response = match result {
            Ok(r) => r?,
            Err(_) => return Err(PerceptionError::Timeout),
        };

        // Cache the result.
        self.cache_put(&cache_key, CachedResult::Ocr(response.clone()));

        Ok(response)
    }

    /// Build a deterministic cache key for a transcription request.
    fn transcribe_cache_key(&self, request: &TranscribeRequest) -> String {
        let digest = content_hash(&request.audio_data);
        let lang = request.language_hint.as_deref().unwrap_or("");
        let model = request.model_hint.as_deref().unwrap_or("");
        format!(
            "transcribe|{}|{}|{}|{}",
            request.format.as_str(),
            lang,
            model,
            digest
        )
    }

    /// Build a deterministic cache key for an OCR request.
    fn ocr_cache_key(&self, request: &OcrRequest) -> String {
        let digest = content_hash(&request.image_data);
        let lang = request.language_hint.as_deref().unwrap_or("");
        let dpi = request.dpi_hint.unwrap_or(0);
        format!(
            "ocr|{}|{}|{}|{}",
            request.format.as_str(),
            lang,
            dpi,
            digest
        )
    }

    /// Check and increment the per-operation rate-limit bucket.
    fn check_rate_limit(&self, key: RateBucketKey, limit: u32) -> Result<(), PerceptionError> {
        const MINUTE_MS: u64 = 60 * 1000;

        let now_ms = (self.clock)();
        let mut buckets = self
            .rate_limiter
            .write()
            .expect("rate_limiter lock poisoned");

        let bucket = buckets
            .entry(key)
            .or_insert_with(|| RateBucket::new(now_ms));

        // Reset the window if a minute has elapsed.
        if now_ms.saturating_sub(bucket.window_start_ms) >= MINUTE_MS {
            bucket.window_start_ms = now_ms;
            bucket.count = 0;
        }

        if bucket.count >= limit {
            return Err(PerceptionError::RateLimited);
        }

        bucket.count += 1;
        Ok(())
    }

    /// Look up a key in the cache, returning a clone if present and fresh.
    fn cache_get(&self, key: &str) -> Option<CachedResult> {
        let now_ms = (self.clock)();
        let cache = self.cache.read().expect("cache lock poisoned");
        let entry = cache.get(key)?;
        if now_ms.saturating_sub(entry.timestamp) >= self.config.cache_ttl_ms {
            // Expired.
            return None;
        }
        Some(entry.result.clone())
    }

    /// Store a result in the cache, evicting expired entries if the cache
    /// is full.
    fn cache_put(&self, key: &str, result: CachedResult) {
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
                result,
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

/// Compute a hex SHA-256 digest of the given bytes.
fn content_hash(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
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

    /// A mock media provider with configurable canned responses and call
    /// counting for both operations.
    struct MockProvider {
        transcribe_response: RwLock<TranscribeResponse>,
        ocr_response: RwLock<OcrResponse>,
        transcribe_calls: AtomicU64,
        ocr_calls: AtomicU64,
        delay_ms: u64,
    }

    impl MockProvider {
        fn new(transcribe: TranscribeResponse, ocr: OcrResponse) -> Self {
            Self {
                transcribe_response: RwLock::new(transcribe),
                ocr_response: RwLock::new(ocr),
                transcribe_calls: AtomicU64::new(0),
                ocr_calls: AtomicU64::new(0),
                delay_ms: 0,
            }
        }

        fn with_delay(transcribe: TranscribeResponse, ocr: OcrResponse, delay_ms: u64) -> Self {
            Self {
                transcribe_response: RwLock::new(transcribe),
                ocr_response: RwLock::new(ocr),
                transcribe_calls: AtomicU64::new(0),
                ocr_calls: AtomicU64::new(0),
                delay_ms,
            }
        }

        fn transcribe_calls(&self) -> u64 {
            self.transcribe_calls.load(Ordering::SeqCst)
        }

        fn ocr_calls(&self) -> u64 {
            self.ocr_calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl MediaProvider for MockProvider {
        async fn transcribe(
            &self,
            _req: &TranscribeRequest,
        ) -> Result<TranscribeResponse, PerceptionError> {
            self.transcribe_calls.fetch_add(1, Ordering::SeqCst);
            if self.delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
            }
            Ok(self
                .transcribe_response
                .read()
                .expect("transcribe lock poisoned")
                .clone())
        }

        async fn ocr(&self, _req: &OcrRequest) -> Result<OcrResponse, PerceptionError> {
            self.ocr_calls.fetch_add(1, Ordering::SeqCst);
            if self.delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
            }
            Ok(self.ocr_response.read().expect("ocr lock poisoned").clone())
        }
    }

    fn sample_transcribe_response() -> TranscribeResponse {
        let mut resp = TranscribeResponse::new("hello world", 0.95, 3.5);
        resp.language_detected = Some("en".into());
        resp.segments = vec![
            TextSegment::new("hello", 0.0, 1.0, 0.97),
            TextSegment::new("world", 1.0, 2.0, 0.93),
        ];
        resp
    }

    fn sample_ocr_response() -> OcrResponse {
        let mut resp = OcrResponse::new("Hello World", 0.92);
        resp.blocks = vec![
            TextBlock::new("Hello", 10, 20, 100, 30, 0.95),
            TextBlock::new("World", 10, 60, 100, 30, 0.89),
        ];
        resp
    }

    fn default_config() -> MediaConfig {
        MediaConfig {
            cache_ttl_ms: 60_000,
            max_cache_entries: 4,
            transcribe_rate_limit_per_minute: 100,
            ocr_rate_limit_per_minute: 100,
            timeout_ms: 5_000,
        }
    }

    // -----------------------------------------------------------------------
    // AudioFormat
    // -----------------------------------------------------------------------

    #[test]
    fn test_audio_format_as_str() {
        assert_eq!(AudioFormat::Wav.as_str(), "WAV");
        assert_eq!(AudioFormat::Mp3.as_str(), "MP3");
        assert_eq!(AudioFormat::Ogg.as_str(), "OGG");
        assert_eq!(AudioFormat::Flac.as_str(), "FLAC");
    }

    #[test]
    fn test_audio_format_display() {
        assert_eq!(format!("{}", AudioFormat::Wav), "WAV");
        assert_eq!(format!("{}", AudioFormat::Mp3), "MP3");
    }

    #[test]
    fn test_audio_format_from_str_ok() {
        assert_eq!("wav".parse::<AudioFormat>().unwrap(), AudioFormat::Wav);
        assert_eq!("WAVE".parse::<AudioFormat>().unwrap(), AudioFormat::Wav);
        assert_eq!("mp3".parse::<AudioFormat>().unwrap(), AudioFormat::Mp3);
        assert_eq!("ogg".parse::<AudioFormat>().unwrap(), AudioFormat::Ogg);
        assert_eq!("flac".parse::<AudioFormat>().unwrap(), AudioFormat::Flac);
    }

    #[test]
    fn test_audio_format_from_str_unknown() {
        let err = "aac".parse::<AudioFormat>().unwrap_err();
        assert!(matches!(
            err,
            PerceptionError::InvalidField {
                field: "format",
                ..
            }
        ));
    }

    // -----------------------------------------------------------------------
    // ImageFormat
    // -----------------------------------------------------------------------

    #[test]
    fn test_image_format_as_str() {
        assert_eq!(ImageFormat::Png.as_str(), "PNG");
        assert_eq!(ImageFormat::Jpeg.as_str(), "JPEG");
        assert_eq!(ImageFormat::Webp.as_str(), "WEBP");
        assert_eq!(ImageFormat::Tiff.as_str(), "TIFF");
    }

    #[test]
    fn test_image_format_display() {
        assert_eq!(format!("{}", ImageFormat::Png), "PNG");
        assert_eq!(format!("{}", ImageFormat::Jpeg), "JPEG");
    }

    #[test]
    fn test_image_format_from_str_ok() {
        assert_eq!("png".parse::<ImageFormat>().unwrap(), ImageFormat::Png);
        assert_eq!("jpg".parse::<ImageFormat>().unwrap(), ImageFormat::Jpeg);
        assert_eq!("jpeg".parse::<ImageFormat>().unwrap(), ImageFormat::Jpeg);
        assert_eq!("webp".parse::<ImageFormat>().unwrap(), ImageFormat::Webp);
        assert_eq!("tiff".parse::<ImageFormat>().unwrap(), ImageFormat::Tiff);
        assert_eq!("tif".parse::<ImageFormat>().unwrap(), ImageFormat::Tiff);
    }

    #[test]
    fn test_image_format_from_str_unknown() {
        let err = "bmp".parse::<ImageFormat>().unwrap_err();
        assert!(matches!(
            err,
            PerceptionError::InvalidField {
                field: "format",
                ..
            }
        ));
    }

    // -----------------------------------------------------------------------
    // TextSegment
    // -----------------------------------------------------------------------

    #[test]
    fn test_text_segment_new() {
        let seg = TextSegment::new("hi", 1.0, 2.5, 0.9);
        assert_eq!(seg.text, "hi");
        assert_eq!(seg.start_time, 1.0);
        assert_eq!(seg.end_time, 2.5);
        assert_eq!(seg.confidence, 0.9);
    }

    #[test]
    fn test_text_segment_duration() {
        let seg = TextSegment::new("hi", 1.0, 3.5, 0.9);
        assert_eq!(seg.duration(), 2.5);
    }

    // -----------------------------------------------------------------------
    // TextBlock
    // -----------------------------------------------------------------------

    #[test]
    fn test_text_block_new() {
        let block = TextBlock::new("text", 10, 20, 100, 50, 0.8);
        assert_eq!(block.text, "text");
        assert_eq!(block.x, 10);
        assert_eq!(block.y, 20);
        assert_eq!(block.width, 100);
        assert_eq!(block.height, 50);
        assert_eq!(block.confidence, 0.8);
    }

    #[test]
    fn test_text_block_area() {
        let block = TextBlock::new("text", 0, 0, 100, 50, 1.0);
        assert_eq!(block.area(), 5000);
    }

    // -----------------------------------------------------------------------
    // Request / response serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_transcribe_request_to_json_roundtrip() {
        let req = TranscribeRequest::new(vec![1, 2, 3], AudioFormat::Mp3)
            .with_language("en-US")
            .with_model("whisper-large-v3");
        let json = req.to_json().expect("serialize");
        let parsed = TranscribeRequest::from_json(&json).expect("deserialize");
        assert_eq!(parsed.audio_data, req.audio_data);
        assert_eq!(parsed.format, AudioFormat::Mp3);
        assert_eq!(parsed.language_hint, Some("en-US".into()));
        assert_eq!(parsed.model_hint, Some("whisper-large-v3".into()));
    }

    #[test]
    fn test_transcribe_response_to_json_roundtrip() {
        let resp = sample_transcribe_response();
        let json = resp.to_json().expect("serialize");
        let parsed = TranscribeResponse::from_json(&json).expect("deserialize");
        assert_eq!(parsed.text, "hello world");
        assert_eq!(parsed.confidence, 0.95);
        assert_eq!(parsed.duration_secs, 3.5);
        assert_eq!(parsed.language_detected, Some("en".into()));
        assert_eq!(parsed.segments.len(), 2);
        assert_eq!(parsed.segments[0].text, "hello");
    }

    #[test]
    fn test_ocr_request_to_json_roundtrip() {
        let req = OcrRequest::new(vec![4, 5, 6], ImageFormat::Png)
            .with_language("eng")
            .with_dpi(300);
        let json = req.to_json().expect("serialize");
        let parsed = OcrRequest::from_json(&json).expect("deserialize");
        assert_eq!(parsed.image_data, req.image_data);
        assert_eq!(parsed.format, ImageFormat::Png);
        assert_eq!(parsed.language_hint, Some("eng".into()));
        assert_eq!(parsed.dpi_hint, Some(300));
    }

    #[test]
    fn test_ocr_response_to_json_roundtrip() {
        let resp = sample_ocr_response();
        let json = resp.to_json().expect("serialize");
        let parsed = OcrResponse::from_json(&json).expect("deserialize");
        assert_eq!(parsed.text, "Hello World");
        assert_eq!(parsed.confidence, 0.92);
        assert_eq!(parsed.page_count, 1);
        assert_eq!(parsed.blocks.len(), 2);
        assert_eq!(parsed.blocks[0].text, "Hello");
    }

    // -----------------------------------------------------------------------
    // Builders
    // -----------------------------------------------------------------------

    #[test]
    fn test_transcribe_request_builder() {
        let req = TranscribeRequest::new(vec![1], AudioFormat::Wav)
            .with_language("fr")
            .with_model("model-x");
        assert_eq!(req.audio_data, vec![1]);
        assert_eq!(req.format, AudioFormat::Wav);
        assert_eq!(req.language_hint, Some("fr".into()));
        assert_eq!(req.model_hint, Some("model-x".into()));
    }

    #[test]
    fn test_ocr_request_builder() {
        let req = OcrRequest::new(vec![2], ImageFormat::Jpeg)
            .with_language("deu")
            .with_dpi(600);
        assert_eq!(req.image_data, vec![2]);
        assert_eq!(req.format, ImageFormat::Jpeg);
        assert_eq!(req.language_hint, Some("deu".into()));
        assert_eq!(req.dpi_hint, Some(600));
    }

    // -----------------------------------------------------------------------
    // Transcribe
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_transcribe_success() {
        let provider = Arc::new(MockProvider::new(
            sample_transcribe_response(),
            sample_ocr_response(),
        ));
        let (clock, _) = mock_clock();
        let cap = MediaCapability::with_clock(provider.clone(), default_config(), clock);
        let resp = cap
            .transcribe(&TranscribeRequest::new(vec![1, 2, 3], AudioFormat::Mp3))
            .await
            .expect("transcribe ok");
        assert_eq!(resp.text, "hello world");
        assert!(resp.has_segments());
        assert_eq!(provider.transcribe_calls(), 1);
    }

    #[tokio::test]
    async fn test_transcribe_empty_audio_error() {
        let provider = Arc::new(MockProvider::new(
            sample_transcribe_response(),
            sample_ocr_response(),
        ));
        let (clock, _) = mock_clock();
        let cap = MediaCapability::with_clock(provider.clone(), default_config(), clock);
        let err = cap
            .transcribe(&TranscribeRequest::new(vec![], AudioFormat::Mp3))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            PerceptionError::InvalidField {
                field: "audio_data",
                ..
            }
        ));
        assert_eq!(provider.transcribe_calls(), 0);
    }

    #[tokio::test]
    async fn test_transcribe_cache_hit() {
        let provider = Arc::new(MockProvider::new(
            sample_transcribe_response(),
            sample_ocr_response(),
        ));
        let (clock, _) = mock_clock();
        let cap = MediaCapability::with_clock(provider.clone(), default_config(), clock);
        let req = TranscribeRequest::new(vec![1, 2, 3], AudioFormat::Mp3);
        let _ = cap.transcribe(&req).await.expect("first");
        let _ = cap.transcribe(&req).await.expect("second");
        assert_eq!(provider.transcribe_calls(), 1, "second should hit cache");
    }

    #[tokio::test]
    async fn test_transcribe_cache_miss_different_audio() {
        let provider = Arc::new(MockProvider::new(
            sample_transcribe_response(),
            sample_ocr_response(),
        ));
        let (clock, _) = mock_clock();
        let cap = MediaCapability::with_clock(provider.clone(), default_config(), clock);
        let _ = cap
            .transcribe(&TranscribeRequest::new(vec![1], AudioFormat::Mp3))
            .await;
        let _ = cap
            .transcribe(&TranscribeRequest::new(vec![2], AudioFormat::Mp3))
            .await;
        assert_eq!(
            provider.transcribe_calls(),
            2,
            "different audio → cache miss"
        );
    }

    // -----------------------------------------------------------------------
    // OCR
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_ocr_success() {
        let provider = Arc::new(MockProvider::new(
            sample_transcribe_response(),
            sample_ocr_response(),
        ));
        let (clock, _) = mock_clock();
        let cap = MediaCapability::with_clock(provider.clone(), default_config(), clock);
        let resp = cap
            .ocr(&OcrRequest::new(vec![4, 5, 6], ImageFormat::Png))
            .await
            .expect("ocr ok");
        assert_eq!(resp.text, "Hello World");
        assert!(resp.has_blocks());
        assert_eq!(resp.blocks.len(), 2);
        assert_eq!(provider.ocr_calls(), 1);
    }

    #[tokio::test]
    async fn test_ocr_empty_image_error() {
        let provider = Arc::new(MockProvider::new(
            sample_transcribe_response(),
            sample_ocr_response(),
        ));
        let (clock, _) = mock_clock();
        let cap = MediaCapability::with_clock(provider.clone(), default_config(), clock);
        let err = cap
            .ocr(&OcrRequest::new(vec![], ImageFormat::Png))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            PerceptionError::InvalidField {
                field: "image_data",
                ..
            }
        ));
        assert_eq!(provider.ocr_calls(), 0);
    }

    #[tokio::test]
    async fn test_ocr_cache_hit() {
        let provider = Arc::new(MockProvider::new(
            sample_transcribe_response(),
            sample_ocr_response(),
        ));
        let (clock, _) = mock_clock();
        let cap = MediaCapability::with_clock(provider.clone(), default_config(), clock);
        let req = OcrRequest::new(vec![4, 5, 6], ImageFormat::Png);
        let _ = cap.ocr(&req).await.expect("first");
        let _ = cap.ocr(&req).await.expect("second");
        assert_eq!(provider.ocr_calls(), 1, "second should hit cache");
    }

    #[tokio::test]
    async fn test_ocr_cache_miss_different_image() {
        let provider = Arc::new(MockProvider::new(
            sample_transcribe_response(),
            sample_ocr_response(),
        ));
        let (clock, _) = mock_clock();
        let cap = MediaCapability::with_clock(provider.clone(), default_config(), clock);
        let _ = cap.ocr(&OcrRequest::new(vec![1], ImageFormat::Png)).await;
        let _ = cap.ocr(&OcrRequest::new(vec![2], ImageFormat::Png)).await;
        assert_eq!(provider.ocr_calls(), 2, "different image → cache miss");
    }

    // -----------------------------------------------------------------------
    // Cache TTL & eviction
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_cache_ttl_expiration() {
        let provider = Arc::new(MockProvider::new(
            sample_transcribe_response(),
            sample_ocr_response(),
        ));
        let (clock, cell) = mock_clock();
        let cap = MediaCapability::with_clock(
            provider.clone(),
            MediaConfig {
                cache_ttl_ms: 1_000,
                max_cache_entries: 4,
                transcribe_rate_limit_per_minute: 100,
                ocr_rate_limit_per_minute: 100,
                timeout_ms: 5_000,
            },
            clock,
        );
        let req = TranscribeRequest::new(vec![1, 2, 3], AudioFormat::Mp3);
        let _ = cap.transcribe(&req).await.expect("first");
        assert_eq!(provider.transcribe_calls(), 1);
        cell.store(1_700_000_000_000 + 2_000, Ordering::SeqCst);
        let _ = cap.transcribe(&req).await.expect("second");
        assert_eq!(
            provider.transcribe_calls(),
            2,
            "expired entry should refetch"
        );
    }

    #[tokio::test]
    async fn test_cache_eviction_max_entries() {
        let provider = Arc::new(MockProvider::new(
            sample_transcribe_response(),
            sample_ocr_response(),
        ));
        let (clock, cell) = mock_clock();
        let cap = MediaCapability::with_clock(
            provider.clone(),
            MediaConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 2,
                transcribe_rate_limit_per_minute: 1000,
                ocr_rate_limit_per_minute: 1000,
                timeout_ms: 5_000,
            },
            clock,
        );
        let _ = cap.ocr(&OcrRequest::new(vec![1], ImageFormat::Png)).await;
        cell.fetch_add(1000, Ordering::SeqCst);
        let _ = cap.ocr(&OcrRequest::new(vec![2], ImageFormat::Png)).await;
        cell.fetch_add(1000, Ordering::SeqCst);
        let _ = cap.ocr(&OcrRequest::new(vec![3], ImageFormat::Png)).await;
        assert_eq!(cap.cache_len(), 2, "cache should be at capacity");
    }

    #[tokio::test]
    async fn test_evict_expired_public() {
        let provider = Arc::new(MockProvider::new(
            sample_transcribe_response(),
            sample_ocr_response(),
        ));
        let (clock, cell) = mock_clock();
        let cap = MediaCapability::with_clock(
            provider.clone(),
            MediaConfig {
                cache_ttl_ms: 1_000,
                max_cache_entries: 4,
                transcribe_rate_limit_per_minute: 1000,
                ocr_rate_limit_per_minute: 1000,
                timeout_ms: 5_000,
            },
            clock,
        );
        let _ = cap.ocr(&OcrRequest::new(vec![1], ImageFormat::Png)).await;
        assert_eq!(cap.cache_len(), 1);
        cell.store(1_700_000_000_000 + 2_000, Ordering::SeqCst);
        cap.evict_expired();
        assert_eq!(cap.cache_len(), 0, "expired entry should be evicted");
    }

    // -----------------------------------------------------------------------
    // Rate limiting
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_rate_limit_transcribe() {
        let provider = Arc::new(MockProvider::new(
            sample_transcribe_response(),
            sample_ocr_response(),
        ));
        let (clock, _) = mock_clock();
        let cap = MediaCapability::with_clock(
            provider.clone(),
            MediaConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 4,
                transcribe_rate_limit_per_minute: 2,
                ocr_rate_limit_per_minute: 100,
                timeout_ms: 5_000,
            },
            clock,
        );
        // Different audio each time to bypass cache.
        assert!(cap
            .transcribe(&TranscribeRequest::new(vec![1], AudioFormat::Mp3))
            .await
            .is_ok());
        assert!(cap
            .transcribe(&TranscribeRequest::new(vec![2], AudioFormat::Mp3))
            .await
            .is_ok());
        let err = cap
            .transcribe(&TranscribeRequest::new(vec![3], AudioFormat::Mp3))
            .await
            .unwrap_err();
        assert!(matches!(err, PerceptionError::RateLimited));
    }

    #[tokio::test]
    async fn test_rate_limit_ocr() {
        let provider = Arc::new(MockProvider::new(
            sample_transcribe_response(),
            sample_ocr_response(),
        ));
        let (clock, _) = mock_clock();
        let cap = MediaCapability::with_clock(
            provider.clone(),
            MediaConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 4,
                transcribe_rate_limit_per_minute: 100,
                ocr_rate_limit_per_minute: 2,
                timeout_ms: 5_000,
            },
            clock,
        );
        assert!(cap
            .ocr(&OcrRequest::new(vec![1], ImageFormat::Png))
            .await
            .is_ok());
        assert!(cap
            .ocr(&OcrRequest::new(vec![2], ImageFormat::Png))
            .await
            .is_ok());
        let err = cap
            .ocr(&OcrRequest::new(vec![3], ImageFormat::Png))
            .await
            .unwrap_err();
        assert!(matches!(err, PerceptionError::RateLimited));
    }

    #[tokio::test]
    async fn test_rate_limit_independent_operations() {
        let provider = Arc::new(MockProvider::new(
            sample_transcribe_response(),
            sample_ocr_response(),
        ));
        let (clock, _) = mock_clock();
        let cap = MediaCapability::with_clock(
            provider.clone(),
            MediaConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 4,
                transcribe_rate_limit_per_minute: 1,
                ocr_rate_limit_per_minute: 1,
                timeout_ms: 5_000,
            },
            clock,
        );
        // Each operation type has its own bucket.
        assert!(cap
            .transcribe(&TranscribeRequest::new(vec![1], AudioFormat::Mp3))
            .await
            .is_ok());
        assert!(
            cap.ocr(&OcrRequest::new(vec![1], ImageFormat::Png))
                .await
                .is_ok(),
            "ocr has its own bucket"
        );
    }

    #[tokio::test]
    async fn test_rate_limit_reset_after_window() {
        let provider = Arc::new(MockProvider::new(
            sample_transcribe_response(),
            sample_ocr_response(),
        ));
        let (clock, cell) = mock_clock();
        let cap = MediaCapability::with_clock(
            provider.clone(),
            MediaConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 4,
                transcribe_rate_limit_per_minute: 1,
                ocr_rate_limit_per_minute: 100,
                timeout_ms: 5_000,
            },
            clock,
        );
        assert!(cap
            .transcribe(&TranscribeRequest::new(vec![1], AudioFormat::Mp3))
            .await
            .is_ok());
        assert!(matches!(
            cap.transcribe(&TranscribeRequest::new(vec![2], AudioFormat::Mp3))
                .await
                .unwrap_err(),
            PerceptionError::RateLimited
        ));
        cell.store(1_700_000_000_000 + 60 * 1000 + 1, Ordering::SeqCst);
        assert!(
            cap.transcribe(&TranscribeRequest::new(vec![3], AudioFormat::Mp3))
                .await
                .is_ok(),
            "window reset allows request"
        );
    }

    // -----------------------------------------------------------------------
    // Timeout
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_transcribe_timeout() {
        let provider = Arc::new(MockProvider::with_delay(
            sample_transcribe_response(),
            sample_ocr_response(),
            500,
        ));
        let (clock, _) = mock_clock();
        let cap = MediaCapability::with_clock(
            provider.clone(),
            MediaConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 4,
                transcribe_rate_limit_per_minute: 100,
                ocr_rate_limit_per_minute: 100,
                timeout_ms: 10,
            },
            clock,
        );
        let err = cap
            .transcribe(&TranscribeRequest::new(vec![1], AudioFormat::Mp3))
            .await
            .unwrap_err();
        assert!(matches!(err, PerceptionError::Timeout));
    }

    #[tokio::test]
    async fn test_ocr_timeout() {
        let provider = Arc::new(MockProvider::with_delay(
            sample_transcribe_response(),
            sample_ocr_response(),
            500,
        ));
        let (clock, _) = mock_clock();
        let cap = MediaCapability::with_clock(
            provider.clone(),
            MediaConfig {
                cache_ttl_ms: 60_000,
                max_cache_entries: 4,
                transcribe_rate_limit_per_minute: 100,
                ocr_rate_limit_per_minute: 100,
                timeout_ms: 10,
            },
            clock,
        );
        let err = cap
            .ocr(&OcrRequest::new(vec![1], ImageFormat::Png))
            .await
            .unwrap_err();
        assert!(matches!(err, PerceptionError::Timeout));
    }

    // -----------------------------------------------------------------------
    // Provider error propagation
    // -----------------------------------------------------------------------

    struct FailingProvider;

    #[async_trait]
    impl MediaProvider for FailingProvider {
        async fn transcribe(
            &self,
            _req: &TranscribeRequest,
        ) -> Result<TranscribeResponse, PerceptionError> {
            Err(PerceptionError::Provider("transcribe unavailable".into()))
        }

        async fn ocr(&self, _req: &OcrRequest) -> Result<OcrResponse, PerceptionError> {
            Err(PerceptionError::Provider("ocr unavailable".into()))
        }
    }

    #[tokio::test]
    async fn test_transcribe_provider_error_propagates() {
        let provider = Arc::new(FailingProvider);
        let (clock, _) = mock_clock();
        let cap = MediaCapability::with_clock(provider, default_config(), clock);
        let err = cap
            .transcribe(&TranscribeRequest::new(vec![1], AudioFormat::Mp3))
            .await
            .unwrap_err();
        assert!(matches!(err, PerceptionError::Provider(_)));
    }

    #[tokio::test]
    async fn test_ocr_provider_error_propagates() {
        let provider = Arc::new(FailingProvider);
        let (clock, _) = mock_clock();
        let cap = MediaCapability::with_clock(provider, default_config(), clock);
        let err = cap
            .ocr(&OcrRequest::new(vec![1], ImageFormat::Png))
            .await
            .unwrap_err();
        assert!(matches!(err, PerceptionError::Provider(_)));
    }

    // -----------------------------------------------------------------------
    // Config defaults
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_config_values() {
        let cfg = MediaConfig::default();
        assert_eq!(cfg.cache_ttl_ms, 30 * 60 * 1000);
        assert_eq!(cfg.max_cache_entries, 128);
        assert_eq!(cfg.transcribe_rate_limit_per_minute, 30);
        assert_eq!(cfg.ocr_rate_limit_per_minute, 60);
        assert_eq!(cfg.timeout_ms, 60_000);
    }

    // -----------------------------------------------------------------------
    // Response helpers
    // -----------------------------------------------------------------------

    #[test]
    fn test_transcribe_response_has_segments() {
        let mut resp = TranscribeResponse::new("text", 0.9, 1.0);
        assert!(!resp.has_segments());
        resp.segments.push(TextSegment::new("a", 0.0, 1.0, 0.9));
        assert!(resp.has_segments());
    }

    #[test]
    fn test_ocr_response_has_blocks() {
        let mut resp = OcrResponse::new("text", 0.9);
        assert!(!resp.has_blocks());
        resp.blocks.push(TextBlock::new("a", 0, 0, 10, 10, 0.9));
        assert!(resp.has_blocks());
    }

    #[test]
    fn test_content_hash_deterministic() {
        let h1 = content_hash(b"hello");
        let h2 = content_hash(b"hello");
        let h3 = content_hash(b"world");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }
}
