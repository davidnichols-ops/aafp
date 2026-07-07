//! Intent resolution (Track U8).
//!
//! Translates natural-language intent into structured [`CapabilityQuery`]s
//! and matches them against available capabilities.
//!
//! ## Design
//! The [`IntentResolver`] is the entry point. It holds an [`IntentConfig`]
//! and a pluggable [`IntentParser`] (default: [`DefaultParser`], a simple
//! keyword-based parser with no external NLP dependencies).
//!
//! The resolution pipeline is:
//! 1. `parse_intent()` — raw text → [`Intent`] (capabilities, constraints,
//!    priority, deadline, context).
//! 2. `resolve()` — [`Intent`] → [`ResolvedIntent`] (matched capabilities,
//!    estimated cost/latency, confidence).
//!
//! Multi-intent support: compound requests (e.g. "translate this and then
//! summarize it") are split into multiple [`Intent`]s via
//! [`IntentResolver::parse_intents`].
//!
//! ## CBOR serialization
//! [`Intent`] and [`ResolvedIntent`] implement CBOR round-tripping via
//! `to_cbor` / `from_cbor`, using the same IntMap convention as the rest of
//! the semantic module (see [`encoding`](super::encoding)).

use super::capability::SemanticError;
use super::query::CapabilityQuery;
use aafp_cbor::{int_map, int_map_get, Value};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// IntentConstraint
// ---------------------------------------------------------------------------

/// A constraint parsed from natural-language intent.
///
/// Each variant carries the structured value extracted from the raw text.
#[derive(Clone, Debug, PartialEq)]
pub enum IntentConstraint {
    /// Maximum acceptable latency, in milliseconds.
    MaxLatency(u64),
    /// Minimum reputation score (0-100).
    MinReputation(u8),
    /// Maximum cost in micro-USD credits.
    MaxCost(u64),
    /// Geographic region preference (ISO 3166-1 alpha-2 code, e.g. "us").
    Region(String),
    /// Language preference (BCP 47 tag, e.g. "en", "zh-Hans").
    Language(String),
    /// Required capability version (e.g. "2.1.0").
    CapabilityVersion(String),
}

impl IntentConstraint {
    /// Encode an [`IntentConstraint`] to a CBOR `Value`.
    ///
    /// Encoded as an IntMap: `{ 0: discriminant, 1: payload }`.
    pub fn to_cbor(&self) -> Value {
        let (disc, payload) = match self {
            IntentConstraint::MaxLatency(ms) => (0u64, Value::Unsigned(*ms)),
            IntentConstraint::MinReputation(score) => (1, Value::Unsigned(*score as u64)),
            IntentConstraint::MaxCost(credits) => (2, Value::Unsigned(*credits)),
            IntentConstraint::Region(code) => (3, Value::TextString(code.clone())),
            IntentConstraint::Language(code) => (4, Value::TextString(code.clone())),
            IntentConstraint::CapabilityVersion(version) => (5, Value::TextString(version.clone())),
        };
        int_map(vec![(0, Value::Unsigned(disc)), (1, payload)])
    }

    /// Decode an [`IntentConstraint`] from a CBOR `Value`.
    pub fn from_cbor(val: &Value) -> Result<Self, SemanticError> {
        let disc = match int_map_get(val, 0) {
            Some(Value::Unsigned(n)) => *n,
            _ => {
                return Err(SemanticError::InvalidField {
                    field: "constraint.discriminant",
                    message: "missing or invalid discriminant".into(),
                })
            }
        };
        let payload =
            int_map_get(val, 1).ok_or(SemanticError::MissingField("constraint.payload"))?;
        match disc {
            0 => {
                let ms = match payload {
                    Value::Unsigned(n) => *n,
                    _ => {
                        return Err(SemanticError::InvalidField {
                            field: "MaxLatency",
                            message: "expected unsigned".into(),
                        })
                    }
                };
                Ok(IntentConstraint::MaxLatency(ms))
            }
            1 => {
                let score = match payload {
                    Value::Unsigned(n) if *n <= u8::MAX as u64 => *n as u8,
                    _ => {
                        return Err(SemanticError::InvalidField {
                            field: "MinReputation",
                            message: "expected u8 reputation".into(),
                        })
                    }
                };
                Ok(IntentConstraint::MinReputation(score))
            }
            2 => {
                let credits = match payload {
                    Value::Unsigned(n) => *n,
                    _ => {
                        return Err(SemanticError::InvalidField {
                            field: "MaxCost",
                            message: "expected unsigned".into(),
                        })
                    }
                };
                Ok(IntentConstraint::MaxCost(credits))
            }
            3 => {
                let code = match payload {
                    Value::TextString(s) => s.clone(),
                    _ => {
                        return Err(SemanticError::InvalidField {
                            field: "Region",
                            message: "expected text".into(),
                        })
                    }
                };
                Ok(IntentConstraint::Region(code))
            }
            4 => {
                let code = match payload {
                    Value::TextString(s) => s.clone(),
                    _ => {
                        return Err(SemanticError::InvalidField {
                            field: "Language",
                            message: "expected text".into(),
                        })
                    }
                };
                Ok(IntentConstraint::Language(code))
            }
            5 => {
                let version = match payload {
                    Value::TextString(s) => s.clone(),
                    _ => {
                        return Err(SemanticError::InvalidField {
                            field: "CapabilityVersion",
                            message: "expected text".into(),
                        })
                    }
                };
                Ok(IntentConstraint::CapabilityVersion(version))
            }
            other => Err(SemanticError::InvalidField {
                field: "constraint.discriminant",
                message: format!("unknown discriminant: {}", other),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// IntentPriority
// ---------------------------------------------------------------------------

/// Priority of an intent, derived from keywords like "urgent" or "low".
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum IntentPriority {
    /// Low priority — background / best-effort.
    Low,
    /// Normal priority (default).
    #[default]
    Normal,
    /// High priority — prefer faster/more-reliable providers.
    High,
    /// Urgent — minimum latency, accept higher cost.
    Urgent,
}

impl IntentPriority {
    /// Encode to a CBOR `Value` (uint discriminant).
    pub fn to_cbor(&self) -> Value {
        Value::Unsigned(match self {
            IntentPriority::Low => 0,
            IntentPriority::Normal => 1,
            IntentPriority::High => 2,
            IntentPriority::Urgent => 3,
        })
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &Value) -> Result<Self, SemanticError> {
        match val {
            Value::Unsigned(0) => Ok(IntentPriority::Low),
            Value::Unsigned(1) => Ok(IntentPriority::Normal),
            Value::Unsigned(2) => Ok(IntentPriority::High),
            Value::Unsigned(3) => Ok(IntentPriority::Urgent),
            _ => Err(SemanticError::InvalidField {
                field: "priority",
                message: format!("invalid discriminant: {:?}", val),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Intent
// ---------------------------------------------------------------------------

/// A parsed natural-language intent.
///
/// Produced by [`IntentParser::parse`]. The `raw_text` is preserved for
/// debugging and low-confidence fallback. `parsed_capabilities` is the list
/// of capability names extracted from the text (may be empty if nothing
/// matched).
#[derive(Clone, Debug, Default)]
pub struct Intent {
    /// The original natural-language text.
    pub raw_text: String,
    /// Capability names extracted from the text.
    pub parsed_capabilities: Vec<String>,
    /// Constraints extracted from the text.
    pub constraints: Vec<IntentConstraint>,
    /// Priority inferred from keywords.
    pub priority: IntentPriority,
    /// Optional deadline in milliseconds from parse time (0 = none).
    pub deadline_ms: u64,
    /// Free-form context key-value pairs (e.g. session id, user id).
    pub context: HashMap<String, String>,
}

impl Intent {
    /// Create a new empty intent from raw text.
    pub fn new(raw_text: impl Into<String>) -> Self {
        Self {
            raw_text: raw_text.into(),
            ..Default::default()
        }
    }

    /// Add a parsed capability (builder).
    pub fn with_capability(mut self, cap: impl Into<String>) -> Self {
        self.parsed_capabilities.push(cap.into());
        self
    }

    /// Add a constraint (builder).
    pub fn with_constraint(mut self, c: IntentConstraint) -> Self {
        self.constraints.push(c);
        self
    }

    /// Set priority (builder).
    pub fn with_priority(mut self, p: IntentPriority) -> Self {
        self.priority = p;
        self
    }

    /// Set deadline in ms (builder).
    pub fn with_deadline_ms(mut self, ms: u64) -> Self {
        self.deadline_ms = ms;
        self
    }

    /// Add a context entry (builder).
    pub fn with_context(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.context.insert(key.into(), val.into());
        self
    }

    /// Encode to a CBOR `Value` (IntMap keys 1-6).
    pub fn to_cbor(&self) -> Value {
        let caps = Value::Array(
            self.parsed_capabilities
                .iter()
                .map(|c| Value::TextString(c.clone()))
                .collect(),
        );
        let constraints = Value::Array(
            self.constraints
                .iter()
                .map(IntentConstraint::to_cbor)
                .collect(),
        );
        let context = if self.context.is_empty() {
            Value::Null
        } else {
            Value::StrMap(
                self.context
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::TextString(v.clone())))
                    .collect(),
            )
        };
        int_map(vec![
            (1, Value::TextString(self.raw_text.clone())),
            (2, caps),
            (3, constraints),
            (4, self.priority.to_cbor()),
            (5, Value::Unsigned(self.deadline_ms)),
            (6, context),
        ])
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &Value) -> Result<Self, SemanticError> {
        let raw_text = match int_map_get(val, 1) {
            Some(Value::TextString(s)) => s.clone(),
            _ => return Err(SemanticError::MissingField("raw_text")),
        };
        let parsed_capabilities = match int_map_get(val, 2) {
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| {
                    if let Value::TextString(s) = v {
                        Some(s.clone())
                    } else {
                        None
                    }
                })
                .collect(),
            _ => Vec::new(),
        };
        let constraints = match int_map_get(val, 3) {
            Some(Value::Array(arr)) => arr
                .iter()
                .map(IntentConstraint::from_cbor)
                .collect::<Result<Vec<_>, _>>()?,
            _ => Vec::new(),
        };
        let priority = match int_map_get(val, 4) {
            Some(v) => IntentPriority::from_cbor(v)?,
            None => IntentPriority::Normal,
        };
        let deadline_ms = match int_map_get(val, 5) {
            Some(Value::Unsigned(n)) => *n,
            _ => 0,
        };
        let context = match int_map_get(val, 6) {
            Some(Value::StrMap(entries)) => {
                let mut map = HashMap::new();
                for (k, v) in entries {
                    if let Value::TextString(s) = v {
                        map.insert(k.clone(), s.clone());
                    }
                }
                map
            }
            _ => HashMap::new(),
        };
        Ok(Self {
            raw_text,
            parsed_capabilities,
            constraints,
            priority,
            deadline_ms,
            context,
        })
    }
}

// ---------------------------------------------------------------------------
// ResolvedIntent
// ---------------------------------------------------------------------------

/// The result of resolving an [`Intent`] against available capabilities.
#[derive(Clone, Debug)]
pub struct ResolvedIntent {
    /// The original intent.
    pub intent: Intent,
    /// Capability names that matched available capabilities.
    pub matched_capabilities: Vec<String>,
    /// Estimated total cost in micro-USD (sum across matched capabilities).
    pub estimated_cost: u64,
    /// Estimated total latency in milliseconds (max across matched caps).
    pub estimated_latency: u64,
    /// Confidence score in [0.0, 1.0].
    pub confidence: f64,
}

impl ResolvedIntent {
    /// Encode to a CBOR `Value` (IntMap keys 1-5).
    pub fn to_cbor(&self) -> Value {
        // Confidence is scaled to parts-per-million (u64) since aafp_cbor
        // has no Float variant.
        let confidence_ppm = if self.confidence.is_finite() && self.confidence >= 0.0 {
            (self.confidence * 1_000_000.0) as u64
        } else {
            0
        };
        int_map(vec![
            (1, self.intent.to_cbor()),
            (
                2,
                Value::Array(
                    self.matched_capabilities
                        .iter()
                        .map(|c| Value::TextString(c.clone()))
                        .collect(),
                ),
            ),
            (3, Value::Unsigned(self.estimated_cost)),
            (4, Value::Unsigned(self.estimated_latency)),
            (5, Value::Unsigned(confidence_ppm)),
        ])
    }

    /// Decode from a CBOR `Value`.
    pub fn from_cbor(val: &Value) -> Result<Self, SemanticError> {
        let intent = match int_map_get(val, 1) {
            Some(v) => Intent::from_cbor(v)?,
            None => return Err(SemanticError::MissingField("intent")),
        };
        let matched_capabilities = match int_map_get(val, 2) {
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| {
                    if let Value::TextString(s) = v {
                        Some(s.clone())
                    } else {
                        None
                    }
                })
                .collect(),
            _ => Vec::new(),
        };
        let estimated_cost = match int_map_get(val, 3) {
            Some(Value::Unsigned(n)) => *n,
            _ => 0,
        };
        let estimated_latency = match int_map_get(val, 4) {
            Some(Value::Unsigned(n)) => *n,
            _ => 0,
        };
        let confidence = match int_map_get(val, 5) {
            Some(Value::Unsigned(n)) => *n as f64 / 1_000_000.0,
            _ => 0.0,
        };
        Ok(Self {
            intent,
            matched_capabilities,
            estimated_cost,
            estimated_latency,
            confidence,
        })
    }
}

// ---------------------------------------------------------------------------
// IntentConfig
// ---------------------------------------------------------------------------

/// Configuration for the [`IntentResolver`].
#[derive(Clone, Debug)]
pub struct IntentConfig {
    /// Known capability names used by the default keyword parser. The parser
    /// scans the raw text for these (case-insensitive, word-boundary).
    pub known_capabilities: Vec<String>,
    /// Minimum confidence to accept a resolution (0.0 - 1.0). Resolutions
    /// below this threshold are still returned but flagged via the
    /// `confidence` field; callers should check it.
    pub confidence_threshold: f64,
    /// Maximum number of alternative resolutions to consider.
    pub max_alternatives: usize,
    /// Compound-intent separators used to split multi-intent requests.
    pub separators: Vec<String>,
}

impl Default for IntentConfig {
    fn default() -> Self {
        Self {
            known_capabilities: vec![
                "inference".into(),
                "translation".into(),
                "ocr".into(),
                "summarization".into(),
                "embedding".into(),
                "transcription".into(),
                "navigation".into(),
                "parsing".into(),
                "computation".into(),
                "perception".into(),
                "streaming".into(),
                "retrieval".into(),
                "code-generation".into(),
                "image-generation".into(),
                "speech-synthesis".into(),
            ],
            confidence_threshold: 0.5,
            max_alternatives: 3,
            separators: vec![
                " and then ".into(),
                " then ".into(),
                " after that ".into(),
                "; ".into(),
                " and ".into(),
            ],
        }
    }
}

// ---------------------------------------------------------------------------
// IntentParser trait
// ---------------------------------------------------------------------------

/// A pluggable intent parser.
///
/// The default implementation is [`DefaultParser`] (rule-based keyword
/// matching). An LLM-backed parser can implement this trait for richer
/// natural-language understanding.
pub trait IntentParser: Send + Sync {
    /// Parse raw text into an [`Intent`].
    ///
    /// `config` provides known capabilities and parsing rules.
    fn parse(&self, text: &str, config: &IntentConfig) -> Intent;
}

// ---------------------------------------------------------------------------
// DefaultParser
// ---------------------------------------------------------------------------

/// A simple keyword-based intent parser.
///
/// Extracts capability names by scanning for known capability keywords
/// (case-insensitive, word-boundary). Extracts constraints via regex-free
/// heuristic patterns:
/// - `latency under Nms` / `within Nms` → `MaxLatency(N)`
/// - `reputation at least N` / `reputation >= N` → `MinReputation(N)`
/// - `cost under N` / `cost <= N` / `under N credits` → `MaxCost(N)`
/// - `region: XX` / `in region XX` → `Region(XX)`
/// - `language: XX` / `in XX` (BCP 47) → `Language(XX)`
/// - `version X.Y.Z` / `capability version X.Y.Z` → `CapabilityVersion`
///
/// Priority keywords: `urgent`, `high priority`, `low priority`,
/// `background`.
pub struct DefaultParser;

impl Default for DefaultParser {
    fn default() -> Self {
        Self
    }
}

impl DefaultParser {
    /// Create a new `DefaultParser`.
    pub fn new() -> Self {
        Self
    }

    /// Extract capability names from text by matching against
    /// `known_capabilities` (case-insensitive substring match).
    fn extract_capabilities(text: &str, config: &IntentConfig) -> Vec<String> {
        let lower = text.to_lowercase();
        let mut found: Vec<String> = Vec::new();
        for cap in &config.known_capabilities {
            let cap_lower = cap.to_lowercase();
            if lower.contains(&cap_lower) {
                found.push(cap.clone());
            }
        }
        found
    }

    /// Extract constraints from text using heuristic patterns.
    fn extract_constraints(text: &str) -> Vec<IntentConstraint> {
        let lower = text.to_lowercase();
        let mut constraints = Vec::new();

        // MaxLatency: "latency under Nms", "within Nms", "under N ms"
        Self::extract_number_after(&lower, "latency under", |n| {
            Some(IntentConstraint::MaxLatency(n))
        })
        .into_iter()
        .for_each(|c| constraints.push(c));
        Self::extract_number_after(&lower, "within", |n| Some(IntentConstraint::MaxLatency(n)))
            .into_iter()
            .for_each(|c| constraints.push(c));

        // MinReputation: "reputation at least N", "reputation >= N"
        Self::extract_number_after(&lower, "reputation at least", |n| {
            if n <= u8::MAX as u64 {
                Some(IntentConstraint::MinReputation(n as u8))
            } else {
                None
            }
        })
        .into_iter()
        .for_each(|c| constraints.push(c));

        // MaxCost: "cost under N", "under N credits"
        Self::extract_number_after(&lower, "cost under", |n| Some(IntentConstraint::MaxCost(n)))
            .into_iter()
            .for_each(|c| constraints.push(c));

        // Region: "region: XX", "in region XX"
        if let Some(code) = Self::extract_token_after(&lower, "region:") {
            constraints.push(IntentConstraint::Region(code));
        } else if let Some(code) = Self::extract_token_after(&lower, "in region ") {
            constraints.push(IntentConstraint::Region(code));
        }

        // Language: "language: XX", "in language XX"
        if let Some(code) = Self::extract_token_after(&lower, "language:") {
            constraints.push(IntentConstraint::Language(code));
        }

        // CapabilityVersion: "version X.Y.Z"
        if let Some(ver) = Self::extract_version(&lower) {
            constraints.push(IntentConstraint::CapabilityVersion(ver));
        }

        constraints
    }

    /// Extract a number that appears immediately after `marker` in `text`.
    /// Returns the first match.
    fn extract_number_after<F>(text: &str, marker: &str, map: F) -> Vec<IntentConstraint>
    where
        F: Fn(u64) -> Option<IntentConstraint>,
    {
        if let Some(pos) = text.find(marker) {
            let rest = &text[pos + marker.len()..];
            let num_str: String = rest
                .chars()
                .skip_while(|c| c.is_whitespace())
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(n) = num_str.parse::<u64>() {
                if let Some(c) = map(n) {
                    return vec![c];
                }
            }
        }
        Vec::new()
    }

    /// Extract a short alphabetic token (1-8 chars) after `marker`.
    fn extract_token_after(text: &str, marker: &str) -> Option<String> {
        let pos = text.find(marker)?;
        let rest = &text[pos + marker.len()..];
        let token: String = rest
            .chars()
            .skip_while(|c| c.is_whitespace())
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
            .take(8)
            .collect();
        if token.is_empty() {
            None
        } else {
            Some(token)
        }
    }

    /// Extract a semantic version string (X.Y.Z) following the word
    /// "version".
    fn extract_version(text: &str) -> Option<String> {
        let pos = text.find("version")?;
        let rest = &text[pos + "version".len()..];
        let ver: String = rest
            .chars()
            .skip_while(|c| c.is_whitespace())
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        // Must contain at least one dot to look like a version.
        if ver.contains('.') {
            Some(ver)
        } else {
            None
        }
    }

    /// Infer priority from keywords.
    fn extract_priority(text: &str) -> IntentPriority {
        let lower = text.to_lowercase();
        if lower.contains("urgent") || lower.contains("asap") {
            IntentPriority::Urgent
        } else if lower.contains("high priority") || lower.contains("high-priority") {
            IntentPriority::High
        } else if lower.contains("low priority")
            || lower.contains("low-priority")
            || lower.contains("background")
        {
            IntentPriority::Low
        } else {
            IntentPriority::Normal
        }
    }

    /// Compute a confidence score for the parsed intent.
    ///
    /// Confidence is based on:
    /// - How many known capability keywords were matched (relative to text
    ///   length).
    /// - Whether any constraints were extracted.
    /// - Whether the text is non-trivially long.
    fn compute_confidence(text: &str, caps: &[String], constraints: &[IntentConstraint]) -> f64 {
        if caps.is_empty() {
            // No capabilities matched → very low confidence.
            return 0.1;
        }
        let word_count = text.split_whitespace().count().max(1);
        // Base confidence from capability coverage: more caps found → higher.
        let cap_factor = (caps.len() as f64 / word_count as f64).min(0.5);
        // Constraint bonus: each constraint adds confidence up to 0.3.
        let constraint_factor = (constraints.len() as f64 * 0.1).min(0.3);
        // A minimum base for having matched at least one capability.
        let base = 0.4;
        let confidence = base + cap_factor + constraint_factor;
        confidence.min(1.0)
    }
}

impl IntentParser for DefaultParser {
    fn parse(&self, text: &str, config: &IntentConfig) -> Intent {
        let caps = Self::extract_capabilities(text, config);
        let constraints = Self::extract_constraints(text);
        let priority = Self::extract_priority(text);
        Intent {
            raw_text: text.to_string(),
            parsed_capabilities: caps,
            constraints,
            priority,
            deadline_ms: 0,
            context: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// IntentResolver
// ---------------------------------------------------------------------------

/// Translates natural-language intent into structured capability queries and
/// resolves them against available capabilities.
pub struct IntentResolver {
    /// Configuration (known capabilities, thresholds, separators).
    config: IntentConfig,
    /// The pluggable parser.
    parser: Box<dyn IntentParser>,
}

impl IntentResolver {
    /// Create a new resolver with the given config and parser.
    pub fn new(config: IntentConfig, parser: Box<dyn IntentParser>) -> Self {
        Self { config, parser }
    }

    /// Create a new resolver with the default parser.
    pub fn with_default_parser(config: IntentConfig) -> Self {
        Self::new(config, Box::new(DefaultParser::new()))
    }

    /// Create a resolver with default config and default parser.
    pub fn default_resolver() -> Self {
        Self::with_default_parser(IntentConfig::default())
    }

    /// Return a reference to the config.
    pub fn config(&self) -> &IntentConfig {
        &self.config
    }

    /// Parse raw text into a single [`Intent`].
    ///
    /// For compound requests, use [`parse_intents`](Self::parse_intents)
    /// to get multiple intents.
    pub fn parse_intent(&self, text: &str) -> Intent {
        self.parser.parse(text, &self.config)
    }

    /// Parse a compound request into multiple [`Intent`]s.
    ///
    /// Splits the text on configured separators and parses each segment
    /// independently. Segments that yield no capabilities are still
    /// included (with empty `parsed_capabilities`) so callers can inspect
    /// them.
    pub fn parse_intents(&self, text: &str) -> Vec<Intent> {
        let segments = self.split_compound(text);
        if segments.len() <= 1 {
            return vec![self.parse_intent(text)];
        }
        segments
            .into_iter()
            .map(|s| self.parse_intent(&s))
            .collect()
    }

    /// Split text on compound separators, preserving order.
    fn split_compound(&self, text: &str) -> Vec<String> {
        let mut segments: Vec<String> = Vec::new();
        let mut remaining = text.to_string();
        loop {
            let lower_remaining = remaining.to_lowercase();
            let earliest = self
                .config
                .separators
                .iter()
                .filter_map(|sep| lower_remaining.find(sep.as_str()).map(|pos| (pos, sep)))
                .min_by_key(|(pos, _)| *pos);
            match earliest {
                Some((pos, sep)) => {
                    let head = remaining[..pos].trim().to_string();
                    if !head.is_empty() {
                        segments.push(head);
                    }
                    remaining = remaining[pos + sep.len()..].trim().to_string();
                }
                None => {
                    if !remaining.is_empty() {
                        segments.push(remaining);
                    }
                    break;
                }
            }
        }
        if segments.is_empty() {
            vec![text.to_string()]
        } else {
            segments
        }
    }

    /// Resolve an [`Intent`] against a set of available capability names.
    ///
    /// `available` is the list of capability names known to be offered by
    /// the network (e.g. from the DHT or local index). The resolver matches
    /// `intent.parsed_capabilities` against `available`, computes estimated
    /// cost/latency from constraints, and assigns a confidence score.
    ///
    /// Returns a [`ResolvedIntent`]. If no capabilities matched,
    /// `matched_capabilities` is empty and `confidence` reflects the parse
    /// quality only.
    pub fn resolve(&self, intent: &Intent, available: &[String]) -> ResolvedIntent {
        let available_set: std::collections::HashSet<&str> =
            available.iter().map(|s| s.as_str()).collect();
        let matched: Vec<String> = intent
            .parsed_capabilities
            .iter()
            .filter(|c| available_set.contains(c.as_str()))
            .cloned()
            .collect();

        // Estimate cost and latency from constraints.
        let mut estimated_cost: u64 = 0;
        let mut estimated_latency: u64 = 0;
        for c in &intent.constraints {
            match c {
                IntentConstraint::MaxCost(credits) => estimated_cost = estimated_cost.max(*credits),
                IntentConstraint::MaxLatency(ms) => {
                    estimated_latency = estimated_latency.max(*ms);
                }
                _ => {}
            }
        }
        // If no explicit cost/latency constraints, use heuristics based on
        // priority and matched-capability count.
        if estimated_latency == 0 {
            estimated_latency = match intent.priority {
                IntentPriority::Urgent => 100,
                IntentPriority::High => 500,
                IntentPriority::Normal => 2000,
                IntentPriority::Low => 10_000,
            };
        }
        if estimated_cost == 0 {
            // Base cost per matched capability; urgent costs more.
            let per_cap = match intent.priority {
                IntentPriority::Urgent => 500,
                IntentPriority::High => 200,
                IntentPriority::Normal => 100,
                IntentPriority::Low => 50,
            };
            estimated_cost = per_cap * matched.len() as u64;
        }

        // Confidence: parse quality × match ratio.
        let parse_conf = DefaultParser::compute_confidence(
            &intent.raw_text,
            &intent.parsed_capabilities,
            &intent.constraints,
        );
        let match_ratio = if intent.parsed_capabilities.is_empty() {
            0.0
        } else {
            matched.len() as f64 / intent.parsed_capabilities.len() as f64
        };
        // Confidence is the product of parse quality and match ratio.
        // When no capabilities are matched, confidence is low regardless of
        // parse quality.
        let confidence = (parse_conf * match_ratio).min(1.0);

        ResolvedIntent {
            intent: intent.clone(),
            matched_capabilities: matched,
            estimated_cost,
            estimated_latency,
            confidence,
        }
    }

    /// Convenience: parse text and resolve in one call.
    pub fn parse_and_resolve(&self, text: &str, available: &[String]) -> ResolvedIntent {
        let intent = self.parse_intent(text);
        self.resolve(&intent, available)
    }

    /// Convert an [`Intent`] into a [`CapabilityQuery`] for the first parsed
    /// capability. Returns `None` if no capabilities were parsed.
    ///
    /// Constraint-to-filter translation is deferred to the evaluation engine;
    /// here we attach only the capability name. When the query module's
    /// filter types are needed, they can be wired in here.
    pub fn to_capability_query(&self, intent: &Intent) -> Option<CapabilityQuery> {
        let first_cap = intent.parsed_capabilities.first()?;
        Some(CapabilityQuery::new(first_cap.clone()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- IntentConstraint ------------------------------------------------

    #[test]
    fn test_constraint_max_latency_cbor_roundtrip() {
        let c = IntentConstraint::MaxLatency(500);
        let encoded = c.to_cbor();
        let decoded = IntentConstraint::from_cbor(&encoded).expect("decode");
        assert_eq!(decoded, c);
    }

    #[test]
    fn test_constraint_min_reputation_cbor_roundtrip() {
        let c = IntentConstraint::MinReputation(80);
        let encoded = c.to_cbor();
        let decoded = IntentConstraint::from_cbor(&encoded).expect("decode");
        assert_eq!(decoded, c);
    }

    #[test]
    fn test_constraint_max_cost_cbor_roundtrip() {
        let c = IntentConstraint::MaxCost(1_000_000);
        let encoded = c.to_cbor();
        let decoded = IntentConstraint::from_cbor(&encoded).expect("decode");
        assert_eq!(decoded, c);
    }

    #[test]
    fn test_constraint_region_cbor_roundtrip() {
        let c = IntentConstraint::Region("us".into());
        let encoded = c.to_cbor();
        let decoded = IntentConstraint::from_cbor(&encoded).expect("decode");
        assert_eq!(decoded, c);
    }

    #[test]
    fn test_constraint_language_cbor_roundtrip() {
        let c = IntentConstraint::Language("zh-Hans".into());
        let encoded = c.to_cbor();
        let decoded = IntentConstraint::from_cbor(&encoded).expect("decode");
        assert_eq!(decoded, c);
    }

    #[test]
    fn test_constraint_capability_version_cbor_roundtrip() {
        let c = IntentConstraint::CapabilityVersion("2.1.0".into());
        let encoded = c.to_cbor();
        let decoded = IntentConstraint::from_cbor(&encoded).expect("decode");
        assert_eq!(decoded, c);
    }

    #[test]
    fn test_constraint_invalid_discriminant() {
        let val = int_map(vec![(0, Value::Unsigned(99)), (1, Value::Unsigned(0))]);
        let err = IntentConstraint::from_cbor(&val).unwrap_err();
        assert!(matches!(
            err,
            SemanticError::InvalidField { field, .. } if field == "constraint.discriminant"
        ));
    }

    // --- IntentPriority --------------------------------------------------

    #[test]
    fn test_priority_default_is_normal() {
        let p = IntentPriority::default();
        assert_eq!(p, IntentPriority::Normal);
    }

    #[test]
    fn test_priority_ordering() {
        assert!(IntentPriority::Urgent > IntentPriority::High);
        assert!(IntentPriority::High > IntentPriority::Normal);
        assert!(IntentPriority::Normal > IntentPriority::Low);
    }

    #[test]
    fn test_priority_cbor_roundtrip_all_variants() {
        for p in [
            IntentPriority::Low,
            IntentPriority::Normal,
            IntentPriority::High,
            IntentPriority::Urgent,
        ] {
            let encoded = p.to_cbor();
            let decoded = IntentPriority::from_cbor(&encoded).expect("decode");
            assert_eq!(decoded, p);
        }
    }

    // --- Intent ----------------------------------------------------------

    #[test]
    fn test_intent_default() {
        let i = Intent::default();
        assert!(i.raw_text.is_empty());
        assert!(i.parsed_capabilities.is_empty());
        assert!(i.constraints.is_empty());
        assert_eq!(i.priority, IntentPriority::Normal);
        assert_eq!(i.deadline_ms, 0);
        assert!(i.context.is_empty());
    }

    #[test]
    fn test_intent_builder() {
        let i = Intent::new("translate this")
            .with_capability("translation")
            .with_constraint(IntentConstraint::Language("en".into()))
            .with_priority(IntentPriority::High)
            .with_deadline_ms(5000)
            .with_context("session", "abc123");
        assert_eq!(i.raw_text, "translate this");
        assert_eq!(i.parsed_capabilities, vec!["translation"]);
        assert_eq!(i.priority, IntentPriority::High);
        assert_eq!(i.deadline_ms, 5000);
        assert_eq!(i.context.get("session"), Some(&"abc123".to_string()));
    }

    #[test]
    fn test_intent_cbor_roundtrip_simple() {
        let i = Intent::new("do inference")
            .with_capability("inference")
            .with_priority(IntentPriority::Urgent);
        let encoded = i.to_cbor();
        let decoded = Intent::from_cbor(&encoded).expect("decode");
        assert_eq!(decoded.raw_text, i.raw_text);
        assert_eq!(decoded.parsed_capabilities, i.parsed_capabilities);
        assert_eq!(decoded.priority, i.priority);
    }

    #[test]
    fn test_intent_cbor_roundtrip_with_constraints_and_context() {
        let i = Intent::new("ocr with low latency")
            .with_capability("ocr")
            .with_constraint(IntentConstraint::MaxLatency(200))
            .with_constraint(IntentConstraint::Region("eu".into()))
            .with_context("user", "alice")
            .with_context("trace", "t1");
        let encoded = i.to_cbor();
        let decoded = Intent::from_cbor(&encoded).expect("decode");
        assert_eq!(decoded.raw_text, i.raw_text);
        assert_eq!(decoded.parsed_capabilities, i.parsed_capabilities);
        assert_eq!(decoded.constraints.len(), 2);
        assert_eq!(decoded.context.get("user"), Some(&"alice".to_string()));
        assert_eq!(decoded.context.get("trace"), Some(&"t1".to_string()));
    }

    #[test]
    fn test_intent_cbor_missing_raw_text_errors() {
        let val = int_map(vec![(2, Value::Array(vec![]))]);
        let err = Intent::from_cbor(&val).unwrap_err();
        assert!(matches!(err, SemanticError::MissingField("raw_text")));
    }

    // --- ResolvedIntent --------------------------------------------------

    #[test]
    fn test_resolved_intent_cbor_roundtrip() {
        let intent = Intent::new("inference")
            .with_capability("inference")
            .with_priority(IntentPriority::High);
        let resolved = ResolvedIntent {
            intent,
            matched_capabilities: vec!["inference".into()],
            estimated_cost: 200,
            estimated_latency: 500,
            confidence: 0.85,
        };
        let encoded = resolved.to_cbor();
        let decoded = ResolvedIntent::from_cbor(&encoded).expect("decode");
        assert_eq!(decoded.matched_capabilities, resolved.matched_capabilities);
        assert_eq!(decoded.estimated_cost, resolved.estimated_cost);
        assert_eq!(decoded.estimated_latency, resolved.estimated_latency);
        assert!((decoded.confidence - resolved.confidence).abs() < 1e-6);
    }

    // --- DefaultParser: capability extraction ----------------------------

    #[test]
    fn test_parser_extracts_single_capability() {
        let resolver = IntentResolver::default_resolver();
        let intent = resolver.parse_intent("I need inference");
        assert_eq!(intent.parsed_capabilities, vec!["inference"]);
    }

    #[test]
    fn test_parser_extracts_multiple_capabilities() {
        let resolver = IntentResolver::default_resolver();
        let intent = resolver.parse_intent("do ocr and then translation");
        assert!(intent.parsed_capabilities.contains(&"ocr".to_string()));
        assert!(intent
            .parsed_capabilities
            .contains(&"translation".to_string()));
    }

    #[test]
    fn test_parser_case_insensitive_capability_match() {
        let resolver = IntentResolver::default_resolver();
        let intent = resolver.parse_intent("Please run INFERENCE for me");
        assert_eq!(intent.parsed_capabilities, vec!["inference"]);
    }

    #[test]
    fn test_parser_no_capabilities_matched() {
        let resolver = IntentResolver::default_resolver();
        let intent = resolver.parse_intent("hello world, how are you?");
        assert!(intent.parsed_capabilities.is_empty());
    }

    // --- DefaultParser: constraint extraction ----------------------------

    #[test]
    fn test_parser_extracts_max_latency() {
        let resolver = IntentResolver::default_resolver();
        let intent = resolver.parse_intent("inference with latency under 300ms");
        assert!(intent
            .constraints
            .iter()
            .any(|c| matches!(c, IntentConstraint::MaxLatency(300))));
    }

    #[test]
    fn test_parser_extracts_min_reputation() {
        let resolver = IntentResolver::default_resolver();
        let intent = resolver.parse_intent("inference with reputation at least 75");
        assert!(intent
            .constraints
            .iter()
            .any(|c| matches!(c, IntentConstraint::MinReputation(75))));
    }

    #[test]
    fn test_parser_extracts_max_cost() {
        let resolver = IntentResolver::default_resolver();
        let intent = resolver.parse_intent("inference with cost under 5000");
        assert!(intent
            .constraints
            .iter()
            .any(|c| matches!(c, IntentConstraint::MaxCost(5000))));
    }

    #[test]
    fn test_parser_extracts_region() {
        let resolver = IntentResolver::default_resolver();
        let intent = resolver.parse_intent("inference in region eu");
        assert!(intent
            .constraints
            .iter()
            .any(|c| matches!(c, IntentConstraint::Region(ref r) if r == "eu")));
    }

    #[test]
    fn test_parser_extracts_language() {
        let resolver = IntentResolver::default_resolver();
        let intent = resolver.parse_intent("translation language: en");
        assert!(intent
            .constraints
            .iter()
            .any(|c| matches!(c, IntentConstraint::Language(ref l) if l == "en")));
    }

    #[test]
    fn test_parser_extracts_capability_version() {
        let resolver = IntentResolver::default_resolver();
        let intent = resolver.parse_intent("inference version 2.1.0");
        assert!(intent
            .constraints
            .iter()
            .any(|c| matches!(c, IntentConstraint::CapabilityVersion(ref v) if v == "2.1.0")));
    }

    // --- DefaultParser: priority -----------------------------------------

    #[test]
    fn test_parser_priority_urgent() {
        let resolver = IntentResolver::default_resolver();
        let intent = resolver.parse_intent("urgent inference please");
        assert_eq!(intent.priority, IntentPriority::Urgent);
    }

    #[test]
    fn test_parser_priority_high() {
        let resolver = IntentResolver::default_resolver();
        let intent = resolver.parse_intent("high priority inference");
        assert_eq!(intent.priority, IntentPriority::High);
    }

    #[test]
    fn test_parser_priority_low_background() {
        let resolver = IntentResolver::default_resolver();
        let intent = resolver.parse_intent("background summarization");
        assert_eq!(intent.priority, IntentPriority::Low);
    }

    #[test]
    fn test_parser_priority_normal_default() {
        let resolver = IntentResolver::default_resolver();
        let intent = resolver.parse_intent("inference please");
        assert_eq!(intent.priority, IntentPriority::Normal);
    }

    // --- Confidence scoring ----------------------------------------------

    #[test]
    fn test_confidence_low_when_no_capabilities() {
        let conf = DefaultParser::compute_confidence("hello world", &[], &[]);
        assert!(conf < 0.2);
    }

    #[test]
    fn test_confidence_higher_with_constraints() {
        let conf_no = DefaultParser::compute_confidence("inference", &["inference".into()], &[]);
        let conf_with = DefaultParser::compute_confidence(
            "inference",
            &["inference".into()],
            &[IntentConstraint::MaxLatency(100)],
        );
        assert!(conf_with > conf_no);
    }

    #[test]
    fn test_confidence_capped_at_one() {
        let conf = DefaultParser::compute_confidence(
            "inference",
            &["inference".into()],
            &[
                IntentConstraint::MaxLatency(100),
                IntentConstraint::MaxCost(50),
                IntentConstraint::MinReputation(90),
                IntentConstraint::Region("us".into()),
            ],
        );
        assert!(conf <= 1.0);
    }

    // --- Multi-intent parsing --------------------------------------------

    #[test]
    fn test_parse_intents_single() {
        let resolver = IntentResolver::default_resolver();
        let intents = resolver.parse_intents("do inference");
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].parsed_capabilities, vec!["inference"]);
    }

    #[test]
    fn test_parse_intents_compound_and_then() {
        let resolver = IntentResolver::default_resolver();
        let intents = resolver.parse_intents("do ocr and then translation");
        assert_eq!(intents.len(), 2);
        assert_eq!(intents[0].parsed_capabilities, vec!["ocr"]);
        assert!(intents[1]
            .parsed_capabilities
            .contains(&"translation".to_string()));
    }

    #[test]
    fn test_parse_intents_compound_semicolon() {
        let resolver = IntentResolver::default_resolver();
        let intents = resolver.parse_intents("summarization; embedding");
        assert_eq!(intents.len(), 2);
        assert!(intents[0]
            .parsed_capabilities
            .contains(&"summarization".to_string()));
        assert!(intents[1]
            .parsed_capabilities
            .contains(&"embedding".to_string()));
    }

    // --- resolve() -------------------------------------------------------

    #[test]
    fn test_resolve_all_matched() {
        let resolver = IntentResolver::default_resolver();
        let intent = resolver.parse_intent("inference and translation");
        let available = vec!["inference".into(), "translation".into()];
        let resolved = resolver.resolve(&intent, &available);
        assert_eq!(resolved.matched_capabilities.len(), 2);
        assert!(resolved.confidence > 0.5);
    }

    #[test]
    fn test_resolve_partial_match() {
        let resolver = IntentResolver::default_resolver();
        let intent = resolver.parse_intent("inference and translation");
        let available = vec!["inference".into()];
        let resolved = resolver.resolve(&intent, &available);
        assert_eq!(resolved.matched_capabilities, vec!["inference"]);
        // Partial match → confidence lower than full match.
        assert!(resolved.confidence < 1.0);
    }

    #[test]
    fn test_resolve_no_match() {
        let resolver = IntentResolver::default_resolver();
        let intent = resolver.parse_intent("inference");
        let available: Vec<String> = vec![];
        let resolved = resolver.resolve(&intent, &available);
        assert!(resolved.matched_capabilities.is_empty());
        assert!(resolved.confidence < 0.5);
    }

    #[test]
    fn test_resolve_uses_latency_constraint() {
        let resolver = IntentResolver::default_resolver();
        let intent = Intent::new("inference")
            .with_capability("inference")
            .with_constraint(IntentConstraint::MaxLatency(250));
        let resolved = resolver.resolve(&intent, &["inference".to_string()]);
        assert_eq!(resolved.estimated_latency, 250);
    }

    #[test]
    fn test_resolve_uses_cost_constraint() {
        let resolver = IntentResolver::default_resolver();
        let intent = Intent::new("inference")
            .with_capability("inference")
            .with_constraint(IntentConstraint::MaxCost(9999));
        let resolved = resolver.resolve(&intent, &["inference".to_string()]);
        assert_eq!(resolved.estimated_cost, 9999);
    }

    #[test]
    fn test_resolve_priority_based_latency_heuristic() {
        let resolver = IntentResolver::default_resolver();
        let urgent = Intent::new("inference")
            .with_capability("inference")
            .with_priority(IntentPriority::Urgent);
        let low = Intent::new("inference")
            .with_capability("inference")
            .with_priority(IntentPriority::Low);
        let avail = vec!["inference".to_string()];
        let r_urgent = resolver.resolve(&urgent, &avail);
        let r_low = resolver.resolve(&low, &avail);
        assert!(r_urgent.estimated_latency < r_low.estimated_latency);
        assert!(r_urgent.estimated_cost > r_low.estimated_cost);
    }

    // --- parse_and_resolve convenience -----------------------------------

    #[test]
    fn test_parse_and_resolve() {
        let resolver = IntentResolver::default_resolver();
        let resolved = resolver.parse_and_resolve("urgent inference", &["inference".to_string()]);
        assert_eq!(resolved.matched_capabilities, vec!["inference"]);
        assert_eq!(resolved.intent.priority, IntentPriority::Urgent);
    }

    // --- to_capability_query ---------------------------------------------

    #[test]
    fn test_to_capability_query_with_capability() {
        let resolver = IntentResolver::default_resolver();
        let intent = Intent::new("inference").with_capability("inference");
        let query = resolver.to_capability_query(&intent).expect("some");
        assert_eq!(query.name, "inference");
    }

    #[test]
    fn test_to_capability_query_no_capability_returns_none() {
        let resolver = IntentResolver::default_resolver();
        let intent = Intent::new("hello");
        assert!(resolver.to_capability_query(&intent).is_none());
    }

    // --- Custom parser via trait -----------------------------------------

    #[test]
    fn test_custom_parser_pluggable() {
        struct EchoParser;
        impl IntentParser for EchoParser {
            fn parse(&self, text: &str, _config: &IntentConfig) -> Intent {
                Intent::new(text).with_capability("echo")
            }
        }
        let resolver = IntentResolver::new(IntentConfig::default(), Box::new(EchoParser));
        let intent = resolver.parse_intent("anything");
        assert_eq!(intent.parsed_capabilities, vec!["echo"]);
    }

    // --- IntentConfig ----------------------------------------------------

    #[test]
    fn test_intent_config_default_has_known_capabilities() {
        let cfg = IntentConfig::default();
        assert!(!cfg.known_capabilities.is_empty());
        assert!(cfg.known_capabilities.contains(&"inference".to_string()));
        assert_eq!(cfg.confidence_threshold, 0.5);
        assert!(cfg.max_alternatives >= 1);
    }

    #[test]
    fn test_intent_config_custom_capabilities() {
        let cfg = IntentConfig {
            known_capabilities: vec!["custom-cap".into()],
            ..Default::default()
        };
        let resolver = IntentResolver::with_default_parser(cfg);
        let intent = resolver.parse_intent("run custom-cap now");
        assert_eq!(intent.parsed_capabilities, vec!["custom-cap"]);
    }

    // --- split_compound edge cases ---------------------------------------

    #[test]
    fn test_split_compound_no_separator() {
        let resolver = IntentResolver::default_resolver();
        let segments = resolver.split_compound("just one intent here");
        assert_eq!(segments.len(), 1);
    }

    #[test]
    fn test_split_compound_multiple_separators() {
        let resolver = IntentResolver::default_resolver();
        let segments = resolver.split_compound("ocr and then translation; embedding");
        assert!(segments.len() >= 2);
    }

    #[test]
    fn test_split_compound_empty_string() {
        let resolver = IntentResolver::default_resolver();
        let segments = resolver.split_compound("");
        // Empty string yields a single empty segment (preserving the input).
        assert_eq!(segments, vec!["".to_string()]);
    }

    // --- ResolvedIntent confidence with deadline -------------------------

    #[test]
    fn test_intent_with_deadline_cbor_roundtrip() {
        let i = Intent::new("urgent inference")
            .with_capability("inference")
            .with_priority(IntentPriority::Urgent)
            .with_deadline_ms(10_000);
        let encoded = i.to_cbor();
        let decoded = Intent::from_cbor(&encoded).expect("decode");
        assert_eq!(decoded.deadline_ms, 10_000);
    }

    #[test]
    fn test_resolved_intent_empty_match_has_low_confidence() {
        let resolver = IntentResolver::default_resolver();
        let intent = resolver.parse_intent("inference");
        let resolved = resolver.resolve(&intent, &[]);
        assert!(resolved.confidence < 0.5);
        assert!(resolved.matched_capabilities.is_empty());
    }

    #[test]
    fn test_resolved_intent_full_match_high_confidence() {
        let resolver = IntentResolver::default_resolver();
        let intent = resolver.parse_intent("inference with latency under 100ms");
        let resolved = resolver.resolve(&intent, &["inference".to_string()]);
        assert!(resolved.confidence > 0.6);
        assert_eq!(resolved.matched_capabilities, vec!["inference"]);
    }
}
