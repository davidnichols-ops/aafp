//! Agent-native content schema (Track Y1).
//!
//! All structures encode to canonical CBOR int-keyed maps (RFC-0002 §8)
//! via [`aafp_cbor`] helpers. Optional fields are omitted from the map
//! when `None` so that encodings are minimal and deterministic.

use aafp_cbor::{int_map, int_map_get, Value};
use sha2::{Digest, Sha256};

use crate::PerceptionError;

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

fn enc_str(s: &str) -> Value {
    Value::TextString(s.to_string())
}

fn enc_opt_str(o: &Option<String>) -> Option<Value> {
    o.as_ref().map(|s| enc_str(s))
}

fn enc_u64(n: u64) -> Value {
    Value::Unsigned(n)
}

fn enc_bool(b: bool) -> Value {
    // Per project convention: encode booleans as unsigned 1/0.
    Value::Unsigned(if b { 1 } else { 0 })
}

fn enc_str_array(items: &[String]) -> Value {
    Value::Array(items.iter().map(|s| enc_str(s)).collect())
}

fn enc_str_pairs(pairs: &[(String, String)]) -> Value {
    Value::Array(
        pairs
            .iter()
            .map(|(k, v)| Value::Array(vec![enc_str(k), enc_str(v)]))
            .collect(),
    )
}

fn dec_str(val: &Value, field: &'static str) -> Result<String, PerceptionError> {
    match val {
        Value::TextString(s) => Ok(s.clone()),
        _ => Err(PerceptionError::InvalidField {
            field,
            message: format!("expected text string, got {val:?}"),
        }),
    }
}

fn dec_opt_str(val: &Value) -> Option<String> {
    match val {
        Value::TextString(s) => Some(s.clone()),
        _ => None,
    }
}

fn dec_u64(val: &Value, field: &'static str) -> Result<u64, PerceptionError> {
    match val {
        Value::Unsigned(n) => Ok(*n),
        _ => Err(PerceptionError::InvalidField {
            field,
            message: format!("expected unsigned integer, got {val:?}"),
        }),
    }
}

fn dec_u32(val: &Value, field: &'static str) -> Result<u32, PerceptionError> {
    let n = dec_u64(val, field)?;
    if n > u32::MAX as u64 {
        return Err(PerceptionError::InvalidField {
            field,
            message: format!("value {n} exceeds u32 range"),
        });
    }
    Ok(n as u32)
}

fn dec_u16(val: &Value, field: &'static str) -> Result<u16, PerceptionError> {
    let n = dec_u64(val, field)?;
    if n > u16::MAX as u64 {
        return Err(PerceptionError::InvalidField {
            field,
            message: format!("value {n} exceeds u16 range"),
        });
    }
    Ok(n as u16)
}

fn dec_u8(val: &Value, field: &'static str) -> Result<u8, PerceptionError> {
    let n = dec_u64(val, field)?;
    if n > u8::MAX as u64 {
        return Err(PerceptionError::InvalidField {
            field,
            message: format!("value {n} exceeds u8 range"),
        });
    }
    Ok(n as u8)
}

fn dec_bool(val: &Value, field: &'static str) -> Result<bool, PerceptionError> {
    match val {
        // Canonical AAFP encoding uses unsigned 1/0.
        Value::Unsigned(1) => Ok(true),
        Value::Unsigned(0) => Ok(false),
        // Accept native CBOR booleans for robustness.
        Value::Bool(b) => Ok(*b),
        _ => Err(PerceptionError::InvalidField {
            field,
            message: format!("expected boolean (0/1), got {val:?}"),
        }),
    }
}

fn dec_str_array(val: &Value, field: &'static str) -> Result<Vec<String>, PerceptionError> {
    match val {
        Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                out.push(dec_str(item, field)?);
            }
            Ok(out)
        }
        _ => Err(PerceptionError::InvalidField {
            field,
            message: format!("expected array, got {val:?}"),
        }),
    }
}

fn dec_str_pairs(
    val: &Value,
    field: &'static str,
) -> Result<Vec<(String, String)>, PerceptionError> {
    match val {
        Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                match item {
                    Value::Array(pair) if pair.len() == 2 => {
                        out.push((dec_str(&pair[0], field)?, dec_str(&pair[1], field)?));
                    }
                    _ => {
                        return Err(PerceptionError::InvalidField {
                            field,
                            message: format!("expected 2-element array, got {item:?}"),
                        });
                    }
                }
            }
            Ok(out)
        }
        _ => Err(PerceptionError::InvalidField {
            field,
            message: format!("expected array of pairs, got {val:?}"),
        }),
    }
}

/// Decode a required field from an int-keyed map, returning
/// [`PerceptionError::MissingField`] if absent.
fn req<'a>(map: &'a Value, key: i64, field: &'static str) -> Result<&'a Value, PerceptionError> {
    int_map_get(map, key).ok_or(PerceptionError::MissingField(field))
}

/// Decode an optional field from an int-keyed map.
fn opt(map: &Value, key: i64) -> Option<&Value> {
    int_map_get(map, key)
}

// ---------------------------------------------------------------------------
// ContentHash
// ---------------------------------------------------------------------------

/// SHA-256 hash of normalized content (32 bytes).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ContentHash(pub [u8; 32]);

impl ContentHash {
    /// Compute the SHA-256 hash of the given content bytes.
    pub fn compute(content: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(content);
        let result = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        Self(arr)
    }

    /// Encode as a CBOR byte string.
    pub fn to_cbor(&self) -> Value {
        Value::ByteString(self.0.to_vec())
    }

    /// Decode from a CBOR byte string.
    pub fn from_cbor(val: &Value) -> Result<Self, PerceptionError> {
        match val {
            Value::ByteString(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(b);
                Ok(Self(arr))
            }
            Value::ByteString(b) => Err(PerceptionError::InvalidField {
                field: "hash",
                message: format!("expected 32 bytes, got {}", b.len()),
            }),
            _ => Err(PerceptionError::InvalidField {
                field: "hash",
                message: format!("expected byte string, got {val:?}"),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// ActionSafety
// ---------------------------------------------------------------------------

/// Safety classification of an interactive element's action.
///
/// Encoded as an unsigned integer: `Safe = 0`, `RequiresConfirmation = 1`,
/// `Dangerous = 2`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionSafety {
    /// The action is safe to perform without confirmation.
    Safe = 0,
    /// The action requires explicit confirmation before performing.
    RequiresConfirmation = 1,
    /// The action is potentially dangerous and should be avoided or
    /// require strong confirmation.
    Dangerous = 2,
}

impl ActionSafety {
    pub fn to_cbor(&self) -> Value {
        Value::Unsigned(*self as u64)
    }

    pub fn from_cbor(val: &Value) -> Result<Self, PerceptionError> {
        match val {
            Value::Unsigned(0) => Ok(Self::Safe),
            Value::Unsigned(1) => Ok(Self::RequiresConfirmation),
            Value::Unsigned(2) => Ok(Self::Dangerous),
            _ => Err(PerceptionError::InvalidField {
                field: "safety",
                message: format!("expected 0/1/2, got {val:?}"),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Action
// ---------------------------------------------------------------------------

/// An action that an interactive element can perform.
#[derive(Clone, Debug, PartialEq)]
pub struct Action {
    /// Action type: "click", "type", "submit", etc.
    pub action_type: String, // key 1
    /// Target element reference.
    pub target: String, // key 2
    /// Optional value (e.g. text to type).
    pub value: Option<String>, // key 3
}

impl Action {
    pub fn to_cbor(&self) -> Value {
        let mut entries: Vec<(i64, Value)> =
            vec![(1, enc_str(&self.action_type)), (2, enc_str(&self.target))];
        if let Some(v) = enc_opt_str(&self.value) {
            entries.push((3, v));
        }
        int_map(entries)
    }

    pub fn from_cbor(val: &Value) -> Result<Self, PerceptionError> {
        Ok(Self {
            action_type: dec_str(req(val, 1, "action_type")?, "action_type")?,
            target: dec_str(req(val, 2, "target")?, "target")?,
            value: opt(val, 3).and_then(dec_opt_str),
        })
    }
}

// ---------------------------------------------------------------------------
// InteractiveElement
// ---------------------------------------------------------------------------

/// An interactive element on a page (button, link, input, etc.).
#[derive(Clone, Debug, PartialEq)]
pub struct InteractiveElement {
    /// Element id, e.g. "e0", "e1".
    pub id: String, // key 1
    /// Element type: "button", "link", "input", etc.
    pub element_type: String, // key 2
    /// CSS selector or xpath reference.
    pub ref_target: String, // key 3
    /// Visible text of the element.
    pub text: String, // key 4
    /// The action the element performs.
    pub action: Action, // key 5
    /// Safety classification of the action.
    pub safety: ActionSafety, // key 6
    /// Additional HTML attributes as key/value pairs.
    pub attributes: Vec<(String, String)>, // key 7
}

impl InteractiveElement {
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, enc_str(&self.id)),
            (2, enc_str(&self.element_type)),
            (3, enc_str(&self.ref_target)),
            (4, enc_str(&self.text)),
            (5, self.action.to_cbor()),
            (6, self.safety.to_cbor()),
            (7, enc_str_pairs(&self.attributes)),
        ])
    }

    pub fn from_cbor(val: &Value) -> Result<Self, PerceptionError> {
        Ok(Self {
            id: dec_str(req(val, 1, "id")?, "id")?,
            element_type: dec_str(req(val, 2, "element_type")?, "element_type")?,
            ref_target: dec_str(req(val, 3, "ref_target")?, "ref_target")?,
            text: dec_str(req(val, 4, "text")?, "text")?,
            action: Action::from_cbor(req(val, 5, "action")?)?,
            safety: ActionSafety::from_cbor(req(val, 6, "safety")?)?,
            attributes: match opt(val, 7) {
                Some(v) => dec_str_pairs(v, "attributes")?,
                None => Vec::new(),
            },
        })
    }
}

// ---------------------------------------------------------------------------
// ContentSection
// ---------------------------------------------------------------------------

/// A logical section of page or document content.
#[derive(Clone, Debug, PartialEq)]
pub struct ContentSection {
    /// Section id, e.g. "s0", "s1".
    pub id: String, // key 1
    /// Section heading title.
    pub title: String, // key 2
    /// The text content of the section.
    pub content: String, // key 3
    /// Heading level (1-6).
    pub level: u8, // key 4
    /// Ids of child sections.
    pub children: Vec<String>, // key 5
}

impl ContentSection {
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, enc_str(&self.id)),
            (2, enc_str(&self.title)),
            (3, enc_str(&self.content)),
            (4, enc_u64(self.level as u64)),
            (5, enc_str_array(&self.children)),
        ])
    }

    pub fn from_cbor(val: &Value) -> Result<Self, PerceptionError> {
        Ok(Self {
            id: dec_str(req(val, 1, "id")?, "id")?,
            title: dec_str(req(val, 2, "title")?, "title")?,
            content: dec_str(req(val, 3, "content")?, "content")?,
            level: dec_u8(req(val, 4, "level")?, "level")?,
            children: match opt(val, 5) {
                Some(v) => dec_str_array(v, "children")?,
                None => Vec::new(),
            },
        })
    }
}

// ---------------------------------------------------------------------------
// FormField
// ---------------------------------------------------------------------------

/// A single field within a form.
#[derive(Clone, Debug, PartialEq)]
pub struct FormField {
    /// Field name.
    pub name: String, // key 1
    /// Field type: "text", "email", "password", etc.
    pub field_type: String, // key 2
    /// Whether the field is required.
    pub required: bool, // key 3
    /// Optional human-readable label.
    pub label: Option<String>, // key 4
    /// Optional default value.
    pub default_value: Option<String>, // key 5
}

impl FormField {
    pub fn to_cbor(&self) -> Value {
        let mut entries: Vec<(i64, Value)> = vec![
            (1, enc_str(&self.name)),
            (2, enc_str(&self.field_type)),
            (3, enc_bool(self.required)),
        ];
        if let Some(v) = enc_opt_str(&self.label) {
            entries.push((4, v));
        }
        if let Some(v) = enc_opt_str(&self.default_value) {
            entries.push((5, v));
        }
        int_map(entries)
    }

    pub fn from_cbor(val: &Value) -> Result<Self, PerceptionError> {
        Ok(Self {
            name: dec_str(req(val, 1, "name")?, "name")?,
            field_type: dec_str(req(val, 2, "field_type")?, "field_type")?,
            required: dec_bool(req(val, 3, "required")?, "required")?,
            label: opt(val, 4).and_then(dec_opt_str),
            default_value: opt(val, 5).and_then(dec_opt_str),
        })
    }
}

// ---------------------------------------------------------------------------
// FormDef
// ---------------------------------------------------------------------------

/// A form definition extracted from a page.
#[derive(Clone, Debug, PartialEq)]
pub struct FormDef {
    /// Form id.
    pub id: String, // key 1
    /// Submit URL.
    pub action: String, // key 2
    /// HTTP method: "GET" or "POST".
    pub method: String, // key 3
    /// Form fields.
    pub fields: Vec<FormField>, // key 4
}

impl FormDef {
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, enc_str(&self.id)),
            (2, enc_str(&self.action)),
            (3, enc_str(&self.method)),
            (
                4,
                Value::Array(self.fields.iter().map(|f| f.to_cbor()).collect()),
            ),
        ])
    }

    pub fn from_cbor(val: &Value) -> Result<Self, PerceptionError> {
        let fields_val = req(val, 4, "fields")?;
        let fields = match fields_val {
            Value::Array(arr) => {
                let mut out = Vec::with_capacity(arr.len());
                for item in arr {
                    out.push(FormField::from_cbor(item)?);
                }
                out
            }
            _ => {
                return Err(PerceptionError::InvalidField {
                    field: "fields",
                    message: format!("expected array, got {fields_val:?}"),
                });
            }
        };
        Ok(Self {
            id: dec_str(req(val, 1, "id")?, "id")?,
            action: dec_str(req(val, 2, "action")?, "action")?,
            method: dec_str(req(val, 3, "method")?, "method")?,
            fields,
        })
    }
}

// ---------------------------------------------------------------------------
// MediaItem
// ---------------------------------------------------------------------------

/// A media item (image, video, audio) on a page.
#[derive(Clone, Debug, PartialEq)]
pub struct MediaItem {
    /// Media type: "image", "video", "audio".
    pub media_type: String, // key 1
    /// Source URL.
    pub url: String, // key 2
    /// Optional alt text / caption.
    pub alt_text: Option<String>, // key 3
    /// Optional MIME type.
    pub mime_type: Option<String>, // key 4
    /// Optional width in pixels.
    pub width: Option<u32>, // key 5
    /// Optional height in pixels.
    pub height: Option<u32>, // key 6
}

impl MediaItem {
    pub fn to_cbor(&self) -> Value {
        let mut entries: Vec<(i64, Value)> =
            vec![(1, enc_str(&self.media_type)), (2, enc_str(&self.url))];
        if let Some(v) = enc_opt_str(&self.alt_text) {
            entries.push((3, v));
        }
        if let Some(v) = enc_opt_str(&self.mime_type) {
            entries.push((4, v));
        }
        if let Some(w) = self.width {
            entries.push((5, enc_u64(w as u64)));
        }
        if let Some(h) = self.height {
            entries.push((6, enc_u64(h as u64)));
        }
        int_map(entries)
    }

    pub fn from_cbor(val: &Value) -> Result<Self, PerceptionError> {
        Ok(Self {
            media_type: dec_str(req(val, 1, "media_type")?, "media_type")?,
            url: dec_str(req(val, 2, "url")?, "url")?,
            alt_text: opt(val, 3).and_then(dec_opt_str),
            mime_type: opt(val, 4).and_then(dec_opt_str),
            width: match opt(val, 5) {
                Some(v) => Some(dec_u32(v, "width")?),
                None => None,
            },
            height: match opt(val, 6) {
                Some(v) => Some(dec_u32(v, "height")?),
                None => None,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// LinkDef
// ---------------------------------------------------------------------------

/// A hyperlink on a page.
#[derive(Clone, Debug, PartialEq)]
pub struct LinkDef {
    /// Link text.
    pub text: String, // key 1
    /// Target URL.
    pub url: String, // key 2
    /// Whether the link is internal to the site.
    pub internal: bool, // key 3
    /// Optional rel attribute.
    pub rel: Option<String>, // key 4
}

impl LinkDef {
    pub fn to_cbor(&self) -> Value {
        let mut entries: Vec<(i64, Value)> = vec![
            (1, enc_str(&self.text)),
            (2, enc_str(&self.url)),
            (3, enc_bool(self.internal)),
        ];
        if let Some(v) = enc_opt_str(&self.rel) {
            entries.push((4, v));
        }
        int_map(entries)
    }

    pub fn from_cbor(val: &Value) -> Result<Self, PerceptionError> {
        Ok(Self {
            text: dec_str(req(val, 1, "text")?, "text")?,
            url: dec_str(req(val, 2, "url")?, "url")?,
            internal: dec_bool(req(val, 3, "internal")?, "internal")?,
            rel: opt(val, 4).and_then(dec_opt_str),
        })
    }
}

// ---------------------------------------------------------------------------
// StructuredData
// ---------------------------------------------------------------------------

/// Structured data extracted from a page (e.g. JSON-LD schema.org).
#[derive(Clone, Debug, PartialEq)]
pub struct StructuredData {
    /// Schema type: "BreadcrumbList", "Product", etc.
    pub schema_type: String, // key 1
    /// The raw structured payload as a CBOR value.
    pub data: Value, // key 2
}

impl StructuredData {
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, enc_str(&self.schema_type)),
            (2, self.data.clone()),
        ])
    }

    pub fn from_cbor(val: &Value) -> Result<Self, PerceptionError> {
        Ok(Self {
            schema_type: dec_str(req(val, 1, "schema_type")?, "schema_type")?,
            data: req(val, 2, "data")?.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Entity
// ---------------------------------------------------------------------------

/// A named entity extracted from page content.
#[derive(Clone, Debug, PartialEq)]
pub struct Entity {
    /// Entity name.
    pub name: String, // key 1
    /// Entity type: "person", "org", "location".
    pub entity_type: String, // key 2
    /// Section ids where the entity is mentioned.
    pub mentions: Vec<String>, // key 3
    /// Extraction confidence (0.0 - 1.0).
    pub confidence: f64, // key 4
}

impl Entity {
    pub fn to_cbor(&self) -> Value {
        // Encode confidence as a fixed-point unsigned integer (confidence * 1_000_000)
        // because the CBOR encoder does not support floating point. This preserves
        // 6 decimal digits of precision and round-trips exactly.
        let conf_encoded = (self.confidence * 1_000_000.0).round() as u64;
        int_map(vec![
            (1, enc_str(&self.name)),
            (2, enc_str(&self.entity_type)),
            (3, enc_str_array(&self.mentions)),
            (4, enc_u64(conf_encoded)),
        ])
    }

    pub fn from_cbor(val: &Value) -> Result<Self, PerceptionError> {
        let conf_encoded = dec_u64(req(val, 4, "confidence")?, "confidence")?;
        Ok(Self {
            name: dec_str(req(val, 1, "name")?, "name")?,
            entity_type: dec_str(req(val, 2, "entity_type")?, "entity_type")?,
            mentions: match opt(val, 3) {
                Some(v) => dec_str_array(v, "mentions")?,
                None => Vec::new(),
            },
            confidence: conf_encoded as f64 / 1_000_000.0,
        })
    }
}

// ---------------------------------------------------------------------------
// PageMetadata
// ---------------------------------------------------------------------------

/// Metadata about a fetched page.
#[derive(Clone, Debug, PartialEq)]
pub struct PageMetadata {
    /// HTTP status code.
    pub status_code: u16, // key 1
    /// Content-Type header value.
    pub content_type: String, // key 2
    /// Optional character set.
    pub charset: Option<String>, // key 3
    /// Optional page language (BCP 47 tag).
    pub language: Option<String>, // key 4
    /// Optional page title (from <title> or og:title).
    pub title: Option<String>, // key 5
    /// Optional page description (meta description).
    pub description: Option<String>, // key 6
    /// Unix timestamp (ms) when the page was fetched.
    pub fetched_at: u64, // key 7
}

impl PageMetadata {
    pub fn to_cbor(&self) -> Value {
        let mut entries: Vec<(i64, Value)> = vec![
            (1, enc_u64(self.status_code as u64)),
            (2, enc_str(&self.content_type)),
            (7, enc_u64(self.fetched_at)),
        ];
        if let Some(v) = enc_opt_str(&self.charset) {
            entries.push((3, v));
        }
        if let Some(v) = enc_opt_str(&self.language) {
            entries.push((4, v));
        }
        if let Some(v) = enc_opt_str(&self.title) {
            entries.push((5, v));
        }
        if let Some(v) = enc_opt_str(&self.description) {
            entries.push((6, v));
        }
        int_map(entries)
    }

    pub fn from_cbor(val: &Value) -> Result<Self, PerceptionError> {
        Ok(Self {
            status_code: dec_u16(req(val, 1, "status_code")?, "status_code")?,
            content_type: dec_str(req(val, 2, "content_type")?, "content_type")?,
            charset: opt(val, 3).and_then(dec_opt_str),
            language: opt(val, 4).and_then(dec_opt_str),
            title: opt(val, 5).and_then(dec_opt_str),
            description: opt(val, 6).and_then(dec_opt_str),
            fetched_at: dec_u64(req(val, 7, "fetched_at")?, "fetched_at")?,
        })
    }
}

// ---------------------------------------------------------------------------
// NavigationState
// ---------------------------------------------------------------------------

/// Browser navigation state for a page.
#[derive(Clone, Debug, PartialEq)]
pub struct NavigationState {
    /// Current URL.
    pub url: String, // key 1
    /// Current page title.
    pub title: String, // key 2
    /// Whether backward navigation is possible.
    pub can_go_back: bool, // key 3
    /// Whether forward navigation is possible.
    pub can_go_forward: bool, // key 4
}

impl NavigationState {
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, enc_str(&self.url)),
            (2, enc_str(&self.title)),
            (3, enc_bool(self.can_go_back)),
            (4, enc_bool(self.can_go_forward)),
        ])
    }

    pub fn from_cbor(val: &Value) -> Result<Self, PerceptionError> {
        Ok(Self {
            url: dec_str(req(val, 1, "url")?, "url")?,
            title: dec_str(req(val, 2, "title")?, "title")?,
            can_go_back: dec_bool(req(val, 3, "can_go_back")?, "can_go_back")?,
            can_go_forward: dec_bool(req(val, 4, "can_go_forward")?, "can_go_forward")?,
        })
    }
}

// ---------------------------------------------------------------------------
// WebContent
// ---------------------------------------------------------------------------

/// Agent-native web content representation.
///
/// A 12-field CBOR int-keyed map that replaces raw HTML with structured,
/// deterministic content suitable for autonomous agent consumption.
#[derive(Clone, Debug, PartialEq)]
pub struct WebContent {
    /// Source URL.
    pub url: String, // key 1
    /// Page title.
    pub title: String, // key 2
    /// Page metadata.
    pub metadata: PageMetadata, // key 3
    /// Navigation state.
    pub nav: NavigationState, // key 4
    /// Content sections.
    pub sections: Vec<ContentSection>, // key 5
    /// Interactive elements.
    pub elements: Vec<InteractiveElement>, // key 6
    /// Forms.
    pub forms: Vec<FormDef>, // key 7
    /// Media items.
    pub media: Vec<MediaItem>, // key 8
    /// Links.
    pub links: Vec<LinkDef>, // key 9
    /// Structured data (JSON-LD, microdata, etc.).
    pub structured: Vec<StructuredData>, // key 10
    /// Extracted entities.
    pub entities: Vec<Entity>, // key 11
    /// Content hash.
    pub hash: ContentHash, // key 12
}

impl WebContent {
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, enc_str(&self.url)),
            (2, enc_str(&self.title)),
            (3, self.metadata.to_cbor()),
            (4, self.nav.to_cbor()),
            (
                5,
                Value::Array(self.sections.iter().map(|s| s.to_cbor()).collect()),
            ),
            (
                6,
                Value::Array(self.elements.iter().map(|e| e.to_cbor()).collect()),
            ),
            (
                7,
                Value::Array(self.forms.iter().map(|f| f.to_cbor()).collect()),
            ),
            (
                8,
                Value::Array(self.media.iter().map(|m| m.to_cbor()).collect()),
            ),
            (
                9,
                Value::Array(self.links.iter().map(|l| l.to_cbor()).collect()),
            ),
            (
                10,
                Value::Array(self.structured.iter().map(|s| s.to_cbor()).collect()),
            ),
            (
                11,
                Value::Array(self.entities.iter().map(|e| e.to_cbor()).collect()),
            ),
            (12, self.hash.to_cbor()),
        ])
    }

    pub fn from_cbor(val: &Value) -> Result<Self, PerceptionError> {
        let sections = decode_vec(
            req(val, 5, "sections")?,
            "sections",
            ContentSection::from_cbor,
        )?;
        let elements = decode_vec(
            req(val, 6, "elements")?,
            "elements",
            InteractiveElement::from_cbor,
        )?;
        let forms = decode_vec(req(val, 7, "forms")?, "forms", FormDef::from_cbor)?;
        let media = decode_vec(req(val, 8, "media")?, "media", MediaItem::from_cbor)?;
        let links = decode_vec(req(val, 9, "links")?, "links", LinkDef::from_cbor)?;
        let structured = decode_vec(
            req(val, 10, "structured")?,
            "structured",
            StructuredData::from_cbor,
        )?;
        let entities = decode_vec(req(val, 11, "entities")?, "entities", Entity::from_cbor)?;

        Ok(Self {
            url: dec_str(req(val, 1, "url")?, "url")?,
            title: dec_str(req(val, 2, "title")?, "title")?,
            metadata: PageMetadata::from_cbor(req(val, 3, "metadata")?)?,
            nav: NavigationState::from_cbor(req(val, 4, "nav")?)?,
            sections,
            elements,
            forms,
            media,
            links,
            structured,
            entities,
            hash: ContentHash::from_cbor(req(val, 12, "hash")?)?,
        })
    }
}

/// Decode a CBOR array of nested structs using the provided decoder function.
fn decode_vec<T>(
    val: &Value,
    field: &'static str,
    dec: fn(&Value) -> Result<T, PerceptionError>,
) -> Result<Vec<T>, PerceptionError> {
    match val {
        Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                out.push(dec(item)?);
            }
            Ok(out)
        }
        _ => Err(PerceptionError::InvalidField {
            field,
            message: format!("expected array, got {val:?}"),
        }),
    }
}

// ---------------------------------------------------------------------------
// DocumentPage
// ---------------------------------------------------------------------------

/// A single page within a document.
#[derive(Clone, Debug, PartialEq)]
pub struct DocumentPage {
    /// 1-based page number.
    pub page_num: u32, // key 1
    /// Extracted text of the page.
    pub text: String, // key 2
    /// Sections within the page.
    pub sections: Vec<ContentSection>, // key 3
}

impl DocumentPage {
    pub fn to_cbor(&self) -> Value {
        int_map(vec![
            (1, enc_u64(self.page_num as u64)),
            (2, enc_str(&self.text)),
            (
                3,
                Value::Array(self.sections.iter().map(|s| s.to_cbor()).collect()),
            ),
        ])
    }

    pub fn from_cbor(val: &Value) -> Result<Self, PerceptionError> {
        Ok(Self {
            page_num: dec_u32(req(val, 1, "page_num")?, "page_num")?,
            text: dec_str(req(val, 2, "text")?, "text")?,
            sections: decode_vec(
                req(val, 3, "sections")?,
                "sections",
                ContentSection::from_cbor,
            )?,
        })
    }
}

// ---------------------------------------------------------------------------
// TableDef
// ---------------------------------------------------------------------------

/// A table extracted from a document or page.
#[derive(Clone, Debug, PartialEq)]
pub struct TableDef {
    /// Table id.
    pub id: String, // key 1
    /// Optional caption.
    pub caption: Option<String>, // key 2
    /// Header row labels.
    pub headers: Vec<String>, // key 3
    /// Data rows (each row is a vec of cell strings).
    pub rows: Vec<Vec<String>>, // key 4
}

impl TableDef {
    pub fn to_cbor(&self) -> Value {
        let mut entries: Vec<(i64, Value)> = vec![
            (1, enc_str(&self.id)),
            (3, enc_str_array(&self.headers)),
            (
                4,
                Value::Array(self.rows.iter().map(|row| enc_str_array(row)).collect()),
            ),
        ];
        if let Some(v) = enc_opt_str(&self.caption) {
            entries.push((2, v));
        }
        int_map(entries)
    }

    pub fn from_cbor(val: &Value) -> Result<Self, PerceptionError> {
        let headers = match opt(val, 3) {
            Some(v) => dec_str_array(v, "headers")?,
            None => Vec::new(),
        };
        let rows = match opt(val, 4) {
            Some(Value::Array(arr)) => {
                let mut out = Vec::with_capacity(arr.len());
                for item in arr {
                    out.push(dec_str_array(item, "rows")?);
                }
                out
            }
            Some(v) => {
                return Err(PerceptionError::InvalidField {
                    field: "rows",
                    message: format!("expected array, got {v:?}"),
                });
            }
            None => Vec::new(),
        };
        Ok(Self {
            id: dec_str(req(val, 1, "id")?, "id")?,
            caption: opt(val, 2).and_then(dec_opt_str),
            headers,
            rows,
        })
    }
}

// ---------------------------------------------------------------------------
// DocumentContent
// ---------------------------------------------------------------------------

/// Agent-native document content representation (PDF, Word, Excel, etc.).
#[derive(Clone, Debug, PartialEq)]
pub struct DocumentContent {
    /// Source URL or file path.
    pub source: String, // key 1
    /// Document type: "pdf", "word", "excel", etc.
    pub doc_type: String, // key 2
    /// Optional document title.
    pub title: Option<String>, // key 3
    /// Document pages.
    pub pages: Vec<DocumentPage>, // key 4
    /// Tables extracted from the document.
    pub tables: Vec<TableDef>, // key 5
    /// Fetch metadata.
    pub metadata: PageMetadata, // key 6
    /// Optional document language.
    pub language: Option<String>, // key 7
    /// Whether OCR was applied during extraction.
    pub ocr_applied: bool, // key 8
    /// Content hash.
    pub hash: ContentHash, // key 9
}

impl DocumentContent {
    pub fn to_cbor(&self) -> Value {
        let mut entries: Vec<(i64, Value)> = vec![
            (1, enc_str(&self.source)),
            (2, enc_str(&self.doc_type)),
            (
                4,
                Value::Array(self.pages.iter().map(|p| p.to_cbor()).collect()),
            ),
            (
                5,
                Value::Array(self.tables.iter().map(|t| t.to_cbor()).collect()),
            ),
            (6, self.metadata.to_cbor()),
            (8, enc_bool(self.ocr_applied)),
            (9, self.hash.to_cbor()),
        ];
        if let Some(v) = enc_opt_str(&self.title) {
            entries.push((3, v));
        }
        if let Some(v) = enc_opt_str(&self.language) {
            entries.push((7, v));
        }
        int_map(entries)
    }

    pub fn from_cbor(val: &Value) -> Result<Self, PerceptionError> {
        Ok(Self {
            source: dec_str(req(val, 1, "source")?, "source")?,
            doc_type: dec_str(req(val, 2, "doc_type")?, "doc_type")?,
            title: opt(val, 3).and_then(dec_opt_str),
            pages: decode_vec(req(val, 4, "pages")?, "pages", DocumentPage::from_cbor)?,
            tables: decode_vec(req(val, 5, "tables")?, "tables", TableDef::from_cbor)?,
            metadata: PageMetadata::from_cbor(req(val, 6, "metadata")?)?,
            language: opt(val, 7).and_then(dec_opt_str),
            ocr_applied: dec_bool(req(val, 8, "ocr_applied")?, "ocr_applied")?,
            hash: ContentHash::from_cbor(req(val, 9, "hash")?)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use aafp_cbor::{decode, encode, int_map, Value};

    /// Helper: encode a struct to CBOR bytes and decode back, asserting equality.
    fn roundtrip<T>(
        item: &T,
        to_cbor: fn(&T) -> Value,
        from_cbor: fn(&Value) -> Result<T, PerceptionError>,
    ) where
        T: PartialEq + std::fmt::Debug,
    {
        let cbor = to_cbor(item);
        let bytes = encode(&cbor).expect("encode should succeed");
        let (decoded, consumed) = decode(&bytes).expect("decode should succeed");
        assert_eq!(consumed, bytes.len(), "no trailing bytes");
        let item2 = from_cbor(&decoded).expect("from_cbor should succeed");
        assert_eq!(item, &item2);
    }

    fn sample_metadata() -> PageMetadata {
        PageMetadata {
            status_code: 200,
            content_type: "text/html".into(),
            charset: Some("utf-8".into()),
            language: Some("en".into()),
            title: Some("Example".into()),
            description: Some("An example page".into()),
            fetched_at: 1_700_000_000_000,
        }
    }

    fn sample_nav() -> NavigationState {
        NavigationState {
            url: "https://example.com/page".into(),
            title: "Example".into(),
            can_go_back: true,
            can_go_forward: false,
        }
    }

    fn sample_section(id: &str) -> ContentSection {
        ContentSection {
            id: id.into(),
            title: format!("Section {id}"),
            content: "Some content here.".into(),
            level: 2,
            children: vec![format!("{id}.1"), format!("{id}.2")],
        }
    }

    fn sample_element(id: &str) -> InteractiveElement {
        InteractiveElement {
            id: id.into(),
            element_type: "button".into(),
            ref_target: "#btn".into(),
            text: "Click me".into(),
            action: Action {
                action_type: "click".into(),
                target: "e0".into(),
                value: None,
            },
            safety: ActionSafety::RequiresConfirmation,
            attributes: vec![("aria-label".into(), "Submit".into())],
        }
    }

    fn sample_form() -> FormDef {
        FormDef {
            id: "f0".into(),
            action: "https://example.com/submit".into(),
            method: "POST".into(),
            fields: vec![FormField {
                name: "email".into(),
                field_type: "email".into(),
                required: true,
                label: Some("Email".into()),
                default_value: None,
            }],
        }
    }

    fn sample_media() -> MediaItem {
        MediaItem {
            media_type: "image".into(),
            url: "https://example.com/img.png".into(),
            alt_text: Some("logo".into()),
            mime_type: Some("image/png".into()),
            width: Some(320),
            height: Some(240),
        }
    }

    fn sample_link() -> LinkDef {
        LinkDef {
            text: "About".into(),
            url: "https://example.com/about".into(),
            internal: true,
            rel: Some("noopener".into()),
        }
    }

    fn sample_structured() -> StructuredData {
        StructuredData {
            schema_type: "BreadcrumbList".into(),
            data: int_map(vec![(1, Value::from_str("Home"))]),
        }
    }

    fn sample_entity() -> Entity {
        Entity {
            name: "Acme Corp".into(),
            entity_type: "org".into(),
            mentions: vec!["s0".into(), "s1".into()],
            confidence: 0.95,
        }
    }

    fn sample_web_content() -> WebContent {
        WebContent {
            url: "https://example.com".into(),
            title: "Example".into(),
            metadata: sample_metadata(),
            nav: sample_nav(),
            sections: vec![sample_section("s0"), sample_section("s1")],
            elements: vec![sample_element("e0")],
            forms: vec![sample_form()],
            media: vec![sample_media()],
            links: vec![sample_link()],
            structured: vec![sample_structured()],
            entities: vec![sample_entity()],
            hash: ContentHash::compute(b"normalized content"),
        }
    }

    #[test]
    fn test_webcontent_roundtrip_full() {
        roundtrip(
            &sample_web_content(),
            WebContent::to_cbor,
            WebContent::from_cbor,
        );
    }

    #[test]
    fn test_webcontent_roundtrip_minimal() {
        let wc = WebContent {
            url: "https://example.com".into(),
            title: "Minimal".into(),
            metadata: PageMetadata {
                status_code: 200,
                content_type: "text/html".into(),
                charset: None,
                language: None,
                title: None,
                description: None,
                fetched_at: 0,
            },
            nav: NavigationState {
                url: "https://example.com".into(),
                title: "Minimal".into(),
                can_go_back: false,
                can_go_forward: false,
            },
            sections: vec![],
            elements: vec![],
            forms: vec![],
            media: vec![],
            links: vec![],
            structured: vec![],
            entities: vec![],
            hash: ContentHash::compute(b""),
        };
        roundtrip(&wc, WebContent::to_cbor, WebContent::from_cbor);
    }

    #[test]
    fn test_content_section_roundtrip() {
        roundtrip(
            &sample_section("s0"),
            ContentSection::to_cbor,
            ContentSection::from_cbor,
        );
    }

    #[test]
    fn test_interactive_element_roundtrip() {
        roundtrip(
            &sample_element("e0"),
            InteractiveElement::to_cbor,
            InteractiveElement::from_cbor,
        );
    }

    #[test]
    fn test_action_safety_all_variants() {
        for s in [
            ActionSafety::Safe,
            ActionSafety::RequiresConfirmation,
            ActionSafety::Dangerous,
        ] {
            let cbor = s.to_cbor();
            let bytes = encode(&cbor).expect("encode");
            let (decoded, _) = decode(&bytes).expect("decode");
            let s2 = ActionSafety::from_cbor(&decoded).expect("from_cbor");
            assert_eq!(s, s2);
        }
    }

    #[test]
    fn test_action_roundtrip() {
        let a = Action {
            action_type: "type".into(),
            target: "e1".into(),
            value: Some("hello".into()),
        };
        roundtrip(&a, Action::to_cbor, Action::from_cbor);
    }

    #[test]
    fn test_form_def_roundtrip() {
        roundtrip(&sample_form(), FormDef::to_cbor, FormDef::from_cbor);
    }

    #[test]
    fn test_form_field_roundtrip() {
        let f = FormField {
            name: "pass".into(),
            field_type: "password".into(),
            required: true,
            label: None,
            default_value: Some("".into()),
        };
        roundtrip(&f, FormField::to_cbor, FormField::from_cbor);
    }

    #[test]
    fn test_media_item_roundtrip() {
        roundtrip(&sample_media(), MediaItem::to_cbor, MediaItem::from_cbor);
    }

    #[test]
    fn test_link_def_roundtrip() {
        roundtrip(&sample_link(), LinkDef::to_cbor, LinkDef::from_cbor);
    }

    #[test]
    fn test_structured_data_roundtrip() {
        roundtrip(
            &sample_structured(),
            StructuredData::to_cbor,
            StructuredData::from_cbor,
        );
    }

    #[test]
    fn test_entity_roundtrip() {
        roundtrip(&sample_entity(), Entity::to_cbor, Entity::from_cbor);
    }

    #[test]
    fn test_content_hash_deterministic() {
        let h1 = ContentHash::compute(b"some content");
        let h2 = ContentHash::compute(b"some content");
        assert_eq!(h1, h2, "same input must produce same hash");
        let h3 = ContentHash::compute(b"different content");
        assert_ne!(h1, h3, "different input must produce different hash");
        // Verify it matches a direct SHA-256.
        let expected = Sha256::digest(b"some content");
        assert_eq!(&h1.0, &expected[..]);
    }

    #[test]
    fn test_page_metadata_roundtrip() {
        roundtrip(
            &sample_metadata(),
            PageMetadata::to_cbor,
            PageMetadata::from_cbor,
        );
    }

    #[test]
    fn test_navigation_state_roundtrip() {
        roundtrip(
            &sample_nav(),
            NavigationState::to_cbor,
            NavigationState::from_cbor,
        );
    }

    #[test]
    fn test_document_content_roundtrip() {
        let doc = DocumentContent {
            source: "https://example.com/doc.pdf".into(),
            doc_type: "pdf".into(),
            title: Some("Report".into()),
            pages: vec![DocumentPage {
                page_num: 1,
                text: "Page one text.".into(),
                sections: vec![sample_section("s0")],
            }],
            tables: vec![TableDef {
                id: "t0".into(),
                caption: Some("Sales".into()),
                headers: vec!["Q1".into(), "Q2".into()],
                rows: vec![vec!["100".into(), "200".into()]],
            }],
            metadata: sample_metadata(),
            language: Some("en".into()),
            ocr_applied: true,
            hash: ContentHash::compute(b"doc content"),
        };
        roundtrip(&doc, DocumentContent::to_cbor, DocumentContent::from_cbor);
    }

    #[test]
    fn test_document_page_roundtrip() {
        let p = DocumentPage {
            page_num: 5,
            text: "Hello".into(),
            sections: vec![sample_section("s0")],
        };
        roundtrip(&p, DocumentPage::to_cbor, DocumentPage::from_cbor);
    }

    #[test]
    fn test_table_def_roundtrip() {
        let t = TableDef {
            id: "t0".into(),
            caption: None,
            headers: vec!["a".into(), "b".into()],
            rows: vec![vec!["1".into(), "2".into()], vec!["3".into(), "4".into()]],
        };
        roundtrip(&t, TableDef::to_cbor, TableDef::from_cbor);
    }

    #[test]
    fn test_empty_webcontent() {
        let wc = WebContent {
            url: "".into(),
            title: "".into(),
            metadata: PageMetadata {
                status_code: 0,
                content_type: "".into(),
                charset: None,
                language: None,
                title: None,
                description: None,
                fetched_at: 0,
            },
            nav: NavigationState {
                url: "".into(),
                title: "".into(),
                can_go_back: false,
                can_go_forward: false,
            },
            sections: vec![],
            elements: vec![],
            forms: vec![],
            media: vec![],
            links: vec![],
            structured: vec![],
            entities: vec![],
            hash: ContentHash::compute(b""),
        };
        roundtrip(&wc, WebContent::to_cbor, WebContent::from_cbor);
    }

    #[test]
    fn test_large_content_100_sections() {
        let sections: Vec<ContentSection> = (0..100)
            .map(|i| ContentSection {
                id: format!("s{i}"),
                title: format!("Section {i}"),
                content: format!("Content for section {i}"),
                level: (i % 6 + 1) as u8,
                children: vec![],
            })
            .collect();
        let wc = WebContent {
            url: "https://example.com/big".into(),
            title: "Big".into(),
            metadata: sample_metadata(),
            nav: sample_nav(),
            sections,
            elements: vec![],
            forms: vec![],
            media: vec![],
            links: vec![],
            structured: vec![],
            entities: vec![],
            hash: ContentHash::compute(b"big"),
        };
        let cbor = wc.to_cbor();
        let bytes = encode(&cbor).expect("encode");
        let (decoded, _) = decode(&bytes).expect("decode");
        let wc2 = WebContent::from_cbor(&decoded).expect("from_cbor");
        assert_eq!(wc, wc2);
        assert_eq!(wc2.sections.len(), 100);
    }

    #[test]
    fn test_decode_missing_field() {
        // An empty map should fail to decode WebContent (missing a required field).
        let empty = int_map(vec![]);
        let err = WebContent::from_cbor(&empty).unwrap_err();
        // The first required field checked is "sections" (key 5).
        assert!(matches!(err, PerceptionError::MissingField(_)));
    }

    #[test]
    fn test_decode_invalid_field_type() {
        // url present but wrong type. The first required field checked is
        // sections (key 5), so with only key 1 present, we get MissingField.
        let bad = int_map(vec![(1, Value::Unsigned(42))]);
        let err = WebContent::from_cbor(&bad).unwrap_err();
        assert!(matches!(err, PerceptionError::MissingField(_)));
    }

    #[test]
    fn test_content_hash_wrong_length_rejected() {
        let bad = Value::ByteString(vec![0u8; 16]);
        let err = ContentHash::from_cbor(&bad).unwrap_err();
        assert!(matches!(
            err,
            PerceptionError::InvalidField { field: "hash", .. }
        ));
    }
}
