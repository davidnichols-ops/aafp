//! Internet bridge capability descriptors (SCG §11 / D6).
//!
//! Canonical [`SemanticCapability`] descriptors for the 11 well-known internet
//! bridge capabilities. Bridge agents advertise these (or specializations of
//! them) so that any AAFP agent can discover and plan against the World
//! Perception Layer.
//!
//! The 11 capabilities are:
//! `search`, `web-browse`, `document-read`, `api-call`, `api-discover`,
//! `code-execute`, `image-ocr`, `audio-transcribe`, `crawl`,
//! `real-time-subscribe`, `stealth-browse`.
//!
//! > **Status:** Pre-build scaffolding (D6). Function signatures and struct
//! > shapes are final; field values are `todo!()` pending the build phase.
//! > Note: the D5-D6 build phase will extend `SemanticCapability` with
//! > `requirements` and `provides` fields (see `SCG_D5_D6_PLAN_BRIDGE.md`
//! > Part 4). The struct literals below reflect the current D1 shape; the
//! > build phase will add the new fields.

use super::capability::MetadataValue;
use super::{
    CapabilityAttributes, CapabilityCategory, CapabilityEdge, CostModel, EdgeType, GeoConstraint,
    HardwareSpec, Modality, PerformanceProfile, QualityMetrics, SemanticCapability,
    SemanticVersion,
};

/// Returns the 11 canonical internet bridge capability descriptors.
///
/// Bridge agents advertise these (or specializations of them) so that any
/// AAFP agent can discover and plan against the World Perception Layer.
pub fn internet_bridge_capabilities() -> Vec<SemanticCapability> {
    todo!("D6: assemble all 11 canonical bridge capability descriptors")
}

/// `search` — web search (Brave / SerpAPI / SearXNG).
fn search_capability() -> SemanticCapability {
    SemanticCapability {
        name: todo!("\"search\""),
        category: todo!(CapabilityCategory::InformationRetrieval),
        attributes: todo!(CapabilityAttributes {
            languages: todo!(),
            modalities: todo!(),
            hardware: todo!(),
            frameworks: todo!(),
            precision: todo!(),
            custom: todo!(),
        }),
        performance: todo!(PerformanceProfile {
            avg_latency_ms: todo!(),
            p99_latency_ms: todo!(),
            throughput_rps: todo!(),
            max_batch_size: todo!(),
        }),
        quality: todo!(QualityMetrics {
            trust_score: todo!(),
            accuracy: todo!(),
            uptime_pct: todo!(),
            success_count: todo!(),
        }),
        cost: todo!(CostModel {
            per_invocation_micro_usd: todo!(),
            per_token_micro_usd: todo!(),
            has_free_tier: todo!(),
        }),
        dependencies: todo!(),
        version: todo!(SemanticVersion {
            major: todo!(),
            minor: todo!(),
            patch: todo!(),
        }),
        geo: todo!(),
    }
}

/// `web-browse` — fetch and render a single URL (Firecrawl / Playwright).
fn web_browse_capability() -> SemanticCapability {
    SemanticCapability {
        name: todo!("\"web-browse\""),
        category: todo!(CapabilityCategory::Navigation),
        attributes: todo!(CapabilityAttributes {
            languages: todo!(),
            modalities: todo!(),
            hardware: todo!(),
            frameworks: todo!(),
            precision: todo!(),
            custom: todo!(),
        }),
        performance: todo!(PerformanceProfile {
            avg_latency_ms: todo!(),
            p99_latency_ms: todo!(),
            throughput_rps: todo!(),
            max_batch_size: todo!(),
        }),
        quality: todo!(QualityMetrics {
            trust_score: todo!(),
            accuracy: todo!(),
            uptime_pct: todo!(),
            success_count: todo!(),
        }),
        cost: todo!(CostModel {
            per_invocation_micro_usd: todo!(),
            per_token_micro_usd: todo!(),
            has_free_tier: todo!(),
        }),
        dependencies: todo!(),
        version: todo!(SemanticVersion {
            major: todo!(),
            minor: todo!(),
            patch: todo!(),
        }),
        geo: todo!(),
    }
}

/// `document-read` — parse PDF/Word/Excel/PowerPoint into text (PyMuPDF / Tika).
fn document_read_capability() -> SemanticCapability {
    SemanticCapability {
        name: todo!("\"document-read\""),
        category: todo!(CapabilityCategory::Parsing),
        attributes: todo!(CapabilityAttributes {
            languages: todo!(),
            modalities: todo!(),
            hardware: todo!(),
            frameworks: todo!(),
            precision: todo!(),
            custom: todo!(),
        }),
        performance: todo!(PerformanceProfile {
            avg_latency_ms: todo!(),
            p99_latency_ms: todo!(),
            throughput_rps: todo!(),
            max_batch_size: todo!(),
        }),
        quality: todo!(QualityMetrics {
            trust_score: todo!(),
            accuracy: todo!(),
            uptime_pct: todo!(),
            success_count: todo!(),
        }),
        cost: todo!(CostModel {
            per_invocation_micro_usd: todo!(),
            per_token_micro_usd: todo!(),
            has_free_tier: todo!(),
        }),
        dependencies: todo!(),
        version: todo!(SemanticVersion {
            major: todo!(),
            minor: todo!(),
            patch: todo!(),
        }),
        geo: todo!(),
    }
}

/// `api-call` — invoke a REST/GraphQL/gRPC endpoint.
fn api_call_capability() -> SemanticCapability {
    SemanticCapability {
        name: todo!("\"api-call\""),
        category: todo!(CapabilityCategory::Integration),
        attributes: todo!(CapabilityAttributes {
            languages: todo!(),
            modalities: todo!(),
            hardware: todo!(),
            frameworks: todo!(),
            precision: todo!(),
            custom: todo!(),
        }),
        performance: todo!(PerformanceProfile {
            avg_latency_ms: todo!(),
            p99_latency_ms: todo!(),
            throughput_rps: todo!(),
            max_batch_size: todo!(),
        }),
        quality: todo!(QualityMetrics {
            trust_score: todo!(),
            accuracy: todo!(),
            uptime_pct: todo!(),
            success_count: todo!(),
        }),
        cost: todo!(CostModel {
            per_invocation_micro_usd: todo!(),
            per_token_micro_usd: todo!(),
            has_free_tier: todo!(),
        }),
        dependencies: todo!(),
        version: todo!(SemanticVersion {
            major: todo!(),
            minor: todo!(),
            patch: todo!(),
        }),
        geo: todo!(),
    }
}

/// `api-discover` — discover an API schema (OpenAPI / GraphQL schema).
fn api_discover_capability() -> SemanticCapability {
    SemanticCapability {
        name: todo!("\"api-discover\""),
        category: todo!(CapabilityCategory::Integration),
        attributes: todo!(CapabilityAttributes {
            languages: todo!(),
            modalities: todo!(),
            hardware: todo!(),
            frameworks: todo!(),
            precision: todo!(),
            custom: todo!(),
        }),
        performance: todo!(PerformanceProfile {
            avg_latency_ms: todo!(),
            p99_latency_ms: todo!(),
            throughput_rps: todo!(),
            max_batch_size: todo!(),
        }),
        quality: todo!(QualityMetrics {
            trust_score: todo!(),
            accuracy: todo!(),
            uptime_pct: todo!(),
            success_count: todo!(),
        }),
        cost: todo!(CostModel {
            per_invocation_micro_usd: todo!(),
            per_token_micro_usd: todo!(),
            has_free_tier: todo!(),
        }),
        dependencies: todo!(),
        version: todo!(SemanticVersion {
            major: todo!(),
            minor: todo!(),
            patch: todo!(),
        }),
        geo: todo!(),
    }
}

/// `code-execute` — run code in a sandbox (Firecracker / WASM).
fn code_execute_capability() -> SemanticCapability {
    SemanticCapability {
        name: todo!("\"code-execute\""),
        category: todo!(CapabilityCategory::Computation),
        attributes: todo!(CapabilityAttributes {
            languages: todo!(),
            modalities: todo!(),
            hardware: todo!(),
            frameworks: todo!(),
            precision: todo!(),
            custom: todo!(),
        }),
        performance: todo!(PerformanceProfile {
            avg_latency_ms: todo!(),
            p99_latency_ms: todo!(),
            throughput_rps: todo!(),
            max_batch_size: todo!(),
        }),
        quality: todo!(QualityMetrics {
            trust_score: todo!(),
            accuracy: todo!(),
            uptime_pct: todo!(),
            success_count: todo!(),
        }),
        cost: todo!(CostModel {
            per_invocation_micro_usd: todo!(),
            per_token_micro_usd: todo!(),
            has_free_tier: todo!(),
        }),
        dependencies: todo!(),
        version: todo!(SemanticVersion {
            major: todo!(),
            minor: todo!(),
            patch: todo!(),
        }),
        geo: todo!(),
    }
}

/// `image-ocr` — extract text from images (Tesseract / Google Vision).
fn image_ocr_capability() -> SemanticCapability {
    SemanticCapability {
        name: todo!("\"image-ocr\""),
        category: todo!(CapabilityCategory::Perception),
        attributes: todo!(CapabilityAttributes {
            languages: todo!(),
            modalities: todo!(),
            hardware: todo!(),
            frameworks: todo!(),
            precision: todo!(),
            custom: todo!(),
        }),
        performance: todo!(PerformanceProfile {
            avg_latency_ms: todo!(),
            p99_latency_ms: todo!(),
            throughput_rps: todo!(),
            max_batch_size: todo!(),
        }),
        quality: todo!(QualityMetrics {
            trust_score: todo!(),
            accuracy: todo!(),
            uptime_pct: todo!(),
            success_count: todo!(),
        }),
        cost: todo!(CostModel {
            per_invocation_micro_usd: todo!(),
            per_token_micro_usd: todo!(),
            has_free_tier: todo!(),
        }),
        dependencies: todo!(),
        version: todo!(SemanticVersion {
            major: todo!(),
            minor: todo!(),
            patch: todo!(),
        }),
        geo: todo!(),
    }
}

/// `audio-transcribe` — speech-to-text (Whisper / Deepgram).
fn audio_transcribe_capability() -> SemanticCapability {
    SemanticCapability {
        name: todo!("\"audio-transcribe\""),
        category: todo!(CapabilityCategory::Perception),
        attributes: todo!(CapabilityAttributes {
            languages: todo!(),
            modalities: todo!(),
            hardware: todo!(),
            frameworks: todo!(),
            precision: todo!(),
            custom: todo!(),
        }),
        performance: todo!(PerformanceProfile {
            avg_latency_ms: todo!(),
            p99_latency_ms: todo!(),
            throughput_rps: todo!(),
            max_batch_size: todo!(),
        }),
        quality: todo!(QualityMetrics {
            trust_score: todo!(),
            accuracy: todo!(),
            uptime_pct: todo!(),
            success_count: todo!(),
        }),
        cost: todo!(CostModel {
            per_invocation_micro_usd: todo!(),
            per_token_micro_usd: todo!(),
            has_free_tier: todo!(),
        }),
        dependencies: todo!(),
        version: todo!(SemanticVersion {
            major: todo!(),
            minor: todo!(),
            patch: todo!(),
        }),
        geo: todo!(),
    }
}

/// `crawl` — multi-page crawl with frontier scheduling (DHT-frontier).
fn crawl_capability() -> SemanticCapability {
    SemanticCapability {
        name: todo!("\"crawl\""),
        category: todo!(CapabilityCategory::InformationRetrieval),
        attributes: todo!(CapabilityAttributes {
            languages: todo!(),
            modalities: todo!(),
            hardware: todo!(),
            frameworks: todo!(),
            precision: todo!(),
            custom: todo!(),
        }),
        performance: todo!(PerformanceProfile {
            avg_latency_ms: todo!(),
            p99_latency_ms: todo!(),
            throughput_rps: todo!(),
            max_batch_size: todo!(),
        }),
        quality: todo!(QualityMetrics {
            trust_score: todo!(),
            accuracy: todo!(),
            uptime_pct: todo!(),
            success_count: todo!(),
        }),
        cost: todo!(CostModel {
            per_invocation_micro_usd: todo!(),
            per_token_micro_usd: todo!(),
            has_free_tier: todo!(),
        }),
        dependencies: todo!(),
        version: todo!(SemanticVersion {
            major: todo!(),
            minor: todo!(),
            patch: todo!(),
        }),
        geo: todo!(),
    }
}

/// `real-time-subscribe` — subscribe to a streaming event source
/// (WebSocket / SSE / gRPC stream).
fn real_time_subscribe_capability() -> SemanticCapability {
    SemanticCapability {
        name: todo!("\"real-time-subscribe\""),
        category: todo!(CapabilityCategory::Streaming),
        attributes: todo!(CapabilityAttributes {
            languages: todo!(),
            modalities: todo!(),
            hardware: todo!(),
            frameworks: todo!(),
            precision: todo!(),
            custom: todo!(),
        }),
        performance: todo!(PerformanceProfile {
            avg_latency_ms: todo!(),
            p99_latency_ms: todo!(),
            throughput_rps: todo!(),
            max_batch_size: todo!(),
        }),
        quality: todo!(QualityMetrics {
            trust_score: todo!(),
            accuracy: todo!(),
            uptime_pct: todo!(),
            success_count: todo!(),
        }),
        cost: todo!(CostModel {
            per_invocation_micro_usd: todo!(),
            per_token_micro_usd: todo!(),
            has_free_tier: todo!(),
        }),
        dependencies: todo!(),
        version: todo!(SemanticVersion {
            major: todo!(),
            minor: todo!(),
            patch: todo!(),
        }),
        geo: todo!(),
    }
}

/// `stealth-browse` — anti-bot-resistant browsing (Browserless / Bright Data).
fn stealth_browse_capability() -> SemanticCapability {
    SemanticCapability {
        name: todo!("\"stealth-browse\""),
        category: todo!(CapabilityCategory::Navigation),
        attributes: todo!(CapabilityAttributes {
            languages: todo!(),
            modalities: todo!(),
            hardware: todo!(),
            frameworks: todo!(),
            precision: todo!(),
            custom: todo!(),
        }),
        performance: todo!(PerformanceProfile {
            avg_latency_ms: todo!(),
            p99_latency_ms: todo!(),
            throughput_rps: todo!(),
            max_batch_size: todo!(),
        }),
        quality: todo!(QualityMetrics {
            trust_score: todo!(),
            accuracy: todo!(),
            uptime_pct: todo!(),
            success_count: todo!(),
        }),
        cost: todo!(CostModel {
            per_invocation_micro_usd: todo!(),
            per_token_micro_usd: todo!(),
            has_free_tier: todo!(),
        }),
        dependencies: todo!(),
        version: todo!(SemanticVersion {
            major: todo!(),
            minor: todo!(),
            patch: todo!(),
        }),
        geo: todo!(),
    }
}
