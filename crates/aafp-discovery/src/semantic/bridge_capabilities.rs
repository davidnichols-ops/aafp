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

use super::capability::{MetadataValue, OutputSpec, Requirement};
use super::{
    CapabilityAttributes, CapabilityCategory, CapabilityEdge, CostModel, EdgeType, HardwareSpec,
    Modality, PerformanceProfile, QualityMetrics, SemanticCapability, SemanticVersion,
};
use std::collections::HashMap;

/// Returns the 11 canonical internet bridge capability descriptors.
///
/// Bridge agents advertise these (or specializations of them) so that any
/// AAFP agent can discover and plan against the World Perception Layer.
pub fn internet_bridge_capabilities() -> Vec<SemanticCapability> {
    vec![
        search_capability(),
        web_browse_capability(),
        document_read_capability(),
        api_call_capability(),
        api_discover_capability(),
        code_execute_capability(),
        image_ocr_capability(),
        audio_transcribe_capability(),
        crawl_capability(),
        real_time_subscribe_capability(),
        stealth_browse_capability(),
    ]
}

fn search_capability() -> SemanticCapability {
    SemanticCapability {
        name: "search".into(),
        category: CapabilityCategory::InformationRetrieval,
        attributes: CapabilityAttributes {
            languages: vec!["en".into(), "fr".into(), "de".into(), "ja".into()],
            modalities: vec![Modality::Text],
            hardware: vec![],
            frameworks: vec!["brave".into(), "serpapi".into(), "searxng".into()],
            precision: vec![],
            custom: HashMap::from([
                ("query_type".into(), MetadataValue::Text("web".into())),
                ("max_results".into(), MetadataValue::Int(50)),
                (
                    "freshness".into(),
                    MetadataValue::Text("any|day|week|month|year".into()),
                ),
            ]),
        },
        performance: PerformanceProfile {
            avg_latency_ms: 800.0,
            p99_latency_ms: 2500.0,
            throughput_rps: 10.0,
            max_batch_size: Some(1),
        },
        requirements: vec![],
        provides: vec![OutputSpec {
            kind: "search-results".into(),
            attributes: HashMap::new(),
        }],
        dependencies: vec![],
        quality: QualityMetrics {
            trust_score: 90,
            accuracy: Some(0.95),
            uptime_pct: 99.5,
            success_count: 0,
        },
        version: SemanticVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        cost: CostModel {
            per_invocation_micro_usd: 500,
            per_token_micro_usd: None,
            has_free_tier: true,
        },
        geo: None,
    }
}

fn web_browse_capability() -> SemanticCapability {
    SemanticCapability {
        name: "web-browse".into(),
        category: CapabilityCategory::Navigation,
        attributes: CapabilityAttributes {
            languages: vec!["*".into()],
            modalities: vec![Modality::Text, Modality::Image],
            hardware: vec![],
            frameworks: vec!["firecrawl".into(), "playwright".into()],
            precision: vec![],
            custom: HashMap::from([
                ("javascript_support".into(), MetadataValue::Bool(true)),
                (
                    "wait_strategy".into(),
                    MetadataValue::Text("domcontentloaded|load|networkidle".into()),
                ),
                (
                    "format".into(),
                    MetadataValue::Text("agent-native|markdown|html|accessibility".into()),
                ),
            ]),
        },
        performance: PerformanceProfile {
            avg_latency_ms: 2000.0,
            p99_latency_ms: 8000.0,
            throughput_rps: 5.0,
            max_batch_size: Some(1),
        },
        requirements: vec![],
        provides: vec![OutputSpec {
            kind: "web-content".into(),
            attributes: HashMap::new(),
        }],
        dependencies: vec![],
        quality: QualityMetrics {
            trust_score: 85,
            accuracy: None,
            uptime_pct: 99.0,
            success_count: 0,
        },
        version: SemanticVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        cost: CostModel {
            per_invocation_micro_usd: 2000,
            per_token_micro_usd: None,
            has_free_tier: false,
        },
        geo: None,
    }
}

fn document_read_capability() -> SemanticCapability {
    SemanticCapability {
        name: "document-read".into(),
        category: CapabilityCategory::Parsing,
        attributes: CapabilityAttributes {
            languages: vec!["*".into()],
            modalities: vec![Modality::Text],
            hardware: vec![],
            frameworks: vec!["pymupdf".into(), "tika".into(), "python-docx".into()],
            precision: vec![],
            custom: HashMap::from([
                (
                    "formats".into(),
                    MetadataValue::Text("pdf|word|excel|powerpoint".into()),
                ),
                ("ocr_support".into(), MetadataValue::Bool(true)),
            ]),
        },
        performance: PerformanceProfile {
            avg_latency_ms: 3000.0,
            p99_latency_ms: 15000.0,
            throughput_rps: 3.0,
            max_batch_size: Some(1),
        },
        requirements: vec![Requirement {
            kind: "document-bytes".into(),
            optional: false,
        }],
        provides: vec![OutputSpec {
            kind: "document-content".into(),
            attributes: HashMap::new(),
        }],
        dependencies: vec![CapabilityEdge {
            target: "image-ocr".into(),
            edge_type: EdgeType::Enables,
            constraint: Some("if-scanned".into()),
        }],
        quality: QualityMetrics {
            trust_score: 88,
            accuracy: Some(0.92),
            uptime_pct: 99.0,
            success_count: 0,
        },
        version: SemanticVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        cost: CostModel {
            per_invocation_micro_usd: 1000,
            per_token_micro_usd: None,
            has_free_tier: true,
        },
        geo: None,
    }
}

fn api_call_capability() -> SemanticCapability {
    SemanticCapability {
        name: "api-call".into(),
        category: CapabilityCategory::Integration,
        attributes: CapabilityAttributes {
            languages: vec!["*".into()],
            modalities: vec![Modality::Text],
            hardware: vec![],
            frameworks: vec!["http".into()],
            precision: vec![],
            custom: HashMap::from([
                (
                    "protocols".into(),
                    MetadataValue::Text("rest|graphql|grpc".into()),
                ),
                (
                    "auth_methods".into(),
                    MetadataValue::Text("bearer|basic|oauth2|api-key".into()),
                ),
            ]),
        },
        performance: PerformanceProfile {
            avg_latency_ms: 500.0,
            p99_latency_ms: 5000.0,
            throughput_rps: 20.0,
            max_batch_size: Some(1),
        },
        requirements: vec![],
        provides: vec![OutputSpec {
            kind: "api-response".into(),
            attributes: HashMap::new(),
        }],
        dependencies: vec![],
        quality: QualityMetrics {
            trust_score: 92,
            accuracy: None,
            uptime_pct: 99.5,
            success_count: 0,
        },
        version: SemanticVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        cost: CostModel {
            per_invocation_micro_usd: 100,
            per_token_micro_usd: None,
            has_free_tier: true,
        },
        geo: None,
    }
}

fn api_discover_capability() -> SemanticCapability {
    SemanticCapability {
        name: "api-discover".into(),
        category: CapabilityCategory::Integration,
        attributes: CapabilityAttributes {
            languages: vec!["*".into()],
            modalities: vec![Modality::Text],
            hardware: vec![],
            frameworks: vec!["openapi".into(), "graphql-schema".into()],
            precision: vec![],
            custom: HashMap::from([(
                "spec_formats".into(),
                MetadataValue::Text("openapi|graphql-schema".into()),
            )]),
        },
        performance: PerformanceProfile {
            avg_latency_ms: 1500.0,
            p99_latency_ms: 6000.0,
            throughput_rps: 5.0,
            max_batch_size: Some(1),
        },
        requirements: vec![],
        provides: vec![OutputSpec {
            kind: "api-spec".into(),
            attributes: HashMap::new(),
        }],
        dependencies: vec![CapabilityEdge {
            target: "api-call".into(),
            edge_type: EdgeType::Precedes,
            constraint: None,
        }],
        quality: QualityMetrics {
            trust_score: 80,
            accuracy: Some(0.85),
            uptime_pct: 98.0,
            success_count: 0,
        },
        version: SemanticVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        cost: CostModel {
            per_invocation_micro_usd: 300,
            per_token_micro_usd: None,
            has_free_tier: true,
        },
        geo: None,
    }
}

fn code_execute_capability() -> SemanticCapability {
    SemanticCapability {
        name: "code-execute".into(),
        category: CapabilityCategory::Computation,
        attributes: CapabilityAttributes {
            languages: vec!["*".into()],
            modalities: vec![Modality::Text],
            hardware: vec![HardwareSpec {
                kind: "cpu".into(),
                model: None,
                vram_mb: None,
            }],
            frameworks: vec!["firecracker".into(), "wasm".into()],
            precision: vec![],
            custom: HashMap::from([
                (
                    "sandbox_type".into(),
                    MetadataValue::Text("firecracker|wasm".into()),
                ),
                ("timeout_s".into(), MetadataValue::Int(30)),
                ("network".into(), MetadataValue::Bool(false)),
            ]),
        },
        performance: PerformanceProfile {
            avg_latency_ms: 300.0,
            p99_latency_ms: 30000.0,
            throughput_rps: 2.0,
            max_batch_size: Some(1),
        },
        requirements: vec![],
        provides: vec![OutputSpec {
            kind: "execution-result".into(),
            attributes: HashMap::new(),
        }],
        dependencies: vec![],
        quality: QualityMetrics {
            trust_score: 95,
            accuracy: None,
            uptime_pct: 99.0,
            success_count: 0,
        },
        version: SemanticVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        cost: CostModel {
            per_invocation_micro_usd: 5000,
            per_token_micro_usd: None,
            has_free_tier: false,
        },
        geo: None,
    }
}

fn image_ocr_capability() -> SemanticCapability {
    SemanticCapability {
        name: "image-ocr".into(),
        category: CapabilityCategory::Perception,
        attributes: CapabilityAttributes {
            languages: vec![
                "en".into(),
                "fr".into(),
                "de".into(),
                "ja".into(),
                "zh".into(),
            ],
            modalities: vec![Modality::Image, Modality::Text],
            hardware: vec![HardwareSpec {
                kind: "gpu".into(),
                model: None,
                vram_mb: None,
            }],
            frameworks: vec!["tesseract".into(), "google-vision".into()],
            precision: vec!["FP16".into()],
            custom: HashMap::from([
                ("min_confidence".into(), MetadataValue::Int(80)),
                ("gpu_required".into(), MetadataValue::Bool(false)),
            ]),
        },
        performance: PerformanceProfile {
            avg_latency_ms: 200.0,
            p99_latency_ms: 2000.0,
            throughput_rps: 20.0,
            max_batch_size: Some(32),
        },
        requirements: vec![Requirement {
            kind: "image-bytes".into(),
            optional: false,
        }],
        provides: vec![OutputSpec {
            kind: "ocr-text".into(),
            attributes: HashMap::new(),
        }],
        dependencies: vec![],
        quality: QualityMetrics {
            trust_score: 87,
            accuracy: Some(0.90),
            uptime_pct: 99.0,
            success_count: 0,
        },
        version: SemanticVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        cost: CostModel {
            per_invocation_micro_usd: 100,
            per_token_micro_usd: None,
            has_free_tier: true,
        },
        geo: None,
    }
}

fn audio_transcribe_capability() -> SemanticCapability {
    SemanticCapability {
        name: "audio-transcribe".into(),
        category: CapabilityCategory::Perception,
        attributes: CapabilityAttributes {
            languages: vec![
                "en".into(),
                "fr".into(),
                "de".into(),
                "ja".into(),
                "zh".into(),
            ],
            modalities: vec![Modality::Audio, Modality::Text],
            hardware: vec![HardwareSpec {
                kind: "gpu".into(),
                model: None,
                vram_mb: None,
            }],
            frameworks: vec!["whisper".into(), "deepgram".into()],
            precision: vec!["FP16".into()],
            custom: HashMap::from([
                (
                    "formats".into(),
                    MetadataValue::Text("wav|mp3|flac|ogg".into()),
                ),
                ("real_time".into(), MetadataValue::Bool(true)),
            ]),
        },
        performance: PerformanceProfile {
            avg_latency_ms: 1000.0,
            p99_latency_ms: 10000.0,
            throughput_rps: 5.0,
            max_batch_size: Some(1),
        },
        requirements: vec![Requirement {
            kind: "audio-bytes".into(),
            optional: false,
        }],
        provides: vec![OutputSpec {
            kind: "transcript".into(),
            attributes: HashMap::new(),
        }],
        dependencies: vec![],
        quality: QualityMetrics {
            trust_score: 89,
            accuracy: Some(0.93),
            uptime_pct: 99.0,
            success_count: 0,
        },
        version: SemanticVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        cost: CostModel {
            per_invocation_micro_usd: 2000,
            per_token_micro_usd: None,
            has_free_tier: false,
        },
        geo: None,
    }
}

fn crawl_capability() -> SemanticCapability {
    SemanticCapability {
        name: "crawl".into(),
        category: CapabilityCategory::InformationRetrieval,
        attributes: CapabilityAttributes {
            languages: vec!["*".into()],
            modalities: vec![Modality::Text],
            hardware: vec![],
            frameworks: vec!["dht-frontier".into()],
            precision: vec![],
            custom: HashMap::from([
                ("rate_limit_rps".into(), MetadataValue::Int(1)),
                ("max_depth".into(), MetadataValue::Int(10)),
                ("robots_txt".into(), MetadataValue::Bool(true)),
            ]),
        },
        performance: PerformanceProfile {
            avg_latency_ms: 5000.0,
            p99_latency_ms: 60000.0,
            throughput_rps: 1.0,
            max_batch_size: Some(100),
        },
        requirements: vec![],
        provides: vec![OutputSpec {
            kind: "crawled-pages".into(),
            attributes: HashMap::new(),
        }],
        dependencies: vec![CapabilityEdge {
            target: "web-browse".into(),
            edge_type: EdgeType::Requires,
            constraint: None,
        }],
        quality: QualityMetrics {
            trust_score: 75,
            accuracy: None,
            uptime_pct: 95.0,
            success_count: 0,
        },
        version: SemanticVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        cost: CostModel {
            per_invocation_micro_usd: 100,
            per_token_micro_usd: None,
            has_free_tier: true,
        },
        geo: None,
    }
}

fn real_time_subscribe_capability() -> SemanticCapability {
    SemanticCapability {
        name: "real-time-subscribe".into(),
        category: CapabilityCategory::Streaming,
        attributes: CapabilityAttributes {
            languages: vec!["*".into()],
            modalities: vec![Modality::Text],
            hardware: vec![],
            frameworks: vec!["websocket".into(), "sse".into(), "grpc-stream".into()],
            precision: vec![],
            custom: HashMap::from([(
                "protocols".into(),
                MetadataValue::Text("websocket|sse|grpc-stream".into()),
            )]),
        },
        performance: PerformanceProfile {
            avg_latency_ms: 100.0,
            p99_latency_ms: 1000.0,
            throughput_rps: 100.0,
            max_batch_size: None,
        },
        requirements: vec![],
        provides: vec![OutputSpec {
            kind: "event-stream".into(),
            attributes: HashMap::new(),
        }],
        dependencies: vec![],
        quality: QualityMetrics {
            trust_score: 85,
            accuracy: None,
            uptime_pct: 99.0,
            success_count: 0,
        },
        version: SemanticVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        cost: CostModel {
            per_invocation_micro_usd: 50,
            per_token_micro_usd: None,
            has_free_tier: true,
        },
        geo: None,
    }
}

fn stealth_browse_capability() -> SemanticCapability {
    SemanticCapability {
        name: "stealth-browse".into(),
        category: CapabilityCategory::Navigation,
        attributes: CapabilityAttributes {
            languages: vec!["*".into()],
            modalities: vec![Modality::Text, Modality::Image],
            hardware: vec![],
            frameworks: vec!["browserless".into(), "bright-data".into()],
            precision: vec![],
            custom: HashMap::from([
                ("proxy_support".into(), MetadataValue::Bool(true)),
                ("captcha_solving".into(), MetadataValue::Bool(true)),
            ]),
        },
        performance: PerformanceProfile {
            avg_latency_ms: 4000.0,
            p99_latency_ms: 20000.0,
            throughput_rps: 2.0,
            max_batch_size: Some(1),
        },
        requirements: vec![],
        provides: vec![OutputSpec {
            kind: "web-content".into(),
            attributes: HashMap::new(),
        }],
        dependencies: vec![CapabilityEdge {
            target: "web-browse".into(),
            edge_type: EdgeType::Alternative,
            constraint: Some("anti-bot".into()),
        }],
        quality: QualityMetrics {
            trust_score: 70,
            accuracy: None,
            uptime_pct: 90.0,
            success_count: 0,
        },
        version: SemanticVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        cost: CostModel {
            per_invocation_micro_usd: 10000,
            per_token_micro_usd: None,
            has_free_tier: false,
        },
        geo: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_eleven_capabilities_present() {
        let caps = internet_bridge_capabilities();
        assert_eq!(caps.len(), 11);
        for name in &[
            "search",
            "web-browse",
            "document-read",
            "api-call",
            "api-discover",
            "code-execute",
            "image-ocr",
            "audio-transcribe",
            "crawl",
            "real-time-subscribe",
            "stealth-browse",
        ] {
            assert!(caps.iter().any(|c| c.name == *name), "missing {}", name);
        }
    }

    #[test]
    fn search_has_correct_provides() {
        let caps = internet_bridge_capabilities();
        let search = caps.iter().find(|c| c.name == "search").unwrap();
        assert_eq!(search.provides.len(), 1);
        assert_eq!(search.provides[0].kind, "search-results");
    }

    #[test]
    fn crawl_requires_web_browse() {
        let caps = internet_bridge_capabilities();
        let crawl = caps.iter().find(|c| c.name == "crawl").unwrap();
        assert!(crawl
            .dependencies
            .iter()
            .any(|e| e.target == "web-browse" && e.edge_type == EdgeType::Requires));
    }

    #[test]
    fn stealth_browse_provides_web_content() {
        let caps = internet_bridge_capabilities();
        let stealth = caps.iter().find(|c| c.name == "stealth-browse").unwrap();
        assert!(stealth.provides.iter().any(|o| o.kind == "web-content"));
    }

    #[test]
    fn document_read_requires_document_bytes() {
        let caps = internet_bridge_capabilities();
        let doc = caps.iter().find(|c| c.name == "document-read").unwrap();
        assert!(doc.requirements.iter().any(|r| r.kind == "document-bytes"));
    }

    #[test]
    fn image_ocr_requires_image_bytes() {
        let caps = internet_bridge_capabilities();
        let ocr = caps.iter().find(|c| c.name == "image-ocr").unwrap();
        assert!(ocr.requirements.iter().any(|r| r.kind == "image-bytes"));
    }

    #[test]
    fn api_discover_precedes_api_call() {
        let caps = internet_bridge_capabilities();
        let discover = caps.iter().find(|c| c.name == "api-discover").unwrap();
        assert!(discover
            .dependencies
            .iter()
            .any(|e| e.target == "api-call" && e.edge_type == EdgeType::Precedes));
    }

    #[test]
    fn all_capabilities_have_version_1_0_0() {
        let caps = internet_bridge_capabilities();
        for cap in &caps {
            assert_eq!(cap.version.major, 1);
            assert_eq!(cap.version.minor, 0);
            assert_eq!(cap.version.patch, 0);
        }
    }

    #[test]
    fn bridge_capabilities_cbor_roundtrip() {
        let caps = internet_bridge_capabilities();
        for cap in &caps {
            let cbor = cap.to_cbor();
            let encoded = aafp_cbor::encode(&cbor).unwrap();
            let (decoded, _) = aafp_cbor::decode(&encoded).unwrap();
            let cap2 = SemanticCapability::from_cbor(&decoded).unwrap();
            assert_eq!(cap, &cap2, "CBOR roundtrip failed for {}", cap.name);
        }
    }
}
