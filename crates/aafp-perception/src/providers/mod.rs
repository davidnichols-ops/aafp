//! Real-world provider implementations for the perception layer.
//!
//! Each module implements one of the pluggable provider traits
//! (`SearchProvider`, `BrowseProvider`, `DocumentReadProvider`,
//! `MediaProvider`) against a concrete external service or local tool.
//!
//! - [`firecrawl`] — Firecrawl API → `BrowseProvider`
//! - [`duckduckgo`] — DuckDuckGo HTML search → `SearchProvider` (free, no key)
//! - [`tesseract`] — Tesseract OCR CLI → `MediaProvider` (OCR only)
//! - [`pymupdf`] — PyMuPDF via Python subprocess → `DocumentReadProvider` (PDF)

pub mod duckduckgo;
pub mod firecrawl;
pub mod pymupdf;
pub mod tesseract;

pub use duckduckgo::{DuckDuckGoConfig, DuckDuckGoSearchProvider};
pub use firecrawl::{FirecrawlBrowseProvider, FirecrawlConfig};
pub use pymupdf::{PyMuPdfConfig, PyMuPdfProvider};
pub use tesseract::{TesseractConfig, TesseractOcrProvider};
