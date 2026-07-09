//! Live integration test for real-world providers.
//!
//! Run with:
//! ```bash
//! FIRECRAWL_API_KEY=fc-... cargo test --test live_providers -- --nocapture --ignored
//! ```

#![cfg(test)]

use std::sync::Arc;

use aafp_perception::capabilities::document_read::{DocumentReadCapability, DocumentReadRequest};
use aafp_perception::capabilities::media::{ImageFormat, MediaCapability, MediaConfig, OcrRequest};
use aafp_perception::capabilities::search::{SearchCapability, SearchConfig, SearchRequest};
use aafp_perception::capabilities::web_browse::{BrowseConfig, BrowseRequest, WebBrowseCapability};
use aafp_perception::providers::{
    DuckDuckGoSearchProvider, FirecrawlBrowseProvider, PyMuPdfConfig, PyMuPdfProvider,
    TesseractOcrProvider,
};

fn agent_id() -> aafp_identity::AgentId {
    let mut a = [0u8; 32];
    a[0] = 1;
    a
}

#[tokio::test]
#[ignore = "requires network access"]
async fn live_duckduckgo_search() {
    let provider = DuckDuckGoSearchProvider::new().expect("create DDG provider");
    let cap = SearchCapability::new(
        vec![Arc::new(provider)],
        SearchConfig {
            max_results: 5,
            rate_limit_per_hour: 100,
            federation: false,
        },
    );

    let req = SearchRequest::new("rust programming language");
    let resp = cap.search(&req, &agent_id()).await.expect("search ok");

    println!("\n=== DuckDuckGo Search Results ===");
    println!("Total: {}", resp.total);
    for (i, result) in resp.results.iter().enumerate() {
        println!("  [{}] {} — {}", i + 1, result.title, result.url);
        if !result.snippet.is_empty() {
            println!(
                "       {}",
                result.snippet.chars().take(100).collect::<String>()
            );
        }
    }
    assert!(!resp.results.is_empty(), "should get at least one result");
}

#[tokio::test]
#[ignore = "requires FIRECRAWL_API_KEY and network access"]
async fn live_firecrawl_browse() {
    let provider = FirecrawlBrowseProvider::from_env(Default::default())
        .expect("create Firecrawl provider — set FIRECRAWL_API_KEY");
    let cap = WebBrowseCapability::new(
        Arc::new(provider),
        BrowseConfig {
            respect_robots: false,
            ..Default::default()
        },
    );

    let req = BrowseRequest::new("https://example.com");
    let resp = cap.browse(&req).await.expect("browse ok");

    println!("\n=== Firecrawl Browse Result ===");
    match resp.content {
        aafp_perception::capabilities::web_browse::BrowseContent::AgentNative(wc) => {
            println!("URL: {}", wc.url);
            println!("Title: {}", wc.title);
            println!("Sections: {}", wc.sections.len());
            println!("Links: {}", wc.links.len());
            if let Some(s) = wc.sections.first() {
                println!("\nFirst section: {}", s.title);
                println!("  {}", s.content.chars().take(200).collect::<String>());
            }
            assert!(!wc.title.is_empty(), "should have a title");
        }
        _ => panic!("expected agent-native content"),
    }
}

#[tokio::test]
#[ignore = "requires tesseract installed and /tmp/aafp_test_ocr.png"]
async fn live_tesseract_ocr() {
    let image_data = tokio::fs::read("/tmp/aafp_test_ocr.png")
        .await
        .expect("read test image — create it with the test helper");
    let provider = TesseractOcrProvider::new();
    let cap = MediaCapability::new(Arc::new(provider), MediaConfig::default());

    let req = OcrRequest::new(image_data, ImageFormat::Png);
    let resp = cap.ocr(&req).await.expect("ocr ok");

    println!("\n=== Tesseract OCR Result ===");
    println!("Text: {}", resp.text);
    println!("Confidence: {}", resp.confidence);
    println!("Blocks: {}", resp.blocks.len());

    assert!(!resp.text.is_empty(), "should extract some text");
    assert!(
        resp.text.to_lowercase().contains("hello") || resp.text.to_lowercase().contains("aafp"),
        "should contain expected words"
    );
}

#[tokio::test]
#[ignore = "requires pymupdf installed and /tmp/aafp_test.pdf"]
async fn live_pymupdf_read() {
    // Use the venv Python that has pymupdf installed.
    let python = std::env::var("AAFP_PYTHON")
        .unwrap_or_else(|_| "/Users/david/AAFP-research/.venv/bin/python3".to_string());
    let provider = PyMuPdfProvider::with_config(PyMuPdfConfig {
        python,
        ..Default::default()
    });
    let cap = DocumentReadCapability::new(Arc::new(provider), Default::default());

    let req = DocumentReadRequest::new("/tmp/aafp_test.pdf");
    let content = cap.read(&req, &agent_id()).await.expect("read ok");

    println!("\n=== PyMuPDF Document Read Result ===");
    println!("Source: {}", content.source);
    println!("Type: {}", content.doc_type);
    println!("Pages: {}", content.pages.len());
    for page in &content.pages {
        println!(
            "  Page {}: {}...",
            page.page_num,
            page.text.chars().take(60).collect::<String>()
        );
    }

    assert_eq!(content.doc_type, "pdf");
    assert_eq!(content.pages.len(), 2, "should have 2 pages");
    assert!(
        content.pages[0].text.contains("Hello") || content.pages[0].text.contains("AAFP"),
        "page 1 should contain expected text"
    );
}
