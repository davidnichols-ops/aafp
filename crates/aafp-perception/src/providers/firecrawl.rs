//! Firecrawl browse provider.
//!
//! Implements [`BrowseProvider`] by calling the Firecrawl API
//! (<https://www.firecrawl.dev>) to fetch a URL and convert it to
//! structured markdown / JSON, which is then mapped into the
//! agent-native [`WebContent`] schema.
//!
//! The API key is read from the `FIRECRAWL_API_KEY` environment variable
//! at construction time (or passed explicitly to [`FirecrawlBrowseProvider::with_key`]).

use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::capabilities::web_browse::{BrowseProvider, BrowseRequest};
use crate::schema::{
    ContentHash, ContentSection, LinkDef, NavigationState, PageMetadata, WebContent,
};
use crate::PerceptionError;

/// Firecrawl API configuration.
#[derive(Clone, Debug)]
pub struct FirecrawlConfig {
    /// API base URL (default: `https://api.firecrawl.dev/v0`).
    pub base_url: String,
    /// Request timeout in milliseconds.
    pub timeout_ms: u64,
}

impl Default for FirecrawlConfig {
    fn default() -> Self {
        Self {
            base_url: "https://api.firecrawl.dev/v1".to_string(),
            timeout_ms: 30_000,
        }
    }
}

/// A [`BrowseProvider`] backed by the Firecrawl API.
pub struct FirecrawlBrowseProvider {
    api_key: String,
    config: FirecrawlConfig,
    client: reqwest::Client,
}

// --- Firecrawl request / response types ---

#[derive(Serialize)]
struct FirecrawlScrapeReq {
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    formats: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct FirecrawlScrapeResp {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    data: Option<FirecrawlScrapeData>,
}

#[derive(Deserialize, Default)]
struct FirecrawlScrapeData {
    #[serde(default)]
    markdown: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    html: Option<String>,
    #[serde(default)]
    metadata: Option<FirecrawlPageMeta>,
}

#[derive(Deserialize, Default)]
struct FirecrawlPageMeta {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    source_url: Option<String>,
    #[serde(default)]
    status_code: Option<u16>,
}

impl FirecrawlBrowseProvider {
    /// Create a new provider, reading the API key from the
    /// `FIRECRAWL_API_KEY` environment variable.
    pub fn from_env(config: FirecrawlConfig) -> Result<Self, PerceptionError> {
        let api_key = std::env::var("FIRECRAWL_API_KEY").map_err(|_| {
            PerceptionError::Provider("FIRECRAWL_API_KEY environment variable not set".into())
        })?;
        Self::with_key(api_key, config)
    }

    /// Create a new provider with an explicit API key.
    pub fn with_key(
        api_key: impl Into<String>,
        config: FirecrawlConfig,
    ) -> Result<Self, PerceptionError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(config.timeout_ms))
            .build()
            .map_err(|e| PerceptionError::Provider(format!("reqwest client build: {e}")))?;
        Ok(Self {
            api_key: api_key.into(),
            config,
            client,
        })
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Split markdown into rough sections by heading lines.
    fn markdown_to_sections(markdown: &str) -> Vec<ContentSection> {
        let mut sections = Vec::new();
        let mut current_id = 0u32;
        let mut current_title = String::from("Content");
        let mut current_level = 1u8;
        let mut current_lines: Vec<String> = Vec::new();

        for line in markdown.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with('#') {
                // Flush the previous section.
                if !current_lines.is_empty() {
                    sections.push(ContentSection {
                        id: format!("s{current_id}"),
                        title: std::mem::take(&mut current_title),
                        content: current_lines.join("\n"),
                        level: current_level,
                        children: Vec::new(),
                    });
                    current_id += 1;
                    current_lines.clear();
                }
                let hashes = trimmed.chars().take_while(|c| *c == '#').count();
                current_level = hashes.min(6) as u8;
                current_title = trimmed[hashes..].trim().to_string();
            } else {
                current_lines.push(line.to_string());
            }
        }
        // Flush the last section.
        if !current_lines.is_empty() || current_id == 0 {
            sections.push(ContentSection {
                id: format!("s{current_id}"),
                title: std::mem::take(&mut current_title),
                content: current_lines.join("\n"),
                level: current_level,
                children: Vec::new(),
            });
        }
        sections
    }

    /// Extract links from markdown `[text](url)` syntax.
    fn extract_links(markdown: &str, base_url: &str) -> Vec<LinkDef> {
        let mut links = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (text, url) in extract_markdown_links(markdown) {
            let absolute = if url.starts_with("http://") || url.starts_with("https://") {
                url.clone()
            } else if url.starts_with('/') {
                // Relative to root.
                let base_origin = base_url
                    .split("://")
                    .nth(1)
                    .and_then(|s| s.split('/').next())
                    .unwrap_or("");
                let scheme = base_url.split("://").next().unwrap_or("https");
                format!("{scheme}://{base_origin}{url}")
            } else {
                continue; // Skip complex relative URLs for now.
            };
            if seen.insert(absolute.clone()) {
                let internal = absolute
                    .split("://")
                    .nth(1)
                    .and_then(|s| s.split('/').next())
                    .map(|h| base_url.contains(h))
                    .unwrap_or(false);
                links.push(LinkDef {
                    text,
                    url: absolute,
                    internal,
                    rel: None,
                });
            }
        }
        links
    }
}

/// Parse `[text](url)` pairs from markdown text.
fn extract_markdown_links(markdown: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = markdown.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'[' {
            // Find closing ']'.
            if let Some(close_bracket) = markdown[i + 1..].find(']') {
                let text_end = i + 1 + close_bracket;
                let text = &markdown[i + 1..text_end];
                // Check for '(' right after ']'.
                if text_end + 1 < bytes.len() && bytes[text_end + 1] == b'(' {
                    if let Some(close_paren) = markdown[text_end + 2..].find(')') {
                        let url_end = text_end + 2 + close_paren;
                        let url = &markdown[text_end + 2..url_end];
                        if !text.is_empty() && !url.is_empty() {
                            out.push((text.to_string(), url.to_string()));
                        }
                        i = url_end + 1;
                        continue;
                    }
                }
            }
        }
        i += 1;
    }
    out
}

#[async_trait]
impl BrowseProvider for FirecrawlBrowseProvider {
    async fn browse(&self, request: &BrowseRequest) -> Result<WebContent, PerceptionError> {
        let url = &request.url;
        let endpoint = format!("{}/scrape", self.config.base_url);

        let body = FirecrawlScrapeReq {
            url: url.clone(),
            formats: Some(vec!["markdown".to_string()]),
        };

        let resp = self
            .client
            .post(&endpoint)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&body)
            .send()
            .await
            .map_err(|e| PerceptionError::Provider(format!("firecrawl request: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(PerceptionError::Provider(format!(
                "firecrawl HTTP {status}: {text}"
            )));
        }

        let scrape: FirecrawlScrapeResp = resp
            .json()
            .await
            .map_err(|e| PerceptionError::Provider(format!("firecrawl decode: {e}")))?;

        if !scrape.success {
            return Err(PerceptionError::Provider(
                "firecrawl returned success=false".into(),
            ));
        }

        let data = scrape.data.unwrap_or_default();
        let markdown = data.markdown.unwrap_or_default();
        let meta = data.metadata.unwrap_or_default();

        let title = meta.title.unwrap_or_else(|| {
            // Try to extract from first heading.
            markdown
                .lines()
                .find(|l| l.trim_start().starts_with('#'))
                .map(|l| l.trim_start_matches('#').trim().to_string())
                .unwrap_or_else(|| "Untitled".to_string())
        });

        let sections = Self::markdown_to_sections(&markdown);
        let links = Self::extract_links(&markdown, url);
        let fetched_at = Self::now_ms();

        // Compute content hash from the markdown body.
        let hash = ContentHash::compute(markdown.as_bytes());

        Ok(WebContent {
            url: meta.source_url.unwrap_or_else(|| url.clone()),
            title: title.clone(),
            metadata: PageMetadata {
                status_code: meta.status_code.unwrap_or(200),
                content_type: "text/html".into(),
                charset: Some("utf-8".into()),
                language: meta.language,
                title: Some(title.clone()),
                description: meta.description,
                fetched_at,
            },
            nav: NavigationState {
                url: url.clone(),
                title,
                can_go_back: false,
                can_go_forward: false,
            },
            sections,
            elements: Vec::new(),
            forms: Vec::new(),
            media: Vec::new(),
            links,
            structured: Vec::new(),
            entities: Vec::new(),
            hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_markdown_links() {
        let md = "See [Google](https://google.com) and [about](/about) and [text](relative)";
        let links = extract_markdown_links(md);
        assert_eq!(links.len(), 3);
        assert_eq!(links[0].0, "Google");
        assert_eq!(links[0].1, "https://google.com");
    }

    #[test]
    fn test_markdown_to_sections() {
        let md = "# Title\n\nIntro text\n\n## Section A\n\nContent A\n\n## Section B\n\nContent B";
        let sections = FirecrawlBrowseProvider::markdown_to_sections(md);
        assert_eq!(sections.len(), 3);
        assert_eq!(sections[0].title, "Title");
        assert_eq!(sections[0].level, 1);
        assert_eq!(sections[1].title, "Section A");
        assert_eq!(sections[1].level, 2);
        assert_eq!(sections[2].title, "Section B");
    }

    #[test]
    fn test_extract_links_absolute() {
        let md = "[link](https://example.com/page)";
        let links = FirecrawlBrowseProvider::extract_links(md, "https://mysite.com");
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].url, "https://example.com/page");
        assert!(!links[0].internal);
    }

    #[test]
    fn test_extract_links_internal() {
        let md = "[link](https://mysite.com/page)";
        let links = FirecrawlBrowseProvider::extract_links(md, "https://mysite.com");
        assert_eq!(links.len(), 1);
        assert!(links[0].internal);
    }
}
