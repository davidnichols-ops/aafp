//! DuckDuckGo search provider.
//!
//! Implements [`SearchProvider`] by scraping DuckDuckGo's HTML search
//! results page. This is a free, no-API-key approach that works for
//! low-volume queries.
//!
//! **Rate-limit note:** DuckDuckGo may throttle or block automated
//! requests if the volume is too high. For production use, consider
//! using an official search API or a self-hosted SearXNG instance.

use async_trait::async_trait;
use scraper::{Html, Selector};

use crate::capabilities::search::{
    SearchProvider, SearchRequest, SearchResponse, SearchResult, TimeRange,
};
use crate::PerceptionError;

/// Configuration for the DuckDuckGo search provider.
#[derive(Clone, Debug)]
pub struct DuckDuckGoConfig {
    /// Base URL for the HTML search endpoint.
    pub base_url: String,
    /// Request timeout in milliseconds.
    pub timeout_ms: u64,
    /// Optional user-agent string.
    pub user_agent: String,
}

impl Default for DuckDuckGoConfig {
    fn default() -> Self {
        Self {
            base_url: "https://html.duckduckgo.com/html".to_string(),
            timeout_ms: 15_000,
            user_agent: "Mozilla/5.0 (compatible; AAFP-Agent/1.0)".to_string(),
        }
    }
}

/// A [`SearchProvider`] backed by DuckDuckGo HTML search.
pub struct DuckDuckGoSearchProvider {
    config: DuckDuckGoConfig,
    client: reqwest::Client,
}

impl DuckDuckGoSearchProvider {
    /// Create a new provider with default configuration.
    pub fn new() -> Result<Self, PerceptionError> {
        Self::with_config(DuckDuckGoConfig::default())
    }

    /// Create a new provider with custom configuration.
    pub fn with_config(config: DuckDuckGoConfig) -> Result<Self, PerceptionError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(config.timeout_ms))
            .user_agent(&config.user_agent)
            .build()
            .map_err(|e| PerceptionError::Provider(format!("reqwest client build: {e}")))?;
        Ok(Self { config, client })
    }

    /// Map a [`TimeRange`] to DuckDuckGo's `df` parameter.
    fn time_range_param(range: &TimeRange) -> Option<&'static str> {
        match range {
            TimeRange::PastDay => Some("d"),
            TimeRange::PastWeek => Some("w"),
            TimeRange::PastMonth => Some("m"),
            TimeRange::PastYear => Some("y"),
        }
    }

    /// Parse the DuckDuckGo HTML results page into [`SearchResult`]s.
    fn parse_html(html: &str) -> Vec<SearchResult> {
        let document = Html::parse_document(html);
        let mut results = Vec::new();

        // DuckDuckGo HTML results use `.result` blocks with `.result__a` links
        // and `.result__snippet` text.
        let result_sel = Selector::parse(".result, .web-result").ok();
        let link_sel = Selector::parse(".result__a").ok();
        let snippet_sel = Selector::parse(".result__snippet").ok();

        // Try to select result blocks.
        if let (Some(result_sel), Some(link_sel), Some(snippet_sel)) =
            (&result_sel, &link_sel, &snippet_sel)
        {
            for block in document.select(result_sel) {
                let title = block
                    .select(link_sel)
                    .next()
                    .map(|e| e.text().collect::<String>().trim().to_string())
                    .unwrap_or_default();

                let url = block
                    .select(link_sel)
                    .next()
                    .and_then(|e| e.value().attr("href"))
                    .map(|h| {
                        // DuckDuckGo wraps URLs in a redirect like
                        // //duckduckgo.com/l/?uddg=<actual_url>
                        if let Some(stripped) = h.strip_prefix("//duckduckgo.com/l/?uddg=") {
                            // URL-decode the parameter
                            url_decode(stripped.split('&').next().unwrap_or(stripped))
                        } else {
                            h.to_string()
                        }
                    })
                    .unwrap_or_default();

                let snippet = block
                    .select(snippet_sel)
                    .next()
                    .map(|e| e.text().collect::<String>().trim().to_string())
                    .unwrap_or_default();

                if !title.is_empty() && !url.is_empty() {
                    results.push(SearchResult {
                        title,
                        url,
                        snippet,
                        score: 1.0 - (results.len() as f64 * 0.05),
                        source: "duckduckgo".into(),
                    });
                }
            }
        }

        // Fallback: if the structured selectors didn't match, try a looser
        // approach by scanning for any `.result__a` links on the page.
        if results.is_empty() {
            if let Some(link_sel) = &link_sel {
                for (i, link) in document.select(link_sel).enumerate() {
                    let title = link.text().collect::<String>().trim().to_string();
                    let url = link
                        .value()
                        .attr("href")
                        .map(|h| {
                            if let Some(stripped) = h.strip_prefix("//duckduckgo.com/l/?uddg=") {
                                url_decode(stripped.split('&').next().unwrap_or(stripped))
                            } else {
                                h.to_string()
                            }
                        })
                        .unwrap_or_default();
                    if !title.is_empty() && !url.is_empty() {
                        results.push(SearchResult {
                            title,
                            url,
                            snippet: String::new(),
                            score: 1.0 - (i as f64 * 0.05),
                            source: "duckduckgo".into(),
                        });
                    }
                }
            }
        }

        results
    }
}

/// Minimal URL percent-decoder for the `uddg` redirect parameter.
fn url_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h * 16 + l) as char);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(' ');
        } else {
            out.push(bytes[i] as char);
        }
        i += 1;
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[async_trait]
impl SearchProvider for DuckDuckGoSearchProvider {
    async fn search(&self, request: &SearchRequest) -> Result<SearchResponse, PerceptionError> {
        let mut params = vec![("q", request.query.clone())];

        if let Some(range) = &request.time_range {
            if let Some(df) = Self::time_range_param(range) {
                params.push(("df", df.to_string()));
            }
        }

        let resp = self
            .client
            .post(&self.config.base_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| PerceptionError::Provider(format!("duckduckgo request: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(PerceptionError::Provider(format!(
                "duckduckgo HTTP {status}: {text}"
            )));
        }

        let html = resp
            .text()
            .await
            .map_err(|e| PerceptionError::Provider(format!("duckduckgo body read: {e}")))?;

        let mut results = Self::parse_html(&html);

        // Truncate to requested number.
        let max = request.num_results as usize;
        if results.len() > max {
            results.truncate(max);
        }

        let total = results.len() as u32;
        Ok(SearchResponse { results, total })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_HTML: &str = r#"
    <html><body>
    <div class="result">
      <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpage">Example Page</a>
      <a class="result__snippet">This is a snippet about examples.</a>
    </div>
    <div class="result">
      <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Frust-lang.org">Rust Programming</a>
      <a class="result__snippet">A systems programming language.</a>
    </div>
    </body></html>
    "#;

    #[test]
    fn test_parse_html() {
        let results = DuckDuckGoSearchProvider::parse_html(SAMPLE_HTML);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].title, "Example Page");
        assert_eq!(results[0].url, "https://example.com/page");
        assert_eq!(results[0].source, "duckduckgo");
        assert_eq!(results[1].title, "Rust Programming");
        assert_eq!(results[1].url, "https://rust-lang.org");
    }

    #[test]
    fn test_url_decode() {
        assert_eq!(
            url_decode("https%3A%2F%2Fexample.com"),
            "https://example.com"
        );
        assert_eq!(url_decode("hello+world"), "hello world");
    }

    #[test]
    fn test_time_range_param() {
        assert_eq!(
            DuckDuckGoSearchProvider::time_range_param(&TimeRange::PastDay),
            Some("d")
        );
        assert_eq!(
            DuckDuckGoSearchProvider::time_range_param(&TimeRange::PastWeek),
            Some("w")
        );
    }
}
