//! `aafp search` — search the web via DuckDuckGo (free, no API key).

use colored::Colorize;

pub async fn run(query: &str, num_results: u32, json: bool) -> anyhow::Result<()> {
    // Load .env if present (not strictly needed for DDG, but good practice).
    let _ = dotenvy::dotenv();

    eprintln!("{} searching DuckDuckGo for \"{}\"...", "→".dimmed(), query);

    let provider = aafp_perception::DuckDuckGoSearchProvider::new()?;
    let req = aafp_perception::SearchRequest {
        query: query.to_string(),
        num_results,
        sources: Vec::new(),
        time_range: None,
        fetch_content: false,
    };

    use aafp_perception::SearchProvider;
    let resp = provider.search(&req).await?;

    if json {
        let json = serde_json::json!({
            "query": query,
            "total": resp.total,
            "results": resp.results.iter().map(|r| {
                serde_json::json!({
                    "title": r.title,
                    "url": r.url,
                    "snippet": r.snippet,
                    "score": r.score,
                    "source": r.source,
                })
            }).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        println!();
        println!("{}", "  Search Results  ".bold().on_cyan().black());
        println!();
        if resp.results.is_empty() {
            println!("  {}", "No results found.".dimmed());
        } else {
            for (i, result) in resp.results.iter().enumerate() {
                println!(
                    "  {} {}",
                    format!("[{}]", i + 1).dimmed(),
                    result.title.cyan().bold()
                );
                println!("  {} {}", "  →".dimmed(), result.url.yellow());
                if !result.snippet.is_empty() {
                    println!("  {} {}", "  ".dimmed(), result.snippet.dimmed());
                }
                println!();
            }
        }
        println!("  {} {} results", "✓".green(), resp.total);
    }

    Ok(())
}
