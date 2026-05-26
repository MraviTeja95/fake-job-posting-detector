import functools

import requests
from bs4 import BeautifulSoup


@functools.lru_cache(maxsize=128)
def scrape_url_text(url):
    """Scrape and extract text from a URL, with caching to improve performance."""
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/91.0.4472.124 Safari/537.36"
        )
    }
    response = requests.get(url, headers=headers, timeout=10)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "html.parser")

    for element in soup(["script", "style", "nav", "footer", "header"]):
        element.extract()

    text = soup.get_text(separator=" ")
    block_phrases = [
        "security check",
        "captcha",
        "bot detection",
        "please sign in",
        "log in to view",
        "access denied",
        "verify you are human",
    ]
    if any(phrase in text.lower() for phrase in block_phrases):
        raise ValueError(
            "The website blocked our scanner (Security Check). Please paste the job description text manually for a more accurate analysis."
        )

    lines = (line.strip() for line in text.splitlines())
    chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
    return "\n".join(chunk for chunk in chunks if chunk)
