"""
EXA AI Client module for the VIPER CTI feed application.
Handles semantic search and content retrieval using the EXA AI API.
"""
import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional

from exa_py import Exa
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from src.utils.config import (
    get_exa_api_key,
    get_retry_max_attempts,
    get_retry_wait_max_seconds,
    get_retry_wait_min_seconds,
    get_retry_wait_multiplier,
)

# Initialize module logger
logger = logging.getLogger(__name__)

# Initialize EXA client
try:
    api_key = get_exa_api_key()
    exa = Exa(api_key=api_key)
    logger.info("EXA client initialized successfully")
except ValueError as e:
    # API key not configured - this is expected in some environments
    logger.warning(f"EXA API key not configured: {str(e)}")
    exa = None
except Exception as e:
    logger.error(f"Failed to initialize EXA client: {str(e)}")
    exa = None


@retry(
    retry=retry_if_exception_type((Exception,)),  # Retry on any exception
    wait=wait_exponential(
        multiplier=get_retry_wait_multiplier(),
        min=get_retry_wait_min_seconds(),
        max=get_retry_wait_max_seconds(),
    ),
    stop=stop_after_attempt(get_retry_max_attempts()),
    before_sleep=lambda retry_state: logger.warning(
        f"Retrying EXA API call after error: {retry_state.outcome.exception()}. "
        f"Attempt {retry_state.attempt_number}/{get_retry_max_attempts()}"
    ),
)
async def search_and_get_contents(
    query: str,
    num_results: int = 5,
    type: str = "neural",
    include_domains: Optional[List[str]] = None,
    exclude_domains: Optional[List[str]] = None,
    start_published_date: Optional[str] = None,
    end_published_date: Optional[str] = None,
) -> Optional[List[Dict]]:
    """
    Performs semantic search using EXA AI and retrieves full content for results.

    Args:
        query (str): The search query (e.g., 'technical analysis of CVE-2023-xxxx')
        num_results (int): Number of results to return (default: 5)
        type (str): Search type - 'neural' for semantic search, 'keyword' for traditional search
        include_domains (Optional[List[str]]): List of domains to include in search
        exclude_domains (Optional[List[str]]): List of domains to exclude from search
        start_published_date (Optional[str]): Only include content published after this date (YYYY-MM-DD)
        end_published_date (Optional[str]): Only include content published before this date (YYYY-MM-DD)

    Returns:
        Optional[List[Dict]]: List of dictionaries containing article data, or None if error/no results

    Each dictionary contains:
        - url: Article URL
        - title: Article title
        - published_date: Publication date (if available)
        - text: Full text content
        - highlights: Highlighted relevant sections
        - score: Relevance score
    """
    if not exa:
        logger.error("EXA client not initialized. Cannot perform search.")
        return None

    if not query or not query.strip():
        logger.error("Empty query provided to EXA search")
        return None

    try:
        logger.info(f"Performing EXA search for query: '{query}' with {num_results} results")

        # Prepare search parameters
        search_params = {
            "query": query.strip(),
            "num_results": num_results,
            "type": type,
            "text": True,  # Get full text content
            "highlights": True,  # Get highlights
        }

        # Add optional parameters if provided
        if include_domains:
            search_params["include_domains"] = include_domains
            logger.debug(f"Including domains: {include_domains}")

        if exclude_domains:
            search_params["exclude_domains"] = exclude_domains
            logger.debug(f"Excluding domains: {exclude_domains}")

        if start_published_date:
            search_params["start_published_date"] = start_published_date
            logger.debug(f"Start published date: {start_published_date}")

        if end_published_date:
            search_params["end_published_date"] = end_published_date
            logger.debug(f"End published date: {end_published_date}")

        # Perform the search with content retrieval
        # Note: Using search_and_contents method which combines search and content retrieval
        result = await asyncio.to_thread(exa.search_and_contents, **search_params)

        if not result or not hasattr(result, "results") or not result.results:
            logger.warning(f"No results found for query: '{query}'")
            return []

        # Process results into our standard format
        articles = []
        for item in result.results:
            try:
                article_data = {
                    "url": getattr(item, "url", ""),
                    "title": getattr(item, "title", ""),
                    "published_date": getattr(item, "published_date", None),
                    "text": getattr(item, "text", ""),
                    "highlights": getattr(item, "highlights", []),
                    "score": getattr(item, "score", 0.0),
                    "author": getattr(item, "author", None),
                }

                # Validate that we have essential data
                if not article_data["url"]:
                    logger.warning("Skipping result with missing URL")
                    continue

                # Ensure highlights is a list
                if not isinstance(article_data["highlights"], list):
                    article_data["highlights"] = []

                # Format published date if available
                if article_data["published_date"]:
                    try:
                        # Try to parse and reformat the date to ensure consistency
                        if isinstance(article_data["published_date"], str):
                            # Keep as-is if it's already a string
                            pass
                        else:
                            # Convert to string if it's a datetime object
                            article_data["published_date"] = str(article_data["published_date"])
                    except Exception as date_error:
                        logger.warning(f"Error processing published date: {date_error}")
                        article_data["published_date"] = None

                articles.append(article_data)
                logger.debug(f"Processed article: {article_data['title'][:50]}...")

            except Exception as item_error:
                logger.error(f"Error processing search result item: {str(item_error)}")
                continue

        logger.info(f"Successfully retrieved {len(articles)} articles for query: '{query}'")
        return articles

    except Exception as e:
        logger.error(f"Error performing EXA search for query '{query}': {str(e)}")
        # Re-raise to trigger retry mechanism
        raise


async def search_cve_related_content(cve_id: str, num_results: int = 3) -> Optional[List[Dict]]:
    """
    Searches for content specifically related to a CVE ID.

    Args:
        cve_id (str): The CVE ID to search for
        num_results (int): Number of results to return

    Returns:
        Optional[List[Dict]]: List of articles related to the CVE
    """
    if not cve_id:
        logger.error("No CVE ID provided for search")
        return None

    # Construct a targeted query for the CVE
    query = f"technical analysis and exploitation of {cve_id}"
    logger.info(f"Searching for CVE-related content: {cve_id}")

    return await search_and_get_contents(
        query=query,
        num_results=num_results,
        type="neural",  # Use semantic search for better CVE-related content
    )


async def search_general_threat_intelligence(queries: List[str], num_results: int = 3) -> List[Dict]:
    """
    Searches for general threat intelligence content using multiple queries.

    Args:
        queries (List[str]): List of threat intelligence queries to search for
        num_results (int): Number of results per query

    Returns:
        List[Dict]: Combined list of articles from all queries
    """
    if not queries:
        logger.warning("No queries provided for general threat intelligence search")
        return []

    all_articles = []

    for query in queries:
        try:
            logger.info(f"Searching general threat intelligence: '{query}'")
            articles = await search_and_get_contents(
                query=query,
                num_results=num_results,
                type="neural",
            )

            if articles:
                # Add query context to each article
                for article in articles:
                    article["source_query"] = query
                all_articles.extend(articles)
                logger.info(f"Found {len(articles)} articles for query: '{query}'")
            else:
                logger.warning(f"No articles found for query: '{query}'")

        except Exception as e:
            logger.error(f"Error searching for query '{query}': {str(e)}")
            continue

    # Remove duplicates based on URL
    unique_articles = []
    seen_urls = set()

    for article in all_articles:
        url = article.get("url", "")
        if url and url not in seen_urls:
            seen_urls.add(url)
            unique_articles.append(article)

    logger.info(f"Retrieved {len(unique_articles)} unique articles from {len(queries)} queries")
    return unique_articles


def validate_exa_client() -> bool:
    """
    Validates that the EXA client is properly initialized and can make requests.

    Returns:
        bool: True if client is valid, False otherwise
    """
    if not exa:
        logger.error("EXA client is not initialized")
        return False

    try:
        # Try a simple test search to validate the client
        test_result = exa.search("test", num_results=1)
        logger.info("EXA client validation successful")
        return True
    except Exception as e:
        logger.error(f"EXA client validation failed: {str(e)}")
        return False


async def generate_threat_intelligence_answer(
    query: str,
    include_full_text: bool = True,
) -> Optional[Dict]:
    """
    Generates an answer to a threat intelligence question using EXA's LLM capabilities.

    This method uses EXA's answer generation feature which provides synthesized responses
    with citations from reliable sources.

    Args:
        query (str): The threat intelligence question to answer
        include_full_text (bool): Whether to include full text of citations (default: True)

    Returns:
        Optional[Dict]: Dictionary containing answer and citations, or None if error

    Example return format:
        {
            "answer": "The capital of France is Paris.",
            "citations": [
                {
                    "url": "https://example.com",
                    "title": "Article title",
                    "published_date": "2023-01-01",
                    "author": "Author name",
                    "text": "Full article text..."  # Only if include_full_text=True
                }
            ]
        }
    """
    if not exa:
        logger.error("EXA client not initialized. Cannot generate answer.")
        return None

    if not query or not query.strip():
        logger.error("Empty query provided to EXA answer generation")
        return None

    try:
        logger.info(f"Generating threat intelligence answer for: '{query}'")

        # Use EXA's answer method
        result = await asyncio.to_thread(exa.answer, query=query.strip(), text=include_full_text)

        if not result:
            logger.warning(f"No answer generated for query: '{query}'")
            return None

        # Process the answer response
        answer_data = {"answer": getattr(result, "answer", ""), "citations": []}

        # Process citations
        if hasattr(result, "citations") and result.citations:
            for citation in result.citations:
                try:
                    citation_data = {
                        "url": getattr(citation, "url", ""),
                        "title": getattr(citation, "title", ""),
                        "published_date": getattr(citation, "published_date", None),
                        "author": getattr(citation, "author", None),
                    }

                    # Include full text if requested and available
                    if include_full_text:
                        citation_data["text"] = getattr(citation, "text", "")

                    answer_data["citations"].append(citation_data)

                except Exception as citation_error:
                    logger.error(f"Error processing citation: {str(citation_error)}")
                    continue

        logger.info(f"Generated answer with {len(answer_data['citations'])} citations")
        return answer_data

    except Exception as e:
        logger.error(f"Error generating answer for query '{query}': {str(e)}")
        # Re-raise to trigger retry mechanism
        raise


async def find_similar_threat_articles(
    reference_url: str,
    num_results: int = 5,
    include_content: bool = True,
    exclude_source_domain: bool = True,
) -> Optional[List[Dict]]:
    """
    Finds articles similar to a reference threat intelligence article.

    This is useful for finding related threats, similar attack techniques,
    or follow-up research on a specific security topic.

    Args:
        reference_url (str): URL of the reference article to find similar content for
        num_results (int): Number of similar articles to return (default: 5)
        include_content (bool): Whether to include full text and highlights (default: True)
        exclude_source_domain (bool): Whether to exclude results from same domain (default: True)

    Returns:
        Optional[List[Dict]]: List of similar articles, or None if error
    """
    if not exa:
        logger.error("EXA client not initialized. Cannot find similar articles.")
        return None

    if not reference_url or not reference_url.strip():
        logger.error("Empty reference URL provided to find similar articles")
        return None

    try:
        logger.info(f"Finding similar articles to: {reference_url}")

        # Prepare parameters for find_similar_and_contents
        params = {
            "url": reference_url.strip(),
            "num_results": num_results,
            "exclude_source_domain": exclude_source_domain,
        }

        if include_content:
            params["text"] = True
            params["highlights"] = True

        # Use find_similar_and_contents for comprehensive results
        result = await asyncio.to_thread(exa.find_similar_and_contents, **params)

        if not result or not hasattr(result, "results") or not result.results:
            logger.warning(f"No similar articles found for: {reference_url}")
            return []

        # Process results similar to search_and_get_contents
        articles = []
        for item in result.results:
            try:
                article_data = {
                    "url": getattr(item, "url", ""),
                    "title": getattr(item, "title", ""),
                    "published_date": getattr(item, "published_date", None),
                    "score": getattr(item, "score", 0.0),
                    "author": getattr(item, "author", None),
                }

                if include_content:
                    article_data["text"] = getattr(item, "text", "")
                    article_data["highlights"] = getattr(item, "highlights", [])

                    # Ensure highlights is a list
                    if not isinstance(article_data["highlights"], list):
                        article_data["highlights"] = []

                # Validate essential data
                if not article_data["url"]:
                    logger.warning("Skipping similar article with missing URL")
                    continue

                articles.append(article_data)
                logger.debug(f"Found similar article: {article_data['title'][:50]}...")

            except Exception as item_error:
                logger.error(f"Error processing similar article: {str(item_error)}")
                continue

        logger.info(f"Found {len(articles)} similar articles to reference URL")
        return articles

    except Exception as e:
        logger.error(f"Error finding similar articles for '{reference_url}': {str(e)}")
        # Re-raise to trigger retry mechanism
        raise


def is_exa_client_available() -> bool:
    """
    Checks if the EXA client was successfully initialized.

    Returns:
        bool: True if the client is initialized and ready, False otherwise.
    """
    return exa is not None
