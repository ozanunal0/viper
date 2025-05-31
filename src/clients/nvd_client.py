"""
NVD Client module for the VIPER CTI feed application.
Handles fetching CVE data from the National Vulnerability Database API.
"""
import logging
from datetime import datetime, timedelta, timezone

import requests
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from src.utils.config import (
    get_nvd_api_base_url,
    get_nvd_api_key,
    get_nvd_pagination_delay,
    get_nvd_results_per_page,
    get_retry_max_attempts,
    get_retry_wait_max_seconds,
    get_retry_wait_min_seconds,
    get_retry_wait_multiplier,
)

# Initialize module logger
logger = logging.getLogger(__name__)


@retry(
    retry=retry_if_exception_type(
        (
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.HTTPError,
        )
    ),
    wait=wait_exponential(
        multiplier=get_retry_wait_multiplier(),
        min=get_retry_wait_min_seconds(),
        max=get_retry_wait_max_seconds(),
    ),
    stop=stop_after_attempt(get_retry_max_attempts()),
    before_sleep=lambda retry_state: logger.warning(
        f"Retrying NVD API call after error: {retry_state.outcome.exception()}. "
        f"Attempt {retry_state.attempt_number}/{get_retry_max_attempts()}"
    ),
)
def _fetch_from_nvd_api(params):
    """
    Fetches data from the NVD API with retry logic.

    Args:
        params (dict): Parameters for the API request.

    Returns:
        dict: The JSON response from the API.

    Raises:
        requests.exceptions.HTTPError: If the HTTP request returns an unsuccessful status code.
    """
    # Set up headers with API key if available
    headers = {}
    api_key = get_nvd_api_key()
    if api_key:
        headers["apiKey"] = api_key

    response = requests.get(get_nvd_api_base_url(), params=params, headers=headers)

    # Raise for status to trigger retry on HTTP errors
    response.raise_for_status()

    return response.json()


def fetch_single_cve_details(cve_id: str) -> dict:
    """
    Fetches details for a single CVE from the NVD API.

    Args:
        cve_id (str): The CVE ID to fetch (e.g., "CVE-2023-12345").

    Returns:
        dict: A dictionary containing the CVE details, or None if not found or an error occurred.
    """
    if not cve_id or not cve_id.startswith("CVE-"):
        logger.error(f"Invalid CVE ID format: {cve_id}")
        return None

    try:
        logger.info(f"Fetching details for {cve_id} from NVD API")

        # Set up parameters for the API request - using cveId parameter for exact match
        params = {"cveId": cve_id}

        # Make the API request with retry logic
        data = _fetch_from_nvd_api(params)

        # Check if the CVE was found
        total_results = data.get("totalResults", 0)
        if total_results == 0:
            logger.warning(f"CVE {cve_id} not found in NVD database")
            return None

        # Process the CVE data
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            logger.warning(f"No vulnerability data returned for {cve_id}")
            return None

        # Extract the first (and should be only) CVE entry
        cve_entry = vulnerabilities[0]
        cve = cve_entry.get("cve", {})

        # Extract basic CVE information
        result = {"cve_id": cve.get("id")}

        # Extract description (English preferred)
        for desc_entry in cve.get("descriptions", []):
            if desc_entry.get("lang") == "en":
                result["description"] = desc_entry.get("value")
                break

        # Extract CVSS v3 score if available
        metrics = cve.get("metrics", {})
        # Check both cvssMetricV31 and cvssMetricV30
        cvss_v3_metrics_list = metrics.get("cvssMetricV31", [])
        if not cvss_v3_metrics_list:
            cvss_v3_metrics_list = metrics.get("cvssMetricV30", [])

        if cvss_v3_metrics_list:
            cvss_data = cvss_v3_metrics_list[0].get("cvssData", {})
            result["cvss_v3_score"] = cvss_data.get("baseScore")
            result["cvss_v3_vector"] = cvss_data.get("vectorString")
            result["cvss_v3_severity"] = cvss_data.get("baseSeverity")

        # Extract published and last modified dates
        result["published_date"] = cve.get("published")
        result["last_modified_date"] = cve.get("lastModified")

        # Extract references
        references = []
        for ref in cve.get("references", []):
            references.append({"url": ref.get("url"), "source": ref.get("source"), "tags": ref.get("tags", [])})

        if references:
            result["references"] = references

        # Extract CPE configuration data if available
        configurations = cve_entry.get("configurations", [])
        if configurations:
            cpe_entries = []

            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        cpe_data = {
                            "criteria": cpe_match.get("criteria"),
                            "vulnerable": cpe_match.get("vulnerable", True),
                        }

                        if cpe_data not in cpe_entries:
                            cpe_entries.append(cpe_data)

            if cpe_entries:
                result["cpe_entries"] = cpe_entries

        logger.info(f"Successfully fetched details for {cve_id}")
        return result

    except requests.exceptions.RequestException as e:
        logger.error(f"Request error fetching CVE {cve_id}: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error fetching CVE {cve_id}: {str(e)}")
        return None


def fetch_recent_cves(days_published_ago=None):
    """
    Fetches CVEs published within the specified number of days up to the current time.

    Args:
        days_published_ago (int, optional): Number of days to look back for CVEs.
            If None, uses the value from configuration.

    Returns:
        list: A list of dictionaries containing CVE data.
    """
    try:
        # Use configuration value if not specified
        if days_published_ago is None:
            from src.utils.config import get_nvd_days_published_ago

            days_published_ago = get_nvd_days_published_ago()

        # Calculate the start and end dates for the query
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days_published_ago)

        # Format dates as per NVD API requirements (YYYY-MM-DDTHH:MM:SSZ)
        start_date_str = start_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_date_str = end_date.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Parameters for the NVD API request
        params = {
            "pubStartDate": start_date_str,
            "pubEndDate": end_date_str,
            "resultsPerPage": get_nvd_results_per_page(),
        }

        logger.info(f"Fetching CVEs published between {start_date_str} and {end_date_str}")

        # Use the retry-enabled function to fetch data
        data = _fetch_from_nvd_api(params)

        # totalResults check (useful for pagination in the future)
        total_results = data.get("totalResults", 0)
        logger.info(f"NVD API reported {total_results} total matching CVEs for the period.")

        vulnerabilities = data.get("vulnerabilities", [])

        processed_cves = []
        for cve_entry in vulnerabilities:
            try:
                cve = cve_entry.get("cve", {})
                cve_id = cve.get("id")

                description = ""
                for desc_entry in cve.get("descriptions", []):
                    if desc_entry.get("lang") == "en":
                        description = desc_entry.get("value")
                        break

                cvss_v3_score = None
                metrics = cve.get("metrics", {})
                # Check both cvssMetricV31 and cvssMetricV30
                cvss_v3_metrics_list = metrics.get("cvssMetricV31", [])
                if not cvss_v3_metrics_list:
                    cvss_v3_metrics_list = metrics.get("cvssMetricV30", [])

                if cvss_v3_metrics_list:
                    cvss_v3_score = cvss_v3_metrics_list[0].get("cvssData", {}).get("baseScore")

                published_date = cve.get("published")

                if cve_id and description:
                    processed_cves.append(
                        {
                            "cve_id": cve_id,
                            "description": description,
                            "cvss_v3_score": cvss_v3_score,
                            "published_date": published_date,
                        }
                    )
                else:
                    logger.warning(f"Skipping CVE due to missing ID or description: {cve_entry}")
            except Exception as e:
                logger.error(
                    f"Error processing individual CVE entry {cve_entry.get('cve', {}).get('id', 'UNKNOWN_ID')}: {str(e)}"
                )
                continue

        logger.info(f"Successfully processed {len(processed_cves)} CVEs from the current API response page.")
        return processed_cves

    except requests.exceptions.RequestException as e:
        logger.critical(f"Critical error fetching data from NVD API after retries: {str(e)}")
        return []
    except Exception as e:
        logger.critical(f"Unexpected critical error in fetch_recent_cves: {str(e)}")
        return []
