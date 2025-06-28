"""
Gemini analyzer module for the VIPER CTI feed application.
Handles analyzing CVEs using Google's Gemini API.
"""
import asyncio
import logging

import google.generativeai as genai
from google.api_core import exceptions as google_exceptions
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from src.utils.config import (
    get_gemini_api_key,
    get_gemini_model_name,
    get_retry_max_attempts,
    get_retry_wait_max_seconds,
    get_retry_wait_min_seconds,
    get_retry_wait_multiplier,
)

# Initialize module logger
logger = logging.getLogger(__name__)


def configure_gemini():
    """
    Configures the Gemini API with the API key.

    Raises:
        ValueError: If the API key cannot be retrieved.
    """
    try:
        api_key = get_gemini_api_key()
        genai.configure(api_key=api_key)
        logger.info("Gemini API configured successfully")
    except Exception as e:
        logger.error(f"Failed to configure Gemini API: {str(e)}")
        raise


def analyze_cve_with_gemini(cve_data):
    """
    Analyzes a CVE using the Gemini API to determine its priority.

    Args:
        cve_data (dict): A dictionary containing CVE data (cve_id, description, cvss_v3_score,
                         and optionally epss_score, epss_percentile, is_in_kev, kev_date_added).

    Returns:
        tuple: (priority, raw_response) where priority is one of 'HIGH', 'MEDIUM', 'LOW', or 'ERROR_ANALYZING'.
    """
    try:
        # Configure Gemini API
        configure_gemini()

        # Initialize Gemini model
        model = genai.GenerativeModel(get_gemini_model_name())

        # Extract CVE information
        cve_id = cve_data.get("cve_id", "Unknown CVE")
        cvss_score = cve_data.get("cvss_v3_score", "Not available")
        description = cve_data.get("description", "No description available")

        # Extract EPSS data if available
        epss_score = cve_data.get("epss_score")
        epss_percentile = cve_data.get("epss_percentile")

        # Format EPSS data for the prompt
        epss_info = "Not available"
        if epss_score is not None and epss_percentile is not None:
            epss_info = f"{epss_score:.4f} (Exploitation probability in the {epss_percentile:.2%} percentile)"

        # Extract CISA KEV data if available
        is_in_kev = cve_data.get("is_in_kev", False)
        kev_date_added = cve_data.get("kev_date_added")

        # Format KEV data for the prompt
        kev_info = "No"
        if is_in_kev:
            kev_info = f"Yes, added on {kev_date_added}" if kev_date_added else "Yes"

        # Construct the prompt
        prompt = f"""
Analyze the following CVE information to determine its priority for a typical mid-to-large sized organization. Consider potential impact (RCE, data breach, DoS), ubiquity of the affected software, and reported exploitation (if any can be inferred).
Respond with only ONE of the following words: HIGH, MEDIUM, or LOW.

CVE ID: {cve_id}
CVSS v3 Score: {cvss_score}
EPSS Score: {epss_info}
In CISA KEV (Known Exploited Vulnerabilities Catalog): {kev_info}
Description: {description}

Priority:
"""

        logger.info(f"Sending CVE {cve_id} to Gemini for analysis")

        # Send the prompt to Gemini
        response = model.generate_content(prompt)

        # Get the response text
        raw_response = response.text.strip()

        # Extract the priority (HIGH, MEDIUM, LOW)
        priority = raw_response.upper()

        # Validate and normalize the response
        if "HIGH" in priority:
            priority = "HIGH"
        elif "MEDIUM" in priority:
            priority = "MEDIUM"
        elif "LOW" in priority:
            priority = "LOW"
        else:
            logger.warning(f"Unexpected priority format from Gemini: {priority}")
            priority = "ERROR_ANALYZING"

        logger.info(f"Gemini assigned {priority} priority to {cve_id}")
        return priority, raw_response

    except Exception as e:
        logger.error(f"Error analyzing CVE with Gemini: {str(e)}")
        return "ERROR_ANALYZING", f"Error: {str(e)}"


@retry(
    retry=retry_if_exception_type(
        (
            google_exceptions.ServiceUnavailable,
            google_exceptions.DeadlineExceeded,
            google_exceptions.ResourceExhausted,
            google_exceptions.TooManyRequests,
        )
    ),
    wait=wait_exponential(
        multiplier=get_retry_wait_multiplier(),
        min=get_retry_wait_min_seconds(),
        max=get_retry_wait_max_seconds(),
    ),
    stop=stop_after_attempt(get_retry_max_attempts()),
    before_sleep=lambda retry_state: logger.warning(
        f"Retrying Gemini API call after error: {retry_state.outcome.exception()}. "
        f"Attempt {retry_state.attempt_number}/{get_retry_max_attempts()}"
    ),
)
async def _generate_content_with_retry(model, prompt, cve_id):
    """
    Helper function to generate content with retry logic.

    Args:
        model: The Gemini model instance
        prompt: The prompt to send to Gemini
        cve_id: The CVE ID (for logging purposes)

    Returns:
        The response from Gemini
    """
    logger.info(f"Sending CVE {cve_id} to Gemini for analysis")
    return await model.generate_content_async(prompt)


async def analyze_cve_with_gemini_async(cve_data):
    """
    Asynchronously analyzes a CVE using the Gemini API to determine its priority.

    Args:
        cve_data (dict): A dictionary containing CVE data (cve_id, description, cvss_v3_score,
                         and optionally epss_score, epss_percentile, is_in_kev, kev_date_added,
                         microsoft_severity, microsoft_product_family, microsoft_product_name,
                         has_public_exploit, exploit_references).

    Returns:
        tuple: (priority, raw_response) where priority is one of 'HIGH', 'MEDIUM', 'LOW', or 'ERROR_ANALYZING'.
    """
    try:
        # Configure Gemini API (this is synchronous and should be done before async operations)
        configure_gemini()

        # Initialize Gemini model
        model = genai.GenerativeModel(get_gemini_model_name())

        # Extract CVE information
        cve_id = cve_data.get("cve_id", "Unknown CVE")
        cvss_score = cve_data.get("cvss_v3_score", "Not available")
        description = cve_data.get("description", "No description available")

        # Extract EPSS data if available
        epss_score = cve_data.get("epss_score")
        epss_percentile = cve_data.get("epss_percentile")

        # Format EPSS data for the prompt
        epss_info = "Not available"
        if epss_score is not None and epss_percentile is not None:
            epss_info = f"{epss_score:.4f} (Exploitation probability in the {epss_percentile:.2%} percentile)"

        # Extract CISA KEV data if available
        is_in_kev = cve_data.get("is_in_kev", False)
        kev_date_added = cve_data.get("kev_date_added")

        # Format KEV data for the prompt
        kev_info = "No"
        if is_in_kev:
            kev_info = f"Yes, added on {kev_date_added}" if kev_date_added else "Yes"

        # Extract Microsoft-specific information if available
        ms_severity = cve_data.get("microsoft_severity", "N/A")
        ms_product_family = cve_data.get("microsoft_product_family", "N/A")
        ms_product_name = cve_data.get("microsoft_product_name", "N/A")
        patch_tuesday_date = cve_data.get("patch_tuesday_date", "N/A")

        # Extract exploit information if available
        has_public_exploit = cve_data.get("has_public_exploit", False)
        exploit_references = cve_data.get("exploit_references", [])

        # Format exploit information for the prompt
        exploit_info = "No"
        if has_public_exploit and exploit_references:
            if isinstance(exploit_references, list):
                sources = set(exploit.get("source", "Unknown") for exploit in exploit_references)
                exploit_info = f"Yes, {len(exploit_references)} exploit(s) found on {', '.join(sources)}"
            else:
                exploit_info = "Yes, exploits available"

        # Construct the prompt
        prompt = f"""
Analyze the following CVE information to determine its priority for a typical mid-to-large sized organization. Consider potential impact (RCE, data breach, DoS), ubiquity of the affected software, and reported exploitation (if any can be inferred).
Respond with only ONE of the following words: HIGH, MEDIUM, or LOW.

CVE ID: {cve_id}
CVSS v3 Score: {cvss_score}
EPSS Score: {epss_info}
In CISA KEV (Known Exploited Vulnerabilities Catalog): {kev_info}
Microsoft Severity: {ms_severity}
Affected Microsoft Product Family: {ms_product_family}
Specific Microsoft Product: {ms_product_name}
Microsoft Patch Tuesday Date: {patch_tuesday_date}
Public Exploits Available: {exploit_info}
Description: {description}

Priority:
"""

        logger.info(f"Sending CVE {cve_id} to Gemini for analysis")

        # Send the prompt to Gemini with retry logic
        response = await _generate_content_with_retry(model, prompt, cve_id)

        # Get the response text
        raw_response = response.text.strip()

        # Extract the priority (HIGH, MEDIUM, LOW)
        priority = raw_response.upper()

        # Validate and normalize the response
        if "HIGH" in priority:
            priority = "HIGH"
        elif "MEDIUM" in priority:
            priority = "MEDIUM"
        elif "LOW" in priority:
            priority = "LOW"
        else:
            logger.warning(f"Unexpected priority format from Gemini: {priority}")
            priority = "ERROR_ANALYZING"

        logger.info(f"Gemini assigned {priority} priority to {cve_id}")
        return priority, raw_response

    except Exception as e:
        logger.error(f"Error asynchronously analyzing CVE with Gemini: {str(e)}")
        return "ERROR_ANALYZING", f"Error: {str(e)}"
