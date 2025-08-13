"""
LLM analyzer module for the VIPER CTI feed application.
Handles analyzing CVEs using different LLM providers (Gemini, Ollama).
"""
import asyncio
import json
import logging
import re
from typing import Optional, Tuple, Union

import aiohttp
import google.generativeai as genai
from openai import AsyncOpenAI
from google.api_core import exceptions as google_exceptions
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from src.utils.config import (
    get_gemini_api_key,
    get_gemini_model_name,
    get_llm_provider,
    get_local_llm_model_name,
    get_ollama_api_base_url,
    get_openai_api_key,
    get_openai_model_name,
    get_openai_base_url,
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


def _extract_cve_data_for_prompt(cve_data: dict) -> dict:
    """
    Extracts and formats CVE data for prompt generation.
    This function eliminates code duplication between different prompt creators.

    Args:
        cve_data (dict): CVE information dictionary

    Returns:
        dict: Formatted CVE data ready for prompt generation
    """
    # Extract basic CVE information
    cve_id = cve_data.get("cve_id", "Unknown CVE")
    cvss_score = cve_data.get("cvss_v3_score", "Not available")
    description = cve_data.get("description", "No description available")

    # Extract EPSS data if available
    epss_score = cve_data.get("epss_score")
    epss_percentile = cve_data.get("epss_percentile")
    epss_info = "Not available"
    if epss_score is not None and epss_percentile is not None:
        epss_info = f"{epss_score:.4f} (Exploitation probability in the {epss_percentile:.2%} percentile)"

    # Extract CISA KEV data if available
    is_in_kev = cve_data.get("is_in_kev", False)
    kev_date_added = cve_data.get("kev_date_added")
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
    exploit_info = "No"
    if has_public_exploit and exploit_references:
        if isinstance(exploit_references, list):
            sources = set(exploit.get("source", "Unknown") for exploit in exploit_references)
            exploit_info = f"Yes, {len(exploit_references)} exploit(s) found on {', '.join(sorted(sources))}"
        else:
            exploit_info = "Yes, exploits available"

    return {
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "description": description,
        "epss_info": epss_info,
        "kev_info": kev_info,
        "ms_severity": ms_severity,
        "ms_product_family": ms_product_family,
        "ms_product_name": ms_product_name,
        "patch_tuesday_date": patch_tuesday_date,
        "exploit_info": exploit_info,
    }


def _format_cve_info_block(data: dict, include_ms_details: bool = True) -> str:
    """
    Creates a formatted CVE information block to eliminate duplication.

    Args:
        data (dict): Extracted CVE data from _extract_cve_data_for_prompt()
        include_ms_details (bool): Whether to include Microsoft-specific details

    Returns:
        str: Formatted CVE information block
    """
    info_lines = [
        f"CVE ID: {data['cve_id']}",
        f"CVSS v3 Score: {data['cvss_score']}",
        f"EPSS Score: {data['epss_info']}",
        f"In CISA KEV (Known Exploited Vulnerabilities Catalog): {data['kev_info']}",
        f"Microsoft Severity: {data['ms_severity']}",
        f"Affected Microsoft Product Family: {data['ms_product_family']}",
    ]

    if include_ms_details:
        info_lines.extend(
            [
                f"Specific Microsoft Product: {data['ms_product_name']}",
                f"Microsoft Patch Tuesday Date: {data['patch_tuesday_date']}",
            ]
        )

    info_lines.extend(
        [
            f"Public Exploits Available: {data['exploit_info']}",
            f"Description: {data['description']}",
        ]
    )

    return "\n".join(info_lines)


@retry(
    retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError)),
    wait=wait_exponential(
        multiplier=get_retry_wait_multiplier(),
        min=get_retry_wait_min_seconds(),
        max=get_retry_wait_max_seconds(),
    ),
    stop=stop_after_attempt(get_retry_max_attempts()),
    before_sleep=lambda retry_state: logger.warning(
        f"Retrying Ollama API call after error: {retry_state.outcome.exception()}. "
        f"Attempt {retry_state.attempt_number}/{get_retry_max_attempts()}"
    ),
)
async def _analyze_with_ollama_async(prompt: str, cve_id: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Analyzes a CVE using the Ollama API.

    Args:
        prompt (str): The prompt to send to Ollama
        cve_id (str): The CVE ID for logging purposes

    Returns:
        tuple: (priority, justification, raw_response) where priority is one of 'HIGH', 'MEDIUM', 'LOW', or 'ERROR_ANALYZING'.
    """
    try:
        base_url = get_ollama_api_base_url()
        model_name = get_local_llm_model_name()
        url = f"{base_url}/api/generate"

        # Enhanced payload with additional Ollama API parameters
        payload = {
            "model": model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,  # Low temperature for consistent analysis
                "top_p": 0.9,  # Nucleus sampling
                "top_k": 40,  # Top-k sampling
                "num_predict": 500,  # Limit response length for structured output
                "stop": ["</analysis>", "\n\nNext:", "---"],  # Stop sequences
            },
        }

        logger.info(f"Sending CVE {cve_id} to Ollama ({model_name}) for analysis")

        timeout = aiohttp.ClientTimeout(total=120)  # 2 minute timeout
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, json=payload) as response:
                if response.status != 200:
                    error_text = await response.text()
                    error_msg = f"Ollama API returned status {response.status}: {error_text}"
                    logger.error(f"Ollama API error for CVE {cve_id}: {error_msg}")
                    return "ERROR_ANALYZING", None, error_msg

                result = await response.json()

                # Check for API-level errors
                if "error" in result:
                    error_msg = f"Ollama API error: {result['error']}"
                    logger.error(f"Ollama API error for CVE {cve_id}: {error_msg}")
                    return "ERROR_ANALYZING", None, error_msg

                raw_response = result.get("response", "").strip()

                if not raw_response:
                    error_msg = "Empty response from Ollama"
                    logger.error(f"Empty Ollama response for CVE {cve_id}")
                    return "ERROR_ANALYZING", None, error_msg

                # Log additional metrics if available
                if "eval_count" in result and "eval_duration" in result:
                    tokens = result.get("eval_count", 0)
                    duration_ns = result.get("eval_duration", 0)
                    tokens_per_sec = tokens / (duration_ns / 1e9) if duration_ns > 0 else 0
                    logger.info(f"Ollama analysis completed: {tokens} tokens, {tokens_per_sec:.1f} tokens/sec")

                # Parse the response to extract priority and justification
                priority, justification = _parse_ollama_response(raw_response)

                logger.info(f"Ollama assigned {priority} priority to {cve_id}")
                return priority, justification, raw_response

    except asyncio.TimeoutError:
        error_msg = "Timeout waiting for Ollama response"
        logger.error(f"Ollama timeout for CVE {cve_id}: {error_msg}")
        return "ERROR_ANALYZING", None, error_msg
    except aiohttp.ClientError as e:
        error_msg = f"HTTP client error: {str(e)}"
        logger.error(f"Ollama HTTP error for CVE {cve_id}: {error_msg}")
        return "ERROR_ANALYZING", None, error_msg
    except Exception as e:
        error_msg = f"Error communicating with Ollama: {str(e)}"
        logger.error(f"Ollama error for CVE {cve_id}: {error_msg}")
        return "ERROR_ANALYZING", None, error_msg


def _parse_ollama_response(response: str) -> Tuple[str, str]:
    """
    Parses the Ollama response to extract priority and justification.

    Args:
        response (str): The raw response from Ollama

    Returns:
        tuple: (priority, justification)
    """
    try:
        # Look for structured patterns first
        priority_match = re.search(r"PRIORITY:\s*(HIGH|MEDIUM|LOW)", response.upper())
        justification_match = re.search(r"JUSTIFICATION:\s*(.*?)(?:\n|$)", response, re.DOTALL)

        if priority_match:
            priority = priority_match.group(1)
            justification = justification_match.group(1).strip() if justification_match else "No justification provided"
            return priority, justification

        # Fallback: look for priority keywords in the response
        response_upper = response.upper()
        if "HIGH" in response_upper:
            priority = "HIGH"
        elif "MEDIUM" in response_upper:
            priority = "MEDIUM"
        elif "LOW" in response_upper:
            priority = "LOW"
        else:
            logger.warning(f"Could not parse priority from Ollama response: {response[:100]}...")
            priority = "MEDIUM"  # Default to medium if unclear

        # Use the full response as justification if no structured format found
        justification = response.strip()

        return priority, justification

    except Exception as e:
        logger.error(f"Error parsing Ollama response: {str(e)}")
        return "ERROR_ANALYZING", f"Parse error: {str(e)}"


def _create_ollama_prompt(cve_data: dict) -> str:
    """
    Creates a prompt optimized for local LLM models like Ollama.

    Args:
        cve_data (dict): CVE information dictionary

    Returns:
        str: Formatted prompt for Ollama
    """
    # Extract CVE data using shared function
    data = _extract_cve_data_for_prompt(cve_data)

    # Format CVE information block (excluding MS details for cleaner Ollama prompt)
    cve_info = _format_cve_info_block(data, include_ms_details=False)

    # Create a prompt optimized for local models with clear structure
    prompt = f"""<analysis>
You are a cybersecurity expert analyzing vulnerability data. Analyze the following CVE and determine its priority for a typical mid-to-large organization.

CVE Information:
{cve_info}

Based on this information, consider:
1. Impact severity (RCE, data breach, DoS)
2. Software ubiquity and affected systems
3. Active exploitation indicators
4. Available exploits and ease of exploitation

Respond EXACTLY in this format:
PRIORITY: [HIGH/MEDIUM/LOW]
JUSTIFICATION: [Brief explanation of your reasoning]
</analysis>"""

    return prompt


def _create_openai_prompt(cve_data: dict) -> str:
    """
    Creates a prompt optimized for OpenAI models. Reuse Ollama prompt format for
    consistent PRIORITY/JUSTIFICATION parsing.

    Args:
        cve_data (dict): CVE information dictionary

    Returns:
        str: Formatted prompt for OpenAI
    """
    return _create_ollama_prompt(cve_data)


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
    Helper function to generate content with retry logic for Gemini.

    Args:
        model: The Gemini model instance
        prompt: The prompt to send to Gemini
        cve_id: The CVE ID (for logging purposes)

    Returns:
        The response from Gemini
    """
    logger.info(f"Sending CVE {cve_id} to Gemini for analysis")
    return await model.generate_content_async(prompt)


def _create_gemini_prompt(cve_data: dict) -> str:
    """
    Creates a prompt optimized for Gemini API.

    Args:
        cve_data (dict): CVE information dictionary

    Returns:
        str: Formatted prompt for Gemini
    """
    # Extract CVE data using shared function
    data = _extract_cve_data_for_prompt(cve_data)

    # Format CVE information block (including MS details for comprehensive Gemini analysis)
    cve_info = _format_cve_info_block(data, include_ms_details=True)

    # Construct the prompt
    prompt = f"""
Analyze the following CVE information to determine its priority for a typical mid-to-large sized organization. Consider potential impact (RCE, data breach, DoS), ubiquity of the affected software, and reported exploitation (if any can be inferred).
Respond with only ONE of the following words: HIGH, MEDIUM, or LOW.

{cve_info}

Priority:
"""

    return prompt


@retry(
    retry=retry_if_exception_type(Exception),
    wait=wait_exponential(
        multiplier=get_retry_wait_multiplier(),
        min=get_retry_wait_min_seconds(),
        max=get_retry_wait_max_seconds(),
    ),
    stop=stop_after_attempt(get_retry_max_attempts()),
)
async def _analyze_with_openai_async(cve_data) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Analyzes a CVE using the OpenAI Chat Completions API.

    Returns:
        tuple: (priority, justification, raw_response)
    """
    client = AsyncOpenAI(api_key=get_openai_api_key(), base_url=get_openai_base_url())
    model = get_openai_model_name()
    prompt = _create_openai_prompt(cve_data)
    cve_id = cve_data.get("cve_id", "Unknown CVE")

    logger.info(f"Sending CVE {cve_id} to OpenAI ({model}) for analysis")
    response = await client.chat.completions.create(
        model=model,
        temperature=0.1,
        messages=[{"role": "user", "content": prompt}],
    )

    raw_response = (response.choices[0].message.content or "").strip()
    if not raw_response:
        error_msg = "Empty response from OpenAI"
        logger.error(error_msg)
        return "ERROR_ANALYZING", None, error_msg

    priority, justification = _parse_ollama_response(raw_response)
    logger.info(f"OpenAI assigned {priority} priority to {cve_id}")
    return priority, justification, raw_response


async def analyze_cve_async(cve_data):
    """
    Asynchronously analyzes a CVE using the configured LLM provider to determine its priority.

    Args:
        cve_data (dict): A dictionary containing CVE data (cve_id, description, cvss_v3_score,
                         and optionally epss_score, epss_percentile, is_in_kev, kev_date_added,
                         microsoft_severity, microsoft_product_family, microsoft_product_name,
                         has_public_exploit, exploit_references).

    Returns:
        tuple: (priority, justification, raw_response) where priority is one of 'HIGH', 'MEDIUM', 'LOW', or 'ERROR_ANALYZING'.
    """
    cve_id = cve_data.get("cve_id", "Unknown CVE")
    llm_provider = get_llm_provider()

    try:
        if llm_provider == "gemini":
            return await _analyze_with_gemini_async(cve_data)
        elif llm_provider == "ollama":
            prompt = _create_ollama_prompt(cve_data)
            return await _analyze_with_ollama_async(prompt, cve_id)
        elif llm_provider == "openai":
            return await _analyze_with_openai_async(cve_data)
        else:
            error_msg = f"Unknown LLM provider: {llm_provider}"
            logger.error(error_msg)
            return "ERROR_ANALYZING", None, error_msg

    except Exception as e:
        error_msg = f"Error analyzing CVE with {llm_provider}: {str(e)}"
        logger.error(error_msg)
        return "ERROR_ANALYZING", None, error_msg


async def _analyze_with_gemini_async(cve_data):
    """
    Asynchronously analyzes a CVE using the Gemini API to determine its priority.

    Args:
        cve_data (dict): A dictionary containing CVE data

    Returns:
        tuple: (priority, justification, raw_response) where priority is one of 'HIGH', 'MEDIUM', 'LOW', or 'ERROR_ANALYZING'.
    """
    try:
        # Configure Gemini API (this is synchronous and should be done before async operations)
        configure_gemini()

        # Initialize Gemini model
        model = genai.GenerativeModel(get_gemini_model_name())

        cve_id = cve_data.get("cve_id", "Unknown CVE")
        prompt = _create_gemini_prompt(cve_data)

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
        return priority, raw_response, raw_response

    except Exception as e:
        logger.error(f"Error asynchronously analyzing CVE with Gemini: {str(e)}")
        return "ERROR_ANALYZING", None, f"Error: {str(e)}"


def analyze_cve_with_gemini(cve_data):
    """
    Analyzes a CVE using the Gemini API to determine its priority.
    DEPRECATED: Use analyze_cve_async() instead for better LLM provider support.

    Args:
        cve_data (dict): A dictionary containing CVE data

    Returns:
        tuple: (priority, raw_response) where priority is one of 'HIGH', 'MEDIUM', 'LOW', or 'ERROR_ANALYZING'.
    """
    logger.warning("analyze_cve_with_gemini() is deprecated. Use analyze_cve_async() instead.")
    try:
        # Run the async version synchronously for backward compatibility
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If we're already in an async context, create a new event loop in a thread
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, analyze_cve_async(cve_data))
                priority, justification, raw_response = future.result()
        else:
            priority, justification, raw_response = asyncio.run(analyze_cve_async(cve_data))

        # Return in the old format for backward compatibility
        return priority, raw_response

    except Exception as e:
        logger.error(f"Error in backward compatibility wrapper: {str(e)}")
        return "ERROR_ANALYZING", f"Error: {str(e)}"


# Backward compatibility alias
analyze_cve_with_gemini_async = analyze_cve_async


async def check_ollama_availability() -> Tuple[bool, str, list]:
    """
    Checks if Ollama is available and returns the list of installed models.

    Returns:
        tuple: (is_available, status_message, models_list)
    """
    try:
        base_url = get_ollama_api_base_url()

        # Check if Ollama is running
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Test basic connectivity
            async with session.get(f"{base_url}/api/tags") as response:
                if response.status != 200:
                    return False, f"Ollama API returned status {response.status}", []

                result = await response.json()
                models = result.get("models", [])
                model_names = [model.get("name", "Unknown") for model in models]

                if not models:
                    return True, "Ollama is running but no models are installed", []

                return True, f"Ollama is running with {len(models)} model(s)", model_names

    except asyncio.TimeoutError:
        return False, "Timeout connecting to Ollama - check if it's running", []
    except aiohttp.ClientError as e:
        return False, f"Cannot connect to Ollama: {str(e)}", []
    except Exception as e:
        return False, f"Error checking Ollama: {str(e)}", []


def _clean_json_response(response: str) -> str:
    """
    Attempts to clean and extract valid JSON from LLM response.

    Args:
        response (str): The raw response from the LLM

    Returns:
        str: Cleaned JSON string or empty string if not found
    """
    try:
        # Remove markdown code blocks
        if "```json" in response:
            start = response.find("```json") + 7
            end = response.find("```", start)
            if end != -1:
                response = response[start:end].strip()
        elif "```" in response:
            start = response.find("```") + 3
            end = response.find("```", start)
            if end != -1:
                response = response[start:end].strip()

        # Try to find JSON object boundaries
        start_idx = response.find("{")
        end_idx = response.rfind("}")

        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            response = response[start_idx : end_idx + 1]

        return response.strip()
    except Exception as e:
        logger.warning(f"Error cleaning JSON response: {str(e)}")
        return ""


def _create_article_analysis_prompt(article_text: str) -> str:
    """
    Creates a prompt for analyzing cybersecurity article content.

    Args:
        article_text (str): The article text to analyze

    Returns:
        str: Formatted prompt for article analysis
    """
    # Truncate article text if too long (limit to ~8000 chars to leave room for prompt)
    if len(article_text) > 8000:
        article_text = article_text[:8000] + "... [TRUNCATED]"

    prompt = f"""Analyze the following cybersecurity article. Extract key threat intelligence information and provide the output ONLY in a valid JSON format with the specified keys.

Article Text:
---
{article_text}
---

JSON Output Schema:
{{
  "summary": "A concise, 2-3 sentence summary of the article's main findings, focusing on the threat, vulnerability, or campaign.",
  "extracted_iocs": [
    {{ "value": "1.2.3.4", "type": "ipv4" }},
    {{ "value": "badsite.com", "type": "domain" }},
    {{ "value": "a1b2c3d4...", "type": "sha256" }}
  ],
  "mentioned_actors": ["APT Name", "Cybercrime Group"],
  "mentioned_malware": ["MalwareFamily1", "Backdoor.Name"],
  "identified_ttps": ["T1566.001", "T1059.003"],
  "target_sectors": ["Financial", "Government"]
}}

Provide ONLY the JSON response, no additional text or explanations."""

    return prompt


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
        f"Retrying article analysis API call after error: {retry_state.outcome.exception()}. "
        f"Attempt {retry_state.attempt_number}/{get_retry_max_attempts()}"
    ),
)
async def _analyze_article_with_gemini_async(prompt: str) -> Optional[dict]:
    """
    Analyzes article content using Gemini API.

    Args:
        prompt (str): The analysis prompt

    Returns:
        Optional[dict]: Parsed analysis results or None on error
    """
    try:
        # Configure Gemini API
        configure_gemini()

        # Initialize Gemini model
        model = genai.GenerativeModel(get_gemini_model_name())

        logger.info("Sending article to Gemini for analysis")
        response = await model.generate_content_async(prompt)

        # Get the response text
        raw_response = response.text.strip()

        # Clean and parse JSON response
        cleaned_response = _clean_json_response(raw_response)

        if not cleaned_response:
            logger.error("Failed to extract JSON from Gemini response")
            return None

        try:
            result = json.loads(cleaned_response)
            logger.info("Successfully analyzed article with Gemini")
            return result
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON from Gemini response: {str(e)}")
            logger.debug(f"Raw response: {raw_response[:200]}...")
            return None

    except Exception as e:
        logger.error(f"Error analyzing article with Gemini: {str(e)}")
        return None


@retry(
    retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError)),
    wait=wait_exponential(
        multiplier=get_retry_wait_multiplier(),
        min=get_retry_wait_min_seconds(),
        max=get_retry_wait_max_seconds(),
    ),
    stop=stop_after_attempt(get_retry_max_attempts()),
    before_sleep=lambda retry_state: logger.warning(
        f"Retrying article analysis with Ollama after error: {retry_state.outcome.exception()}. "
        f"Attempt {retry_state.attempt_number}/{get_retry_max_attempts()}"
    ),
)
async def _analyze_article_with_ollama_async(prompt: str) -> Optional[dict]:
    """
    Analyzes article content using Ollama API.

    Args:
        prompt (str): The analysis prompt

    Returns:
        Optional[dict]: Parsed analysis results or None on error
    """
    try:
        base_url = get_ollama_api_base_url()
        model_name = get_local_llm_model_name()
        url = f"{base_url}/api/generate"

        # Payload optimized for structured JSON output
        payload = {
            "model": model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,  # Low temperature for consistent structured output
                "top_p": 0.9,
                "num_predict": 1000,  # Allow longer response for JSON
                "stop": ["\n\n---", "Human:", "Assistant:"],
            },
        }

        logger.info(f"Sending article to Ollama ({model_name}) for analysis")

        timeout = aiohttp.ClientTimeout(total=180)  # 3 minute timeout for article analysis
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, json=payload) as response:
                if response.status != 200:
                    error_text = await response.text()
                    logger.error(f"Ollama API returned status {response.status}: {error_text}")
                    return None

                result = await response.json()

                # Check for API-level errors
                if "error" in result:
                    logger.error(f"Ollama API error: {result['error']}")
                    return None

                raw_response = result.get("response", "").strip()

                if not raw_response:
                    logger.error("Empty response from Ollama")
                    return None

                # Clean and parse JSON response
                cleaned_response = _clean_json_response(raw_response)

                if not cleaned_response:
                    logger.error("Failed to extract JSON from Ollama response")
                    return None

                try:
                    result = json.loads(cleaned_response)
                    logger.info("Successfully analyzed article with Ollama")
                    return result
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse JSON from Ollama response: {str(e)}")
                    logger.debug(f"Raw response: {raw_response[:200]}...")
                    return None

    except asyncio.TimeoutError:
        logger.error("Timeout waiting for Ollama article analysis response")
        return None
    except aiohttp.ClientError as e:
        logger.error(f"HTTP client error during Ollama article analysis: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Error analyzing article with Ollama: {str(e)}")
        return None


@retry(
    retry=retry_if_exception_type(Exception),
    wait=wait_exponential(
        multiplier=get_retry_wait_multiplier(),
        min=get_retry_wait_min_seconds(),
        max=get_retry_wait_max_seconds(),
    ),
    stop=stop_after_attempt(get_retry_max_attempts()),
)
async def _analyze_article_with_openai_async(prompt: str) -> Optional[dict]:
    """
    Analyzes article content using OpenAI API and returns structured JSON.
    """
    client = AsyncOpenAI(api_key=get_openai_api_key(), base_url=get_openai_base_url())
    model = get_openai_model_name()
    logger.info("Sending article to OpenAI for analysis")
    response = await client.chat.completions.create(
        model=model,
        temperature=0.1,
        messages=[{"role": "user", "content": prompt}],
    )
    raw_response = (response.choices[0].message.content or "").strip()
    cleaned_response = _clean_json_response(raw_response)
    if not cleaned_response:
        logger.error("Failed to extract JSON from OpenAI response")
        return None
    try:
        return json.loads(cleaned_response)
    except json.JSONDecodeError:
        logger.error("Failed to parse JSON from OpenAI response")
        return None

async def analyze_article_content_async(article_text: str) -> Optional[dict]:
    """
    Analyzes cybersecurity article content to extract threat intelligence information.

    Acts as a senior cyber threat analyst to extract structured information including:
    - Summary of main findings
    - IOCs (indicators of compromise)
    - Threat actors mentioned
    - Malware families
    - TTPs (tactics, techniques, procedures)
    - Target sectors

    Args:
        article_text (str): The article content to analyze

    Returns:
        Optional[dict]: Dictionary containing analysis results with keys:
            - summary: Brief summary of the article
            - extracted_iocs: List of IOCs with value and type
            - mentioned_actors: List of threat actors
            - mentioned_malware: List of malware families
            - identified_ttps: List of MITRE ATT&CK TTPs
            - target_sectors: List of targeted sectors
        Returns None if analysis fails.
    """
    if not article_text or not article_text.strip():
        logger.warning("Empty or invalid article text provided for analysis")
        return None

    try:
        llm_provider = get_llm_provider()
        prompt = _create_article_analysis_prompt(article_text)

        logger.info(f"Starting article analysis with {llm_provider} provider")

        if llm_provider == "gemini":
            result = await _analyze_article_with_gemini_async(prompt)
        elif llm_provider == "ollama":
            result = await _analyze_article_with_ollama_async(prompt)
        elif llm_provider == "openai":
            result = await _analyze_article_with_openai_async(prompt)
        else:
            logger.error(f"Unknown LLM provider: {llm_provider}")
            return None

        if result is None:
            logger.error("Article analysis failed - no valid result returned")
            return None

        # Validate that the result has the expected structure
        required_keys = [
            "summary",
            "extracted_iocs",
            "mentioned_actors",
            "mentioned_malware",
            "identified_ttps",
            "target_sectors",
        ]

        for key in required_keys:
            if key not in result:
                logger.warning(f"Missing key '{key}' in analysis result, adding empty value")
                if key == "summary":
                    result[key] = "No summary available"
                else:
                    result[key] = []

        logger.info("Article analysis completed successfully")
        return result

    except Exception as e:
        logger.error(f"Error in article content analysis: {str(e)}")
        return None
