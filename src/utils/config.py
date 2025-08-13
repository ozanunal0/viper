"""
Configuration module for the VIPER CTI feed application.
Handles loading API keys and other configuration settings from environment variables.
"""
import logging
import os

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Initialize module logger
logger = logging.getLogger(__name__)


def get_gemini_api_key():
    """
    Retrieves the Gemini API key from environment variables.

    Returns:
        str: The Gemini API key

    Raises:
        ValueError: If the API key is not found in environment variables
    """
    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        logger.error("GEMINI_API_KEY not found in environment variables")
        raise ValueError("GEMINI_API_KEY not found. Please add it to your .env file")

    return api_key


def get_gemini_model_name():
    """
    Retrieves the Gemini model name to use.
    Defaults to 'gemini-2.5-flash-preview-04-17' if not specified.

    Returns:
        str: The Gemini model name
    """
    model_name = os.getenv("GEMINI_MODEL_NAME", "")

    if not model_name:
        default = "gemini-2.5-flash-preview-04-17"
        logger.warning(f"GEMINI_MODEL_NAME not found in environment variables. Using default: {default}")
        return default

    return model_name


def get_gemini_concurrent_requests():
    """
    Retrieves the number of concurrent requests allowed for Gemini API.
    Defaults to 5 if not specified.

    Returns:
        int: Number of concurrent requests allowed
    """
    concurrent_requests = os.getenv("GEMINI_CONCURRENT_REQUESTS", "")

    try:
        value = int(concurrent_requests)
        if value <= 0:
            raise ValueError("Value must be positive")
        return value
    except (ValueError, TypeError):
        default = 5
        logger.warning(f"Invalid or missing GEMINI_CONCURRENT_REQUESTS value. Using default: {default}")
        return default


def get_nvd_api_base_url():
    """
    Retrieves the NVD API base URL.
    Defaults to 'https://services.nvd.nist.gov/rest/json/cves/2.0' if not specified.

    Returns:
        str: The NVD API base URL
    """
    base_url = os.getenv("NVD_API_BASE_URL", "")

    if not base_url:
        default = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        logger.warning(f"NVD_API_BASE_URL not found in environment variables. Using default: {default}")
        return default

    return base_url


def get_nvd_days_published_ago():
    """
    Retrieves the number of days to look back for CVEs.
    Defaults to 7 if not specified or invalid.

    Returns:
        int: Number of days to look back
    """
    days = os.getenv("NVD_DAYS_PUBLISHED_AGO", "")

    try:
        value = int(days)
        if value <= 0:
            raise ValueError("Value must be positive")
        return value
    except (ValueError, TypeError):
        default = 7
        logger.warning(f"Invalid or missing NVD_DAYS_PUBLISHED_AGO value. Using default: {default}")
        return default


def get_nvd_results_per_page():
    """
    Retrieves the number of results per page for NVD API requests.
    Defaults to 2000 if not specified or invalid.

    Returns:
        int: Number of results per page
    """
    results_per_page = os.getenv("NVD_RESULTS_PER_PAGE", "")

    try:
        value = int(results_per_page)
        if value <= 0:
            raise ValueError("Value must be positive")
        return value
    except (ValueError, TypeError):
        default = 2000
        logger.warning(f"Invalid or missing NVD_RESULTS_PER_PAGE value. Using default: {default}")
        return default


def get_nvd_pagination_delay():
    """
    Retrieves the delay in seconds between paginated NVD API requests.
    Defaults to 0.5 if not specified or invalid.

    Returns:
        float: Delay in seconds
    """
    delay = os.getenv("NVD_PAGINATION_DELAY_SECONDS", "")

    try:
        value = float(delay)
        if value < 0:
            raise ValueError("Value must be non-negative")
        return value
    except (ValueError, TypeError):
        default = 0.5
        logger.warning(f"Invalid or missing NVD_PAGINATION_DELAY_SECONDS value. Using default: {default}")
        return default


def get_db_file_name():
    """
    Retrieves the database file name.
    Defaults to 'viper.db' if not specified.
    Returns the absolute path to ensure consistent access.
    Creates necessary directories if they don't exist.

    Returns:
        str: The absolute path to the database file
    """
    db_file = os.getenv("DB_FILE_NAME", "")

    if not db_file:
        default = "viper.db"
        logger.warning(f"DB_FILE_NAME not found in environment variables. Using default: {default}")
        db_file = default

    # If an absolute path is provided, use it directly
    if os.path.isabs(db_file):
        # Ensure the directory exists
        db_dir = os.path.dirname(db_file)
        if db_dir and not os.path.exists(db_dir):
            try:
                logger.info(f"Creating directory for absolute DB path: {db_dir}")
                os.makedirs(db_dir, exist_ok=True)
            except Exception as e:
                logger.error(f"Failed to create directory for DB: {str(e)}")

        logger.info(f"Using database at absolute path: {db_file}")
        return db_file

    # For relative paths, use the data directory in the project root
    try:
        # Get the project root directory (two levels up from this script)
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

        # Create data directory in project root (not nested)
        data_dir = os.path.join(project_root, "data")
        if not os.path.exists(data_dir):
            logger.info(f"Creating data directory at: {data_dir}")
            os.makedirs(data_dir, exist_ok=True)

        # Return absolute path to the database file
        db_path = os.path.join(data_dir, os.path.basename(db_file))
        logger.info(f"Using database file in data directory: {db_path}")

        # Test if the directory is writable
        test_file = os.path.join(data_dir, ".writetest")
        try:
            with open(test_file, "w") as f:
                f.write("test")
            os.remove(test_file)
            logger.info(f"Data directory is writable: {data_dir}")
            return db_path
        except (IOError, PermissionError) as e:
            logger.warning(f"Data directory not writable: {str(e)}")
            # Fall through to use project root
    except Exception as e:
        logger.warning(f"Error setting up data directory: {str(e)}")
        # Fall through to use project root or absolute path

    # Use project root as fallback
    fallback_path = os.path.join(project_root, db_file)
    logger.info(f"Using database file in project root as fallback: {fallback_path}")
    return fallback_path


def get_log_file_name():
    """
    Retrieves the log file name.
    Defaults to 'viper.log' if not specified.

    Returns:
        str: The log file name
    """
    log_file = os.getenv("LOG_FILE_NAME", "")

    if not log_file:
        default = "viper.log"
        logger.warning(f"LOG_FILE_NAME not found in environment variables. Using default: {default}")
        return default

    return log_file


def get_log_level():
    """
    Retrieves the logging level.
    Defaults to 'INFO' if not specified or invalid.
    Valid levels are: 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'

    Returns:
        str: The log level name (uppercase)
    """
    log_level = os.getenv("LOG_LEVEL", "").upper()
    valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

    if log_level not in valid_levels:
        default = "INFO"
        logger.warning(f"Invalid or missing LOG_LEVEL. Must be one of {valid_levels}. Using default: {default}")
        return default

    return log_level


def get_retry_max_attempts():
    """
    Retrieves the maximum number of retry attempts.
    Defaults to 3 if not specified or invalid.

    Returns:
        int: Maximum number of retry attempts
    """
    max_attempts = os.getenv("RETRY_MAX_ATTEMPTS", "")

    try:
        value = int(max_attempts)
        if value <= 0:
            raise ValueError("Value must be positive")
        return value
    except (ValueError, TypeError):
        default = 3
        logger.warning(f"Invalid or missing RETRY_MAX_ATTEMPTS value. Using default: {default}")
        return default


def get_retry_wait_multiplier():
    """
    Retrieves the multiplier for wait time between retry attempts.
    Defaults to 1.0 if not specified or invalid.

    Returns:
        float: Wait time multiplier
    """
    multiplier = os.getenv("RETRY_WAIT_MULTIPLIER", "")

    try:
        value = float(multiplier)
        if value <= 0:
            raise ValueError("Value must be positive")
        return value
    except (ValueError, TypeError):
        default = 1.0
        logger.warning(f"Invalid or missing RETRY_WAIT_MULTIPLIER value. Using default: {default}")
        return default


def get_retry_wait_min_seconds():
    """
    Retrieves the minimum wait time in seconds between retry attempts.
    Defaults to 2.0 if not specified or invalid.

    Returns:
        float: Minimum wait time in seconds
    """
    min_seconds = os.getenv("RETRY_WAIT_MIN_SECONDS", "")

    try:
        value = float(min_seconds)
        if value < 0:
            raise ValueError("Value must be non-negative")
        return value
    except (ValueError, TypeError):
        default = 2.0
        logger.warning(f"Invalid or missing RETRY_WAIT_MIN_SECONDS value. Using default: {default}")
        return default


def get_retry_wait_max_seconds():
    """
    Retrieves the maximum wait time in seconds between retry attempts.
    Defaults to 30.0 if not specified or invalid.

    Returns:
        float: Maximum wait time in seconds
    """
    max_seconds = os.getenv("RETRY_WAIT_MAX_SECONDS", "")

    try:
        value = float(max_seconds)
        if value < 0:
            raise ValueError("Value must be non-negative")
        return value
    except (ValueError, TypeError):
        default = 30.0
        logger.warning(f"Invalid or missing RETRY_WAIT_MAX_SECONDS value. Using default: {default}")
        return default


# Risk Scoring System Configuration


def get_risk_score_weights():
    """
    Retrieves the weights for different factors in calculating the combined risk score.
    Defaults to 0.4 for Gemini, 0.3 for CVSS, 0.3 for EPSS, and 0.2 for Microsoft severity.
    Note that these should ideally sum to about 1.0, but they'll be normalized regardless.

    Returns:
        list: [gemini_weight, cvss_weight, epss_weight, ms_weight]
    """
    # Try to parse from environment variables if available
    try:
        gemini_weight = float(os.getenv("RISK_WEIGHT_GEMINI", "0.4"))
        cvss_weight = float(os.getenv("RISK_WEIGHT_CVSS", "0.3"))
        epss_weight = float(os.getenv("RISK_WEIGHT_EPSS", "0.3"))
        ms_weight = float(os.getenv("RISK_WEIGHT_MS_SEVERITY", "0.2"))

        # Validate weights are positive
        if gemini_weight < 0 or cvss_weight < 0 or epss_weight < 0 or ms_weight < 0:
            raise ValueError("All weights must be non-negative")

    except (ValueError, TypeError):
        logger.warning("Invalid risk score weights. Using defaults.")
        gemini_weight = 0.4
        cvss_weight = 0.3
        epss_weight = 0.3
        ms_weight = 0.2

    # Normalize weights to sum to 1.0
    total = gemini_weight + cvss_weight + epss_weight + ms_weight
    if total > 0:  # Avoid division by zero
        gemini_weight /= total
        cvss_weight /= total
        epss_weight /= total
        ms_weight /= total

    return [gemini_weight, cvss_weight, epss_weight, ms_weight]


def get_gemini_priority_factors():
    """
    Retrieves the numerical factors for each Gemini priority level.
    Defaults to HIGH=1.0, MEDIUM=0.6, LOW=0.3 if not specified or invalid.

    Returns:
        dict: A dictionary mapping priority levels to numerical factors
    """
    try:
        high = float(os.getenv("GEMINI_PRIORITY_FACTOR_HIGH", "1.0"))
        medium = float(os.getenv("GEMINI_PRIORITY_FACTOR_MEDIUM", "0.6"))
        low = float(os.getenv("GEMINI_PRIORITY_FACTOR_LOW", "0.3"))

        # Validate factors are between 0 and 1
        if not (0 <= high <= 1 and 0 <= medium <= 1 and 0 <= low <= 1):
            raise ValueError("Priority factors must be between 0 and 1")

        # Ensure HIGH > MEDIUM > LOW
        if not (high > medium > low):
            logger.warning("Priority factors should follow HIGH > MEDIUM > LOW")

        return {
            "HIGH": high,
            "MEDIUM": medium,
            "LOW": low,
            None: 0.1,  # Default factor for None/unknown priority
        }
    except (ValueError, TypeError):
        default = {"HIGH": 1.0, "MEDIUM": 0.6, "LOW": 0.3, None: 0.1}
        logger.warning(f"Invalid priority factors. Using defaults: {default}")
        return default


# Alert System Configuration


def get_alert_rules():
    """
    Retrieves the configuration for alert generation rules.
    Returns default rules if environment variables are not set or are invalid.

    Returns:
        dict: A dictionary containing alert thresholds and keywords
    """
    try:
        # Critical Exploitability Risk threshold
        critical_epss = float(os.getenv("ALERT_CRITICAL_EPSS_THRESHOLD", "0.05"))

        # Severe Impact & Likely Exploit thresholds
        severe_cvss = float(os.getenv("ALERT_SEVERE_CVSS_THRESHOLD", "9.0"))
        severe_epss = float(os.getenv("ALERT_SEVERE_EPSS_THRESHOLD", "0.02"))

        # High Impact Technique thresholds
        high_impact_epss = float(os.getenv("ALERT_HIGH_IMPACT_EPSS_THRESHOLD", "0.01"))

        # Keywords for High Impact Technique
        keywords_str = os.getenv(
            "ALERT_HIGH_IMPACT_KEYWORDS",
            "RCE,remote code execution,zero-day,zero day,privilege escalation,arbitrary code",
        )
        keywords = [kw.strip().lower() for kw in keywords_str.split(",")]

        return {
            "critical_epss": critical_epss,
            "severe_cvss": severe_cvss,
            "severe_epss": severe_epss,
            "high_impact_epss": high_impact_epss,
            "high_impact_keywords": keywords,
        }
    except (ValueError, TypeError, AttributeError):
        default = {
            "critical_epss": 0.05,
            "severe_cvss": 9.0,
            "severe_epss": 0.02,
            "high_impact_epss": 0.01,
            "high_impact_keywords": [
                "rce",
                "remote code execution",
                "zero-day",
                "zero day",
                "privilege escalation",
                "arbitrary code",
            ],
        }
        logger.warning(f"Invalid alert rules configuration. Using defaults")
        return default


def get_kev_boost_factor():
    """
    Retrieves the boost factor applied to risk scores for CVEs in the CISA KEV catalog.
    Defaults to 0.2 (20% boost) if not specified or invalid.

    Returns:
        float: KEV boost factor
    """
    boost_factor = os.getenv("KEV_BOOST_FACTOR", "")

    try:
        value = float(boost_factor)
        if value < 0:
            raise ValueError("Value must be non-negative")
        return value
    except (ValueError, TypeError):
        default = 0.2
        logger.warning(f"Invalid or missing KEV_BOOST_FACTOR value. Using default: {default}")
        return default


def get_msrc_api_key():
    """
    Retrieves the Microsoft Security Response Center (MSRC) API key from environment variables.
    Returns None if not found to allow unauthenticated API access with rate limiting.

    Returns:
        str or None: The MSRC API key if found, None otherwise
    """
    api_key = os.getenv("MSRC_API_KEY")

    if not api_key:
        logger.warning("MSRC_API_KEY not found in environment variables. Using unauthenticated access (rate limited)")
        return None

    return api_key


def get_microsoft_severity_factors():
    """
    Retrieves the factors to convert Microsoft severity ratings to numerical values.
    Defaults to reasonable values if not specified.

    Returns:
        dict: Mapping of severity ratings to numerical factors
    """
    # Try to parse from environment variables if available
    try:
        critical = float(os.getenv("MS_SEVERITY_CRITICAL_FACTOR", "1.0"))
        important = float(os.getenv("MS_SEVERITY_IMPORTANT_FACTOR", "0.7"))
        moderate = float(os.getenv("MS_SEVERITY_MODERATE_FACTOR", "0.4"))
        low = float(os.getenv("MS_SEVERITY_LOW_FACTOR", "0.1"))
    except (ValueError, TypeError):
        # Use defaults if parsing fails
        critical = 1.0
        important = 0.7
        moderate = 0.4
        low = 0.1
        logger.warning("Invalid Microsoft severity factors. Using defaults")

    return {
        "Critical": critical,
        "Important": important,
        "Moderate": moderate,
        "Low": low,
        None: 0.0,
    }


def get_github_token():
    """
    Retrieves the GitHub API token for searching exploits.
    Returns None if not found (search will be limited).

    Returns:
        str or None: The GitHub API token
    """
    token = os.getenv("GITHUB_TOKEN", "")

    if not token:
        logger.warning("GITHUB_TOKEN not found in environment variables. GitHub search will be limited.")
        return None

    return token


def get_exploit_db_api_url():
    """
    Retrieves the Exploit-DB API URL.
    Returns None if not specified, which will skip Exploit-DB searches.

    Returns:
        str or None: The Exploit-DB API URL
    """
    url = os.getenv("EXPLOIT_DB_API_URL", "")

    if not url:
        logger.warning("EXPLOIT_DB_API_URL not found in environment variables. Exploit-DB searches will be skipped.")
        return None

    return url


def get_github_api_url():
    """
    Retrieves the GitHub API URL.
    Defaults to 'https://api.github.com' if not specified.

    Returns:
        str: The GitHub API URL
    """
    url = os.getenv("GITHUB_API_URL", "")

    if not url:
        default = "https://api.github.com"
        logger.warning(f"GITHUB_API_URL not found in environment variables. Using default: {default}")
        return default

    return url


def get_exploit_search_max_results():
    """
    Retrieves the maximum number of results to fetch from each exploit source.
    Defaults to 10 if not specified or invalid.

    Returns:
        int: Maximum number of results per source
    """
    max_results = os.getenv("EXPLOIT_SEARCH_MAX_RESULTS", "")

    try:
        value = int(max_results)
        if value <= 0:
            raise ValueError("Value must be positive")
        return value
    except (ValueError, TypeError):
        default = 10
        logger.warning(f"Invalid or missing EXPLOIT_SEARCH_MAX_RESULTS value. Using default: {default}")
        return default


def get_public_exploit_boost_factor():
    """
    Retrieves the boost factor for CVEs with public exploits.
    This multiplier is applied to the risk score when public exploits are available.
    Defaults to 1.5 if not specified or invalid.

    Returns:
        float: Boost factor for public exploits
    """
    boost_factor = os.getenv("PUBLIC_EXPLOIT_BOOST_FACTOR", "")

    try:
        value = float(boost_factor)
        if value <= 0:
            raise ValueError("Value must be positive")
        return value
    except (ValueError, TypeError):
        default = 1.5
        logger.warning(f"Invalid or missing PUBLIC_EXPLOIT_BOOST_FACTOR value. Using default: {default}")
        return default


def get_nvd_api_key():
    """
    Retrieves the NVD API key from environment variables.
    API key is optional for basic NVD requests but recommended for higher rate limits.
    Returns None if not configured.

    Returns:
        str or None: The NVD API key if configured, None otherwise
    """
    api_key = os.getenv("NVD_API_KEY", "")

    if not api_key:
        logger.info("NVD_API_KEY not found in environment variables. Using public rate limits.")
        return None

    logger.info("NVD API key found - using authenticated requests for higher rate limits")
    return api_key


def get_exa_api_key():
    """
    Retrieves the EXA AI API key from environment variables.

    Returns:
        str: The EXA AI API key

    Raises:
        ValueError: If the API key is not found in environment variables
    """
    api_key = os.getenv("EXA_API_KEY")

    if not api_key:
        logger.error("EXA_API_KEY not found in environment variables")
        raise ValueError("EXA_API_KEY not found. Please add it to your .env file")

    return api_key


def get_exa_results_per_query():
    """
    Retrieves the number of results to fetch per EXA search query.
    Defaults to 5 if not specified or invalid.

    Returns:
        int: Number of results per EXA query
    """
    results_per_query = os.getenv("EXA_RESULTS_PER_QUERY", "")

    try:
        value = int(results_per_query)
        if value <= 0:
            raise ValueError("Value must be positive")
        return value
    except (ValueError, TypeError):
        default = 5
        logger.warning(f"Invalid or missing EXA_RESULTS_PER_QUERY value. Using default: {default}")
        return default


def get_exa_general_queries():
    """
    Retrieves the general EXA AI queries configuration as a list.
    Returns an empty list if not specified or invalid.

    Returns:
        list: List of general query strings
    """
    queries_str = os.getenv("EXA_GENERAL_QUERIES", "")

    if not queries_str:
        logger.warning("EXA_GENERAL_QUERIES not found in environment variables. Using empty list.")
        return []

    try:
        # Split by commas and strip whitespace
        queries = [query.strip() for query in queries_str.split(",") if query.strip()]
        return queries
    except Exception as e:
        logger.warning(f"Error parsing EXA_GENERAL_QUERIES: {str(e)}. Using empty list.")
        return []


def get_llm_provider(default="gemini"):
    """
    Retrieves the LLM provider setting from environment variables.
    Defaults to 'gemini' if not specified.

    Args:
        default (str): Default LLM provider if not configured

    Returns:
        str: The LLM provider name in lowercase ('gemini' or 'ollama')
    """
    provider = os.getenv("LLM_PROVIDER", "").lower().strip()

    if not provider:
        logger.warning(f"LLM_PROVIDER not found in environment variables. Using default: {default}")
        return default.lower()

    # Validate provider
    valid_providers = ["gemini", "ollama", "openai"]
    if provider not in valid_providers:
        logger.warning(f"Invalid LLM_PROVIDER '{provider}'. Must be one of {valid_providers}. Using default: {default}")
        return default.lower()

    logger.info(f"Using LLM provider: {provider}")
    return provider


def get_ollama_api_base_url(default="http://localhost:11434"):
    """
    Retrieves the Ollama API base URL from environment variables.
    Defaults to 'http://localhost:11434' if not specified.

    Args:
        default (str): Default Ollama API base URL if not configured

    Returns:
        str: The Ollama API base URL
    """
    base_url = os.getenv("OLLAMA_API_BASE_URL", "").strip()

    if not base_url:
        logger.warning(f"OLLAMA_API_BASE_URL not found in environment variables. Using default: {default}")
        return default

    # Remove trailing slash if present
    base_url = base_url.rstrip("/")

    logger.info(f"Using Ollama API base URL: {base_url}")
    return base_url


def get_local_llm_model_name(default="llama3:8b"):
    """
    Retrieves the local LLM model name from environment variables.
    Defaults to 'llama3:8b' if not specified.

    Args:
        default (str): Default model name if not configured

    Returns:
        str: The local LLM model name
    """
    model_name = os.getenv("LOCAL_LLM_MODEL_NAME", "").strip()

    if not model_name:
        logger.warning(f"LOCAL_LLM_MODEL_NAME not found in environment variables. Using default: {default}")
        return default

    logger.info(f"Using local LLM model: {model_name}")
    return model_name


def get_openai_api_key():
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        logger.error("OPENAI_API_KEY not found in environment variables")
        raise ValueError("OPENAI_API_KEY not found. Please add it to your .env file")
    return api_key

def get_openai_model_name(default="gpt-4o-mini"):
    name = os.getenv("OPENAI_MODEL_NAME", "").strip()
    if not name:
        logger.warning(f"OPENAI_MODEL_NAME not found. Using default: {default}")
        return default
    return name

def get_openai_base_url(default="https://api.openai.com/v1"):
    url = os.getenv("OPENAI_BASE_URL", "").strip()
    return url or default
