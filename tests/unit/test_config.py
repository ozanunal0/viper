"""
Tests for configuration utility functions

These tests are designed to be robust and avoid assumptions about
specific implementation details, making them less likely to break
when implementation changes.
"""
import os
import tempfile
from unittest.mock import patch

import pytest

from src.utils.config import (
    get_db_file_name,
    get_gemini_api_key,
    get_gemini_concurrent_requests,
    get_gemini_model_name,
    get_llm_provider,
    get_local_llm_model_name,
    get_log_file_name,
    get_log_level,
    get_nvd_api_base_url,
    get_nvd_days_published_ago,
    get_nvd_pagination_delay,
    get_nvd_results_per_page,
    get_ollama_api_base_url,
    get_retry_max_attempts,
    get_retry_wait_max_seconds,
    get_retry_wait_min_seconds,
    get_retry_wait_multiplier,
)


class TestGeminiConfig:
    """Test Gemini-related configuration functions."""

    def test_get_gemini_model_name_returns_string(self):
        """Test that get_gemini_model_name returns a string."""
        result = get_gemini_model_name()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_get_gemini_model_name_uses_env_var(self):
        """Test that get_gemini_model_name uses environment variable when set."""
        with patch.dict(os.environ, {"GEMINI_MODEL_NAME": "test-model"}):
            result = get_gemini_model_name()
            assert result == "test-model"

    def test_get_gemini_model_name_with_env_var(self):
        """Test get_gemini_model_name with environment variable set."""
        with patch.dict(os.environ, {"GEMINI_MODEL_NAME": "custom-model"}, clear=False):
            result = get_gemini_model_name()
            assert result == "custom-model"

    def test_get_gemini_model_name_default(self):
        """Test get_gemini_model_name returns default when env var is empty."""
        with patch.dict(os.environ, {"GEMINI_MODEL_NAME": ""}, clear=False):
            result = get_gemini_model_name()
            assert result == "gemini-2.5-flash-preview-04-17"

    def test_get_gemini_api_key_success(self):
        """Test successful retrieval of Gemini API key."""
        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-api-key"}):
            result = get_gemini_api_key()
            assert result == "test-api-key"

    def test_get_gemini_api_key_missing(self):
        """Test that missing Gemini API key raises ValueError."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="GEMINI_API_KEY not found"):
                get_gemini_api_key()

    def test_get_gemini_concurrent_requests_valid(self):
        """Test valid concurrent requests configuration."""
        with patch.dict(os.environ, {"GEMINI_CONCURRENT_REQUESTS": "10"}):
            result = get_gemini_concurrent_requests()
            assert result == 10

    def test_get_gemini_concurrent_requests_invalid(self):
        """Test invalid concurrent requests falls back to default."""
        with patch.dict(os.environ, {"GEMINI_CONCURRENT_REQUESTS": "invalid"}):
            result = get_gemini_concurrent_requests()
            assert result == 5  # default

    def test_get_gemini_concurrent_requests_zero(self):
        """Test zero concurrent requests falls back to default."""
        with patch.dict(os.environ, {"GEMINI_CONCURRENT_REQUESTS": "0"}):
            result = get_gemini_concurrent_requests()
            assert result == 5  # default


class TestNVDConfig:
    """Test NVD-related configuration functions."""

    def test_get_nvd_api_base_url_default(self):
        """Test NVD API base URL returns default."""
        with patch.dict(os.environ, {"NVD_API_BASE_URL": ""}, clear=False):
            result = get_nvd_api_base_url()
            assert result == "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def test_get_nvd_api_base_url_custom(self):
        """Test NVD API base URL with custom value."""
        with patch.dict(os.environ, {"NVD_API_BASE_URL": "https://custom.nvd.url"}):
            result = get_nvd_api_base_url()
            assert result == "https://custom.nvd.url"

    def test_get_nvd_days_published_ago_valid(self):
        """Test valid days published ago."""
        with patch.dict(os.environ, {"NVD_DAYS_PUBLISHED_AGO": "14"}):
            result = get_nvd_days_published_ago()
            assert result == 14

    def test_get_nvd_days_published_ago_invalid(self):
        """Test invalid days published ago falls back to default."""
        with patch.dict(os.environ, {"NVD_DAYS_PUBLISHED_AGO": "invalid"}):
            result = get_nvd_days_published_ago()
            assert result == 7  # default

    def test_get_nvd_results_per_page_valid(self):
        """Test valid results per page."""
        with patch.dict(os.environ, {"NVD_RESULTS_PER_PAGE": "1000"}):
            result = get_nvd_results_per_page()
            assert result == 1000

    def test_get_nvd_results_per_page_invalid(self):
        """Test invalid results per page falls back to default."""
        with patch.dict(os.environ, {"NVD_RESULTS_PER_PAGE": "not_a_number"}):
            result = get_nvd_results_per_page()
            assert result == 2000  # default

    def test_get_nvd_pagination_delay_valid(self):
        """Test valid pagination delay."""
        with patch.dict(os.environ, {"NVD_PAGINATION_DELAY_SECONDS": "1.5"}):
            result = get_nvd_pagination_delay()
            assert result == 1.5

    def test_get_nvd_pagination_delay_invalid(self):
        """Test invalid pagination delay falls back to default."""
        with patch.dict(os.environ, {"NVD_PAGINATION_DELAY_SECONDS": "invalid"}):
            result = get_nvd_pagination_delay()
            assert result == 0.5  # default


class TestDatabaseConfig:
    """Test database-related configuration functions."""

    def test_get_db_file_name_default(self):
        """Test database file name returns default."""
        with patch.dict(os.environ, {"DB_FILE_NAME": ""}, clear=False):
            result = get_db_file_name()
            assert "viper.db" in result
            assert os.path.isabs(result)  # Should return absolute path

    def test_get_db_file_name_custom_relative(self):
        """Test database file name with custom relative path."""
        with patch.dict(os.environ, {"DB_FILE_NAME": "custom.db"}):
            result = get_db_file_name()
            assert "custom.db" in result
            assert os.path.isabs(result)  # Should return absolute path

    def test_get_db_file_name_absolute_path(self):
        """Test database file name with absolute path."""
        with tempfile.TemporaryDirectory() as temp_dir:
            abs_path = os.path.join(temp_dir, "test.db")
            with patch.dict(os.environ, {"DB_FILE_NAME": abs_path}):
                result = get_db_file_name()
                assert result == abs_path


class TestLoggingConfig:
    """Test logging-related configuration functions."""

    def test_get_log_file_name_default(self):
        """Test log file name returns default."""
        result = get_log_file_name()
        assert isinstance(result, str)
        assert "viper.log" in result

    def test_get_log_level_default(self):
        """Test log level returns default."""
        with patch.dict(os.environ, {"LOG_LEVEL": ""}, clear=False):
            result = get_log_level()
            assert result == "INFO"

    def test_get_log_level_custom(self):
        """Test log level with custom value."""
        with patch.dict(os.environ, {"LOG_LEVEL": "DEBUG"}):
            result = get_log_level()
            assert result == "DEBUG"


class TestRetryConfig:
    """Test retry-related configuration functions."""

    def test_get_retry_max_attempts_default(self):
        """Test retry max attempts returns default."""
        result = get_retry_max_attempts()
        assert isinstance(result, int)
        assert result > 0

    def test_get_retry_wait_multiplier_default(self):
        """Test retry wait multiplier returns default."""
        result = get_retry_wait_multiplier()
        assert isinstance(result, (int, float))
        assert result > 0

    def test_get_retry_wait_min_seconds_default(self):
        """Test retry wait min seconds returns default."""
        result = get_retry_wait_min_seconds()
        assert isinstance(result, (int, float))
        assert result >= 0

    def test_get_retry_wait_max_seconds_default(self):
        """Test retry wait max seconds returns default."""
        result = get_retry_wait_max_seconds()
        assert isinstance(result, (int, float))
        assert result > 0


class TestLLMConfig:
    """Test LLM-related configuration functions."""

    def test_get_llm_provider_default(self):
        """Test LLM provider returns default."""
        with patch.dict(os.environ, {"LLM_PROVIDER": ""}, clear=False):
            result = get_llm_provider()
            assert result == "gemini"

    def test_get_llm_provider_custom(self):
        """Test LLM provider with custom value."""
        with patch.dict(os.environ, {"LLM_PROVIDER": "ollama"}):
            result = get_llm_provider()
            assert result == "ollama"

    def test_get_ollama_api_base_url_default(self):
        """Test Ollama API base URL returns default."""
        with patch.dict(os.environ, {"OLLAMA_API_BASE_URL": ""}, clear=False):
            result = get_ollama_api_base_url()
            assert result == "http://localhost:11434"

    def test_get_ollama_api_base_url_custom(self):
        """Test Ollama API base URL with custom value."""
        with patch.dict(os.environ, {"OLLAMA_API_BASE_URL": "http://custom:8080"}):
            result = get_ollama_api_base_url()
            assert result == "http://custom:8080"

    def test_get_local_llm_model_name_default(self):
        """Test local LLM model name returns default."""
        with patch.dict(os.environ, {"LOCAL_LLM_MODEL_NAME": ""}, clear=False):
            result = get_local_llm_model_name()
            assert result == "llama3:8b"

    def test_get_local_llm_model_name_custom(self):
        """Test local LLM model name with custom value."""
        with patch.dict(os.environ, {"LOCAL_LLM_MODEL_NAME": "custom-model"}):
            result = get_local_llm_model_name()
            assert result == "custom-model"
