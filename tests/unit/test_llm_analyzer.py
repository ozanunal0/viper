"""
Unit tests for the LLM analyzer module.
"""
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import aiohttp
import pytest

from src.llm_analyzer import (
    _analyze_with_gemini_async,
    _analyze_with_ollama_async,
    _create_gemini_prompt,
    _create_ollama_prompt,
    _extract_cve_data_for_prompt,
    _parse_ollama_response,
    analyze_cve_async,
    analyze_cve_with_gemini,
    check_ollama_availability,
    configure_gemini,
)


class TestConfigureGemini:
    """Test cases for Gemini configuration."""

    @patch("src.llm_analyzer.get_gemini_api_key")
    @patch("src.llm_analyzer.genai.configure")
    def test_configure_gemini_success(self, mock_configure, mock_get_api_key):
        """Test successful Gemini configuration."""
        mock_get_api_key.return_value = "test-api-key"

        configure_gemini()

        mock_get_api_key.assert_called_once()
        mock_configure.assert_called_once_with(api_key="test-api-key")

    @patch("src.llm_analyzer.get_gemini_api_key")
    def test_configure_gemini_failure(self, mock_get_api_key):
        """Test Gemini configuration failure."""
        mock_get_api_key.side_effect = ValueError("API key not found")

        with pytest.raises(ValueError):
            configure_gemini()


class TestExtractCveDataForPrompt:
    """Test cases for CVE data extraction."""

    def test_extract_basic_cve_data(self):
        """Test extraction of basic CVE data."""
        cve_data = {
            "cve_id": "CVE-2023-1234",
            "cvss_v3_score": 9.8,
            "description": "Critical vulnerability in test software",
        }

        result = _extract_cve_data_for_prompt(cve_data)

        assert result["cve_id"] == "CVE-2023-1234"
        assert result["cvss_score"] == 9.8
        assert result["description"] == "Critical vulnerability in test software"
        assert result["epss_info"] == "Not available"
        assert result["kev_info"] == "No"

    def test_extract_complete_cve_data(self):
        """Test extraction of complete CVE data with all fields."""
        cve_data = {
            "cve_id": "CVE-2023-5678",
            "cvss_v3_score": 7.5,
            "description": "Test vulnerability",
            "epss_score": 0.123,
            "epss_percentile": 0.95,
            "is_in_kev": True,
            "kev_date_added": "2023-12-01",
            "microsoft_severity": "Critical",
            "microsoft_product_family": "Windows",
            "microsoft_product_name": "Windows 11",
            "patch_tuesday_date": "2023-12-12",
            "has_public_exploit": True,
            "exploit_references": [
                {"source": "ExploitDB", "url": "https://example.com"},
                {"source": "GitHub", "url": "https://github.com/example"},
            ],
        }

        result = _extract_cve_data_for_prompt(cve_data)

        assert result["cve_id"] == "CVE-2023-5678"
        assert result["cvss_score"] == 7.5
        assert result["epss_info"] == "0.1230 (Exploitation probability in the 95.00% percentile)"
        assert result["kev_info"] == "Yes, added on 2023-12-01"
        assert result["ms_severity"] == "Critical"
        assert result["ms_product_family"] == "Windows"
        assert result["exploit_info"] == "Yes, 2 exploit(s) found on ExploitDB, GitHub"

    def test_extract_missing_fields(self):
        """Test extraction with missing optional fields."""
        cve_data = {}

        result = _extract_cve_data_for_prompt(cve_data)

        assert result["cve_id"] == "Unknown CVE"
        assert result["cvss_score"] == "Not available"
        assert result["description"] == "No description available"
        assert result["epss_info"] == "Not available"
        assert result["kev_info"] == "No"
        assert result["ms_severity"] == "N/A"
        assert result["exploit_info"] == "No"


class TestParseOllamaResponse:
    """Test cases for Ollama response parsing."""

    def test_parse_valid_response(self):
        """Test parsing a valid Ollama response."""
        response = """
        PRIORITY: HIGH
        JUSTIFICATION: This is a critical remote code execution vulnerability
        """

        priority, justification = _parse_ollama_response(response)

        assert priority == "HIGH"
        assert "critical remote code execution" in justification

    def test_parse_response_with_extra_text(self):
        """Test parsing response with additional text."""
        response = """
        Based on the analysis:
        PRIORITY: MEDIUM
        JUSTIFICATION: Moderate risk due to limited exploitation
        Additional notes here...
        """

        priority, justification = _parse_ollama_response(response)

        assert priority == "MEDIUM"
        assert "Moderate risk" in justification

    def test_parse_invalid_response(self):
        """Test parsing an invalid response."""
        response = "Invalid response without proper format"

        priority, justification = _parse_ollama_response(response)

        assert priority == "MEDIUM"  # Default fallback
        assert response in justification


class TestCreatePrompts:
    """Test cases for prompt creation functions."""

    def test_create_ollama_prompt(self):
        """Test Ollama prompt creation."""
        cve_data = {
            "cve_id": "CVE-2023-1234",
            "cvss_v3_score": 9.8,
            "description": "Test vulnerability",
        }

        prompt = _create_ollama_prompt(cve_data)

        assert "CVE-2023-1234" in prompt
        assert "9.8" in prompt
        assert "Test vulnerability" in prompt
        assert "PRIORITY: [HIGH/MEDIUM/LOW]" in prompt
        assert "<analysis>" in prompt

    def test_create_gemini_prompt(self):
        """Test Gemini prompt creation."""
        cve_data = {
            "cve_id": "CVE-2023-5678",
            "cvss_v3_score": 7.5,
            "description": "Another test vulnerability",
        }

        prompt = _create_gemini_prompt(cve_data)

        assert "CVE-2023-5678" in prompt
        assert "7.5" in prompt
        assert "Another test vulnerability" in prompt
        assert "Priority:" in prompt


class TestAnalyzeWithOllamaAsync:
    """Test cases for Ollama analysis."""

    @pytest.mark.asyncio
    async def test_ollama_analysis_success(self):
        """Test successful Ollama analysis."""
        mock_response_data = {
            "response": "PRIORITY: HIGH\nJUSTIFICATION: Critical vulnerability",
            "eval_count": 100,
            "eval_duration": 1000000000,  # 1 second in nanoseconds
        }

        with patch("src.llm_analyzer.get_ollama_api_base_url", return_value="http://localhost:11434"), patch(
            "src.llm_analyzer.get_local_llm_model_name", return_value="llama2"
        ), patch("aiohttp.ClientSession.post") as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_response_data)
            mock_post.return_value.__aenter__.return_value = mock_response

            priority, justification, raw_response = await _analyze_with_ollama_async("test prompt", "CVE-2023-1234")

            assert priority == "HIGH"
            assert "Critical vulnerability" in justification
            assert raw_response == "PRIORITY: HIGH\nJUSTIFICATION: Critical vulnerability"

    @pytest.mark.asyncio
    async def test_ollama_analysis_http_error(self):
        """Test Ollama analysis with HTTP error."""
        with patch("src.llm_analyzer.get_ollama_api_base_url", return_value="http://localhost:11434"), patch(
            "src.llm_analyzer.get_local_llm_model_name", return_value="llama2"
        ), patch("aiohttp.ClientSession.post") as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 500
            mock_response.text = AsyncMock(return_value="Internal Server Error")
            mock_post.return_value.__aenter__.return_value = mock_response

            priority, justification, raw_response = await _analyze_with_ollama_async("test prompt", "CVE-2023-1234")

            assert priority == "ERROR_ANALYZING"
            assert justification is None
            assert "status 500" in raw_response

    @pytest.mark.asyncio
    async def test_ollama_analysis_timeout(self):
        """Test Ollama analysis with timeout."""
        with patch("src.llm_analyzer.get_ollama_api_base_url", return_value="http://localhost:11434"), patch(
            "src.llm_analyzer.get_local_llm_model_name", return_value="llama2"
        ), patch("aiohttp.ClientSession.post") as mock_post:
            mock_post.side_effect = asyncio.TimeoutError()

            priority, justification, raw_response = await _analyze_with_ollama_async("test prompt", "CVE-2023-1234")

            assert priority == "ERROR_ANALYZING"
            assert justification is None
            assert "Timeout" in raw_response


class TestAnalyzeCveAsync:
    """Test cases for main CVE analysis function."""

    @pytest.mark.asyncio
    async def test_analyze_cve_gemini_provider(self):
        """Test CVE analysis with Gemini provider."""
        cve_data = {"cve_id": "CVE-2023-1234", "description": "Test CVE"}

        with patch("src.llm_analyzer.get_llm_provider", return_value="gemini"), patch(
            "src.llm_analyzer._analyze_with_gemini_async", return_value=("HIGH", "Test justification", "Raw response")
        ) as mock_analyze:
            result = await analyze_cve_async(cve_data)

            assert result == ("HIGH", "Test justification", "Raw response")
            mock_analyze.assert_called_once_with(cve_data)

    @pytest.mark.asyncio
    async def test_analyze_cve_ollama_provider(self):
        """Test CVE analysis with Ollama provider."""
        cve_data = {"cve_id": "CVE-2023-1234", "description": "Test CVE"}

        with patch("src.llm_analyzer.get_llm_provider", return_value="ollama"), patch(
            "src.llm_analyzer._create_ollama_prompt", return_value="test prompt"
        ), patch(
            "src.llm_analyzer._analyze_with_ollama_async", return_value=("MEDIUM", "Test justification", "Raw response")
        ) as mock_analyze:
            result = await analyze_cve_async(cve_data)

            assert result == ("MEDIUM", "Test justification", "Raw response")
            mock_analyze.assert_called_once_with("test prompt", "CVE-2023-1234")

    @pytest.mark.asyncio
    async def test_analyze_cve_unknown_provider(self):
        """Test CVE analysis with unknown provider."""
        cve_data = {"cve_id": "CVE-2023-1234", "description": "Test CVE"}

        with patch("src.llm_analyzer.get_llm_provider", return_value="unknown"):
            result = await analyze_cve_async(cve_data)

            assert result[0] == "ERROR_ANALYZING"
            assert result[1] is None
            assert "Unknown LLM provider" in result[2]


class TestAnalyzeWithGeminiAsync:
    """Test cases for Gemini analysis."""

    @pytest.mark.asyncio
    async def test_gemini_analysis_success(self):
        """Test successful Gemini analysis."""
        cve_data = {"cve_id": "CVE-2023-1234", "description": "Test CVE"}

        mock_response = MagicMock()
        mock_response.text = "HIGH"

        with patch("src.llm_analyzer.configure_gemini"), patch(
            "src.llm_analyzer.get_gemini_model_name", return_value="gemini-pro"
        ), patch("src.llm_analyzer.genai.GenerativeModel") as mock_model_class, patch(
            "src.llm_analyzer._generate_content_with_retry", return_value=mock_response
        ) as mock_generate:
            result = await _analyze_with_gemini_async(cve_data)

            assert result[0] == "HIGH"
            assert result[1] == "HIGH"
            assert result[2] == "HIGH"

    @pytest.mark.asyncio
    async def test_gemini_analysis_error(self):
        """Test Gemini analysis with error."""
        cve_data = {"cve_id": "CVE-2023-1234", "description": "Test CVE"}

        with patch("src.llm_analyzer.configure_gemini", side_effect=Exception("API Error")):
            result = await _analyze_with_gemini_async(cve_data)

            assert result[0] == "ERROR_ANALYZING"
            assert result[1] is None
            assert "API Error" in result[2]


class TestCheckOllamaAvailability:
    """Test cases for Ollama availability check."""

    @pytest.mark.asyncio
    async def test_ollama_available(self):
        """Test when Ollama is available."""
        mock_response_data = {
            "models": [
                {"name": "llama2:latest", "size": 3800000000},
                {"name": "codellama:latest", "size": 3800000000},
            ]
        }

        with patch("src.llm_analyzer.get_ollama_api_base_url", return_value="http://localhost:11434"), patch(
            "aiohttp.ClientSession.get"
        ) as mock_get:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_response_data)
            mock_get.return_value.__aenter__.return_value = mock_response

            available, message, models = await check_ollama_availability()

            assert available is True
            assert "Ollama is running" in message
            assert len(models) == 2
            assert "llama2:latest" in models

    @pytest.mark.asyncio
    async def test_ollama_unavailable(self):
        """Test when Ollama is unavailable."""
        with patch("src.llm_analyzer.get_ollama_api_base_url", return_value="http://localhost:11434"), patch(
            "aiohttp.ClientSession.get"
        ) as mock_get:
            mock_get.side_effect = aiohttp.ClientError("Connection failed")

            available, message, models = await check_ollama_availability()

            assert available is False
            assert "Connection failed" in message
            assert models == []


class TestLegacyFunctions:
    """Test cases for legacy/backward compatibility functions."""

    def test_analyze_cve_with_gemini_sync(self):
        """Test the synchronous Gemini analysis function."""
        cve_data = {"cve_id": "CVE-2023-1234", "description": "Test CVE"}

        with patch("src.llm_analyzer.asyncio.run") as mock_run:
            mock_run.return_value = ("HIGH", "Test justification", "Raw response")

            result = analyze_cve_with_gemini(cve_data)

            # The function returns only 2 values (priority, raw_response) for backward compatibility
            assert result == ("HIGH", "Raw response")
            mock_run.assert_called_once()
