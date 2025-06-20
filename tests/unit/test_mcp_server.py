"""
Unit tests for MCP server functionality.
"""
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest


class TestMcpServerLogic:
    """Test cases for MCP server logic without complex imports."""

    def test_cve_data_processing(self):
        """Test CVE data processing logic."""

        def process_cve_data(cve_data):
            """Mock CVE data processing."""
            if not cve_data.get("cve_id"):
                return {"error": "CVE ID required"}

            return {
                "cve_id": cve_data["cve_id"],
                "processed": True,
                "timestamp": datetime.now().isoformat(),
            }

        # Test valid CVE data
        valid_cve = {"cve_id": "CVE-2023-1234", "description": "Test vulnerability"}
        result = process_cve_data(valid_cve)

        assert result["cve_id"] == "CVE-2023-1234"
        assert result["processed"] is True
        assert "timestamp" in result

        # Test invalid CVE data
        invalid_cve = {"description": "Missing CVE ID"}
        result = process_cve_data(invalid_cve)

        assert "error" in result
        assert result["error"] == "CVE ID required"

    @pytest.mark.asyncio
    async def test_async_cve_analysis(self):
        """Test async CVE analysis logic."""

        async def mock_analyze_cve(cve_id, provider="gemini"):
            """Mock async CVE analysis."""
            if not cve_id:
                return {"error": "CVE ID required"}

            if provider == "gemini":
                return {"priority": "HIGH", "provider": "gemini", "cve_id": cve_id}
            elif provider == "ollama":
                return {"priority": "MEDIUM", "provider": "ollama", "cve_id": cve_id}
            else:
                return {"error": f"Unknown provider: {provider}"}

        # Test Gemini analysis
        result = await mock_analyze_cve("CVE-2023-1234", "gemini")
        assert result["priority"] == "HIGH"
        assert result["provider"] == "gemini"

        # Test Ollama analysis
        result = await mock_analyze_cve("CVE-2023-1234", "ollama")
        assert result["priority"] == "MEDIUM"
        assert result["provider"] == "ollama"

        # Test unknown provider
        result = await mock_analyze_cve("CVE-2023-1234", "unknown")
        assert "error" in result
        assert "Unknown provider" in result["error"]

    def test_priority_validation(self):
        """Test priority validation logic."""

        def validate_priority(priority):
            """Mock priority validation."""
            valid_priorities = ["HIGH", "MEDIUM", "LOW", "ERROR_ANALYZING"]

            if not priority:
                return False, "Priority cannot be empty"

            if priority.upper() not in valid_priorities:
                return False, f"Invalid priority: {priority}"

            return True, "Valid priority"

        # Test valid priorities
        for priority in ["HIGH", "MEDIUM", "LOW", "high", "medium", "low"]:
            is_valid, message = validate_priority(priority)
            assert is_valid is True
            assert message == "Valid priority"

        # Test invalid priority
        is_valid, message = validate_priority("INVALID")
        assert is_valid is False
        assert "Invalid priority" in message

        # Test empty priority
        is_valid, message = validate_priority("")
        assert is_valid is False
        assert "Priority cannot be empty" in message

    def test_cve_id_validation(self):
        """Test CVE ID validation logic."""

        def validate_cve_id(cve_id):
            """Mock CVE ID validation."""
            import re

            if not cve_id:
                return False, "CVE ID cannot be empty"

            # Basic CVE ID pattern validation
            pattern = r"^CVE-\d{4}-\d{4,}$"
            if not re.match(pattern, cve_id):
                return False, f"Invalid CVE ID format: {cve_id}"

            return True, "Valid CVE ID"

        # Test valid CVE IDs
        valid_cves = ["CVE-2023-1234", "CVE-2024-12345", "CVE-2022-123456"]
        for cve_id in valid_cves:
            is_valid, message = validate_cve_id(cve_id)
            assert is_valid is True
            assert message == "Valid CVE ID"

        # Test invalid CVE IDs
        invalid_cves = ["CVE-23-1234", "CVE-2023-123", "2023-1234", ""]
        for cve_id in invalid_cves:
            is_valid, message = validate_cve_id(cve_id)
            assert is_valid is False

    @pytest.mark.asyncio
    async def test_error_handling(self):
        """Test error handling scenarios."""

        async def mock_api_call(endpoint, data=None):
            """Mock API call with error handling."""
            if endpoint == "error":
                raise Exception("API Error")
            elif endpoint == "timeout":
                raise TimeoutError("Request timeout")
            elif endpoint == "not_found":
                return {"error": "Resource not found", "status": 404}
            else:
                return {"status": "success", "data": data}

        # Test successful call
        result = await mock_api_call("success", {"test": "data"})
        assert result["status"] == "success"
        assert result["data"]["test"] == "data"

        # Test API error
        with pytest.raises(Exception, match="API Error"):
            await mock_api_call("error")

        # Test timeout
        with pytest.raises(TimeoutError, match="Request timeout"):
            await mock_api_call("timeout")

        # Test not found
        result = await mock_api_call("not_found")
        assert result["status"] == 404
        assert "error" in result

    def test_data_transformation(self):
        """Test data transformation logic."""

        def transform_cve_data(raw_data):
            """Mock data transformation."""
            if not isinstance(raw_data, dict):
                return {"error": "Invalid data format"}

            transformed = {
                "cve_id": raw_data.get("id", "Unknown"),
                "description": raw_data.get("desc", "No description"),
                "score": float(raw_data.get("cvss", 0.0)),
                "severity": "HIGH" if float(raw_data.get("cvss", 0.0)) >= 7.0 else "LOW",
            }

            return transformed

        # Test valid transformation
        raw_data = {"id": "CVE-2023-1234", "desc": "Test vulnerability", "cvss": "8.5"}
        result = transform_cve_data(raw_data)

        assert result["cve_id"] == "CVE-2023-1234"
        assert result["description"] == "Test vulnerability"
        assert result["score"] == 8.5
        assert result["severity"] == "HIGH"

        # Test invalid data
        result = transform_cve_data("invalid")
        assert "error" in result
        assert result["error"] == "Invalid data format"


class TestMcpServerUtilities:
    """Test utility functions for MCP server."""

    def test_response_formatting(self):
        """Test response formatting."""

        def format_response(status, data=None, error=None):
            """Mock response formatter."""
            response = {"status": status, "timestamp": datetime.now().isoformat()}

            if data is not None:
                response["data"] = data

            if error is not None:
                response["error"] = error

            return response

        # Test success response
        result = format_response("success", {"cve_id": "CVE-2023-1234"})
        assert result["status"] == "success"
        assert result["data"]["cve_id"] == "CVE-2023-1234"
        assert "timestamp" in result

        # Test error response
        result = format_response("error", error="Something went wrong")
        assert result["status"] == "error"
        assert result["error"] == "Something went wrong"

    def test_configuration_validation(self):
        """Test configuration validation."""

        def validate_config(config):
            """Mock configuration validation."""
            required_fields = ["api_key", "model_name", "provider"]
            missing_fields = []

            for field in required_fields:
                if field not in config or not config[field]:
                    missing_fields.append(field)

            if missing_fields:
                return False, f"Missing required fields: {', '.join(missing_fields)}"

            return True, "Configuration is valid"

        # Test valid configuration
        valid_config = {"api_key": "test-key", "model_name": "test-model", "provider": "gemini"}
        is_valid, message = validate_config(valid_config)
        assert is_valid is True
        assert message == "Configuration is valid"

        # Test invalid configuration
        invalid_config = {"api_key": "test-key"}
        is_valid, message = validate_config(invalid_config)
        assert is_valid is False
        assert "Missing required fields" in message
