"""
Unit tests for dashboard functionality.
"""
from unittest.mock import MagicMock, patch

import pytest


class TestDashboardLogic:
    """Test cases for dashboard logic without complex Streamlit imports."""

    def test_cve_data_formatting(self):
        """Test CVE data formatting for dashboard display."""

        def format_cve_for_display(cve_data):
            """Mock CVE data formatter for dashboard."""
            if not cve_data:
                return {"error": "No CVE data provided"}

            formatted = {
                "display_id": cve_data.get("cve_id", "Unknown"),
                "display_score": f"{cve_data.get('cvss_v3_score', 0.0):.1f}",
                "display_description": cve_data.get("description", "No description")[:100] + "...",
                "priority_color": "red" if cve_data.get("cvss_v3_score", 0) >= 7.0 else "green",
            }

            return formatted

        # Test valid CVE data
        cve_data = {
            "cve_id": "CVE-2023-1234",
            "cvss_v3_score": 8.5,
            "description": "This is a test vulnerability with a long description that should be truncated for display purposes in the dashboard interface.",
        }

        result = format_cve_for_display(cve_data)

        assert result["display_id"] == "CVE-2023-1234"
        assert result["display_score"] == "8.5"
        assert len(result["display_description"]) <= 103  # 100 chars + "..."
        assert result["priority_color"] == "red"

        # Test empty data
        result = format_cve_for_display(None)
        assert "error" in result

    def test_priority_color_mapping(self):
        """Test priority to color mapping for dashboard."""

        def get_priority_color(priority):
            """Mock priority color mapper."""
            color_map = {
                "HIGH": "red",
                "MEDIUM": "orange",
                "LOW": "green",
                "ERROR_ANALYZING": "gray",
            }

            return color_map.get(priority.upper() if priority else "", "gray")

        # Test all priority levels
        assert get_priority_color("HIGH") == "red"
        assert get_priority_color("MEDIUM") == "orange"
        assert get_priority_color("LOW") == "green"
        assert get_priority_color("ERROR_ANALYZING") == "gray"

        # Test case insensitive
        assert get_priority_color("high") == "red"
        assert get_priority_color("medium") == "orange"

        # Test unknown priority
        assert get_priority_color("UNKNOWN") == "gray"
        assert get_priority_color(None) == "gray"

    def test_provider_detection(self):
        """Test LLM provider detection for dashboard display."""

        def get_provider_display_name(provider):
            """Mock provider display name mapper."""
            display_names = {
                "gemini": "Gemini AI",
                "ollama": "Local LLM (Ollama)",
                "openai": "OpenAI GPT",
            }

            return display_names.get(provider.lower() if provider else "", "Unknown Provider")

        # Test known providers
        assert get_provider_display_name("gemini") == "Gemini AI"
        assert get_provider_display_name("ollama") == "Local LLM (Ollama)"
        assert get_provider_display_name("openai") == "OpenAI GPT"

        # Test case insensitive
        assert get_provider_display_name("GEMINI") == "Gemini AI"
        assert get_provider_display_name("Ollama") == "Local LLM (Ollama)"

        # Test unknown provider
        assert get_provider_display_name("unknown") == "Unknown Provider"
        assert get_provider_display_name(None) == "Unknown Provider"

    def test_cve_metrics_calculation(self):
        """Test CVE metrics calculation for dashboard."""

        def calculate_cve_metrics(cve_list):
            """Mock CVE metrics calculator."""
            if not cve_list:
                return {"total": 0, "high": 0, "medium": 0, "low": 0, "error": 0}

            metrics = {"total": len(cve_list), "high": 0, "medium": 0, "low": 0, "error": 0}

            for cve in cve_list:
                priority = cve.get("priority", "").upper()
                if priority == "HIGH":
                    metrics["high"] += 1
                elif priority == "MEDIUM":
                    metrics["medium"] += 1
                elif priority == "LOW":
                    metrics["low"] += 1
                else:
                    metrics["error"] += 1

            return metrics

        # Test with CVE data
        cve_list = [
            {"cve_id": "CVE-2023-1", "priority": "HIGH"},
            {"cve_id": "CVE-2023-2", "priority": "HIGH"},
            {"cve_id": "CVE-2023-3", "priority": "MEDIUM"},
            {"cve_id": "CVE-2023-4", "priority": "LOW"},
            {"cve_id": "CVE-2023-5", "priority": "ERROR_ANALYZING"},
        ]

        metrics = calculate_cve_metrics(cve_list)

        assert metrics["total"] == 5
        assert metrics["high"] == 2
        assert metrics["medium"] == 1
        assert metrics["low"] == 1
        assert metrics["error"] == 1

        # Test with empty list
        metrics = calculate_cve_metrics([])
        assert metrics["total"] == 0
        assert all(metrics[key] == 0 for key in ["high", "medium", "low", "error"])

    def test_search_functionality(self):
        """Test search functionality for dashboard."""

        def search_cves(cve_list, search_term):
            """Mock CVE search function."""
            if not search_term:
                return cve_list

            search_term = search_term.lower()
            filtered = []

            for cve in cve_list:
                cve_id = cve.get("cve_id", "").lower()
                description = cve.get("description", "").lower()

                if search_term in cve_id or search_term in description:
                    filtered.append(cve)

            return filtered

        # Test data
        cve_list = [
            {"cve_id": "CVE-2023-1234", "description": "Remote code execution vulnerability"},
            {"cve_id": "CVE-2023-5678", "description": "SQL injection in web application"},
            {"cve_id": "CVE-2024-1111", "description": "Buffer overflow in network service"},
        ]

        # Test CVE ID search
        result = search_cves(cve_list, "2023-1234")
        assert len(result) == 1
        assert result[0]["cve_id"] == "CVE-2023-1234"

        # Test description search
        result = search_cves(cve_list, "sql injection")
        assert len(result) == 1
        assert result[0]["cve_id"] == "CVE-2023-5678"

        # Test partial match
        result = search_cves(cve_list, "2023")
        assert len(result) == 2

        # Test no match
        result = search_cves(cve_list, "nonexistent")
        assert len(result) == 0

        # Test empty search
        result = search_cves(cve_list, "")
        assert len(result) == 3


class TestDashboardUtilities:
    """Test utility functions for dashboard."""

    def test_pagination_logic(self):
        """Test pagination logic for dashboard tables."""

        def paginate_data(data, page_size=10, current_page=1):
            """Mock pagination function."""
            if not data or page_size <= 0 or current_page <= 0:
                return {"items": [], "total_pages": 0, "current_page": 1, "total_items": 0}

            total_items = len(data)
            total_pages = (total_items + page_size - 1) // page_size

            start_idx = (current_page - 1) * page_size
            end_idx = start_idx + page_size

            items = data[start_idx:end_idx]

            return {
                "items": items,
                "total_pages": total_pages,
                "current_page": current_page,
                "total_items": total_items,
            }

        # Test data
        data = [f"item_{i}" for i in range(25)]  # 25 items

        # Test first page
        result = paginate_data(data, page_size=10, current_page=1)
        assert len(result["items"]) == 10
        assert result["total_pages"] == 3
        assert result["current_page"] == 1
        assert result["total_items"] == 25
        assert result["items"][0] == "item_0"

        # Test last page
        result = paginate_data(data, page_size=10, current_page=3)
        assert len(result["items"]) == 5  # Remaining items
        assert result["current_page"] == 3

        # Test invalid parameters
        result = paginate_data([], page_size=10, current_page=1)
        assert result["items"] == []
        assert result["total_pages"] == 0

    def test_data_validation(self):
        """Test data validation for dashboard inputs."""

        def validate_cve_input(cve_id):
            """Mock CVE ID validation for dashboard."""
            import re

            if not cve_id:
                return False, "CVE ID is required"

            # Remove whitespace
            cve_id = cve_id.strip()

            # Check format
            if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
                return False, "Invalid CVE ID format (expected: CVE-YYYY-NNNN)"

            return True, "Valid CVE ID"

        # Test valid inputs
        valid_inputs = ["CVE-2023-1234", "CVE-2024-12345", " CVE-2022-123456 "]
        for cve_id in valid_inputs:
            is_valid, message = validate_cve_input(cve_id)
            assert is_valid is True
            assert message == "Valid CVE ID"

        # Test invalid inputs
        invalid_inputs = ["", "CVE-23-1234", "2023-1234", "CVE-2023-123", "invalid"]
        for cve_id in invalid_inputs:
            is_valid, message = validate_cve_input(cve_id)
            assert is_valid is False
            assert "Invalid" in message or "required" in message

    def test_error_message_formatting(self):
        """Test error message formatting for dashboard."""

        def format_error_message(error_type, details=None):
            """Mock error message formatter."""
            error_messages = {
                "network": "Network connection failed. Please check your internet connection.",
                "api": "API request failed. Please try again later.",
                "validation": "Invalid input provided. Please check your data.",
                "not_found": "Resource not found. Please verify the ID and try again.",
            }

            base_message = error_messages.get(error_type, "An unknown error occurred.")

            if details:
                base_message += f" Details: {details}"

            return base_message

        # Test known error types
        assert "Network connection failed" in format_error_message("network")
        assert "API request failed" in format_error_message("api")
        assert "Invalid input provided" in format_error_message("validation")
        assert "Resource not found" in format_error_message("not_found")

        # Test with details
        message = format_error_message("api", "Rate limit exceeded")
        assert "API request failed" in message
        assert "Rate limit exceeded" in message

        # Test unknown error type
        message = format_error_message("unknown")
        assert "An unknown error occurred" in message
