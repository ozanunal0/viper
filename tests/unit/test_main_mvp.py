"""
Tests for main_mvp.py functions
"""
import os

# Mock the modules that have complex dependencies
import sys
from datetime import datetime
from unittest.mock import MagicMock, Mock, patch

import pytest

# Mock the complex modules before importing main_mvp
sys.modules["src.clients.cisa_kev_client"] = MagicMock()
sys.modules["src.clients.epss_client"] = MagicMock()
sys.modules["src.clients.exa_client"] = MagicMock()
sys.modules["src.clients.exploit_search_client"] = MagicMock()
sys.modules["src.clients.microsoft_update_client"] = MagicMock()
sys.modules["src.clients.nvd_client"] = MagicMock()
sys.modules["src.llm_analyzer"] = MagicMock()
sys.modules["src.risk_analyzer"] = MagicMock()
sys.modules["src.utils.database_handler"] = MagicMock()

from src.main_mvp import display_cve, display_cve_with_alerts


class TestDisplayFunctions:
    """Test display functions in main_mvp.py."""

    def test_display_cve_basic(self, capsys):
        """Test basic CVE display functionality."""
        cve_data = {
            "cve_id": "CVE-2023-1234",
            "cvss_v3_score": 7.5,
            "epss_score": 0.1234,
            "epss_percentile": 0.85,
            "published_date": "2023-01-01T00:00:00Z",
            "processed_at": "2023-01-01T12:00:00Z",
            "is_in_kev": True,
            "kev_date_added": "2023-01-02T00:00:00Z",
            "microsoft_severity": "Critical",
            "microsoft_product_family": "Windows",
            "patch_tuesday_date": "2023-01-10T00:00:00Z",
            "gemini_priority": "HIGH",
            "description": "Test CVE description",
        }

        display_cve(cve_data)

        captured = capsys.readouterr()
        assert "CVE-2023-1234" in captured.out
        assert "HIGH" in captured.out
        assert "7.5" in captured.out
        assert "Test CVE description" in captured.out

    def test_display_cve_minimal_data(self, capsys):
        """Test CVE display with minimal data."""
        cve_data = {"cve_id": "CVE-2023-5678", "description": "Minimal CVE data"}

        display_cve(cve_data)

        captured = capsys.readouterr()
        assert "CVE-2023-5678" in captured.out
        assert "Minimal CVE data" in captured.out
        assert "N/A" in captured.out  # For missing fields

    def test_display_cve_with_none_values(self, capsys):
        """Test CVE display with None values."""
        cve_data = {
            "cve_id": "CVE-2023-9999",
            "cvss_v3_score": None,
            "epss_score": None,
            "epss_percentile": None,
            "is_in_kev": False,
            "description": "CVE with None values",
        }

        display_cve(cve_data)

        captured = capsys.readouterr()
        assert "CVE-2023-9999" in captured.out
        assert "CVE with None values" in captured.out

    def test_display_cve_with_alerts_basic(self, capsys):
        """Test CVE display with alerts functionality."""
        cve_data = {
            "cve_id": "CVE-2023-1111",
            "cvss_v3_score": 9.8,
            "epss_score": 0.5678,
            "epss_percentile": 0.95,
            "risk_score": 8.5,
            "published_date": "2023-02-01T00:00:00Z",
            "is_in_kev": True,
            "kev_date_added": "2023-02-02T00:00:00Z",
            "description": "High-risk CVE with alerts",
        }

        display_cve_with_alerts(cve_data)

        captured = capsys.readouterr()
        assert "CVE-2023-1111" in captured.out
        assert "9.8" in captured.out
        assert "8.5000" in captured.out  # Risk score formatting
        assert "High-risk CVE with alerts" in captured.out

    def test_display_cve_with_alerts_minimal(self, capsys):
        """Test CVE display with alerts with minimal data."""
        cve_data = {"cve_id": "CVE-2023-2222", "description": "Minimal alert CVE"}

        display_cve_with_alerts(cve_data)

        captured = capsys.readouterr()
        assert "CVE-2023-2222" in captured.out
        assert "Minimal alert CVE" in captured.out

    def test_display_cve_date_parsing_error(self, capsys):
        """Test CVE display with invalid date formats."""
        cve_data = {
            "cve_id": "CVE-2023-3333",
            "published_date": "invalid-date",
            "processed_at": "also-invalid",
            "kev_date_added": "bad-date",
            "patch_tuesday_date": "wrong-format",
            "description": "CVE with bad dates",
        }

        display_cve(cve_data)

        captured = capsys.readouterr()
        assert "CVE-2023-3333" in captured.out
        assert "CVE with bad dates" in captured.out

    def test_display_cve_integer_cvss_score(self, capsys):
        """Test CVE display with integer CVSS score."""
        cve_data = {
            "cve_id": "CVE-2023-4444",
            "cvss_v3_score": 8,  # Integer instead of float
            "description": "CVE with integer CVSS",
        }

        display_cve(cve_data)

        captured = capsys.readouterr()
        assert "CVE-2023-4444" in captured.out
        assert "8.0" in captured.out  # Should format as float

    def test_display_cve_kev_without_date(self, capsys):
        """Test CVE display with KEV status but no date."""
        cve_data = {
            "cve_id": "CVE-2023-5555",
            "is_in_kev": True,
            "kev_date_added": "",  # Empty date
            "description": "KEV without date",
        }

        display_cve(cve_data)

        captured = capsys.readouterr()
        assert "CVE-2023-5555" in captured.out
        assert "Yes" in captured.out  # Should show Yes even without date

    def test_display_cve_microsoft_info_present(self, capsys):
        """Test CVE display with Microsoft information."""
        cve_data = {
            "cve_id": "CVE-2023-6666",
            "microsoft_severity": "Important",
            "microsoft_product_family": "Office",
            "patch_tuesday_date": "2023-03-14T00:00:00Z",
            "description": "Microsoft CVE",
        }

        display_cve(cve_data)

        captured = capsys.readouterr()
        assert "CVE-2023-6666" in captured.out
        assert "Microsoft Severity: Important" in captured.out
        assert "Product: Office" in captured.out

    def test_display_cve_with_alerts_risk_score_none(self, capsys):
        """Test CVE display with alerts when risk score is None."""
        cve_data = {"cve_id": "CVE-2023-7777", "risk_score": None, "description": "CVE with no risk score"}

        display_cve_with_alerts(cve_data)

        captured = capsys.readouterr()
        assert "CVE-2023-7777" in captured.out
        assert "N/A" in captured.out  # Risk score should show N/A


class TestMainMvpImports:
    """Test that main_mvp imports and configurations work."""

    def test_logging_configuration(self):
        """Test that logging is configured properly."""
        # This tests the module-level logging configuration
        import logging

        logger = logging.getLogger("src.main_mvp")
        assert logger is not None

    @patch("src.utils.config.get_log_level")
    @patch("src.utils.config.get_log_file_name")
    def test_logging_setup_with_config(self, mock_log_file, mock_log_level):
        """Test logging setup with configuration values."""
        mock_log_level.return_value = "DEBUG"
        mock_log_file.return_value = "test.log"

        # Re-import to trigger configuration
        import importlib

        import src.main_mvp

        importlib.reload(src.main_mvp)

        # Verify mocks were called
        mock_log_level.assert_called()
        mock_log_file.assert_called()

    def test_module_imports_successfully(self):
        """Test that the main_mvp module can be imported successfully."""
        import src.main_mvp

        assert hasattr(src.main_mvp, "display_cve")
        assert hasattr(src.main_mvp, "display_cve_with_alerts")
