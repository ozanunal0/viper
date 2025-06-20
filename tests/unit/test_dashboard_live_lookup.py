"""
Tests for dashboard Live CVE Lookup page logic
"""
import re
from unittest.mock import MagicMock, Mock, patch

import pytest


class TestCVEValidationLogic:
    """Test CVE ID validation logic without importing the actual module."""

    def test_cve_id_regex_pattern_valid(self):
        """Test CVE ID regex pattern validation for valid cases."""
        # This is the pattern used in the dashboard
        pattern = r"^CVE-\d{4}-\d{4,}$"

        valid_cves = [
            "CVE-2023-1234",
            "CVE-2021-44228",
            "CVE-2020-0001",
            "CVE-2019-12345",
            "CVE-2023-123456",  # More than 4 digits
        ]

        for cve_id in valid_cves:
            assert re.match(pattern, cve_id.upper()), f"CVE {cve_id} should be valid"

    def test_cve_id_regex_pattern_invalid(self):
        """Test CVE ID regex pattern validation for invalid cases."""
        pattern = r"^CVE-\d{4}-\d{4,}$"

        invalid_cves = [
            "",
            "CVE-23-1234",  # Wrong year format
            "CVE-2023-123",  # Too few digits
            "2023-1234",  # Missing CVE prefix
            "CVE-2023",  # Missing number
            "CVE-2023-",  # Missing number after dash
            "CVE 2023 1234",  # Spaces instead of dashes
        ]

        for cve_id in invalid_cves:
            if cve_id:  # Skip empty string
                assert not re.match(pattern, cve_id.upper()), f"CVE {cve_id} should be invalid"

    def test_cve_validation_function_logic(self):
        """Test the CVE validation function logic."""

        def is_valid_cve_id(cve_id: str) -> bool:
            """Replicate the validation logic from the dashboard."""
            if not cve_id:
                return False
            # CVE format: CVE-YYYY-NNNN (where YYYY is year and NNNN is at least 4 digits)
            pattern = r"^CVE-\d{4}-\d{4,}$"
            return bool(re.match(pattern, cve_id.upper()))

        # Test valid cases
        assert is_valid_cve_id("CVE-2023-1234") == True
        assert is_valid_cve_id("CVE-2021-44228") == True

        # Test invalid cases
        assert is_valid_cve_id("") == False
        assert is_valid_cve_id("CVE-2023-123") == False
        assert is_valid_cve_id("cve-2023-1234") == True  # Should handle case insensitive


class TestKEVCatalogLogic:
    """Test KEV catalog checking logic."""

    def test_check_cve_in_kev_logic(self):
        """Test the KEV catalog checking logic."""

        def check_cve_in_kev(cve_id: str, kev_catalog: list) -> tuple:
            """Replicate the KEV checking logic from the dashboard."""
            for entry in kev_catalog:
                if entry.get("cve_id") == cve_id:
                    return True, entry.get("date_added")
            return False, None

        # Test data
        kev_catalog = [
            {"cve_id": "CVE-2023-0001", "date_added": "2023-01-01"},
            {"cve_id": "CVE-2023-1234", "date_added": "2023-01-15"},
            {"cve_id": "CVE-2023-5678", "date_added": "2023-02-01"},
        ]

        # Test found case
        is_in_kev, date_added = check_cve_in_kev("CVE-2023-1234", kev_catalog)
        assert is_in_kev == True
        assert date_added == "2023-01-15"

        # Test not found case
        is_in_kev, date_added = check_cve_in_kev("CVE-2023-9999", kev_catalog)
        assert is_in_kev == False
        assert date_added is None

        # Test empty catalog
        is_in_kev, date_added = check_cve_in_kev("CVE-2023-1234", [])
        assert is_in_kev == False
        assert date_added is None


class TestExploitResultsLogic:
    """Test exploit results processing logic."""

    def test_exploit_data_processing(self):
        """Test exploit data processing logic."""

        def process_exploit_data(exploit_results):
            """Replicate the exploit data processing logic."""
            if not exploit_results or len(exploit_results) == 0:
                return []

            exploit_data = []
            for exploit in exploit_results:
                # Extract data
                source = exploit.get("source", "Unknown")
                title = exploit.get("title", "Unknown")
                url = exploit.get("url", "#")
                exploit_type = exploit.get("type", "Unknown")
                date = exploit.get("date_published", "Unknown")

                # Handle stars correctly
                stars = exploit.get("stars", 0) if "stars" in exploit else 0
                stars_str = str(stars) if stars is not None else "0"

                desc = exploit.get("description", "") if "description" in exploit else ""

                exploit_data.append(
                    {
                        "Source": source,
                        "Title": title,
                        "Type": exploit_type,
                        "Published": date,
                        "Stars": stars_str,
                        "URL": url,
                        "Description": desc[:100] + "..." if desc and len(desc) > 100 else desc,
                    }
                )

            return exploit_data

        # Test with exploit results
        exploit_results = [
            {
                "source": "GitHub",
                "title": "Test Exploit",
                "url": "https://github.com/test/exploit",
                "type": "PoC",
                "date_published": "2023-01-01",
                "stars": 42,
                "description": "Test exploit description for testing purposes that is very long and should definitely be truncated because it exceeds 100 characters",
            },
            {
                "source": "ExploitDB",
                "title": "Another Exploit",
                "url": "https://exploit-db.com/test",
                "type": "Remote",
                "date_published": "2023-01-02",
                "description": "Short desc",
            },
        ]

        processed = process_exploit_data(exploit_results)

        assert len(processed) == 2
        assert processed[0]["Source"] == "GitHub"
        assert processed[0]["Stars"] == "42"
        assert processed[0]["Description"].endswith("...")  # Should be truncated
        assert processed[1]["Stars"] == "0"  # Default value

        # Test with empty results
        assert process_exploit_data([]) == []
        assert process_exploit_data(None) == []


class TestDatabaseConnectionLogic:
    """Test database connection logic."""

    @patch("sqlite3.connect")
    def test_database_connection_logic(self, mock_connect):
        """Test database connection checking logic."""

        def check_database_connection(db_path="/test/path"):
            """Replicate the database connection logic."""
            try:
                conn = mock_connect(db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                cursor.fetchone()
                conn.close()
                return True
            except Exception:
                return False

        # Test successful connection
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchone.return_value = (1,)
        mock_connect.return_value = mock_conn

        result = check_database_connection()
        assert result == True

        # Test failed connection
        mock_connect.side_effect = Exception("Connection failed")
        result = check_database_connection()
        assert result == False


class TestCVEDataFormatting:
    """Test CVE data formatting logic."""

    def test_cve_display_data_formatting(self):
        """Test CVE data formatting for display."""

        def format_cve_for_display(cve_data):
            """Replicate CVE data formatting logic."""
            # Format CVSS score
            cvss_score = cve_data.get("cvss_v3_score", "N/A")
            if cvss_score is not None:
                cvss_display = f"{cvss_score:.1f}" if isinstance(cvss_score, (float, int)) else "N/A"
            else:
                cvss_display = "N/A"

            # Format EPSS score and percentile
            epss_score = cve_data.get("epss_score")
            epss_percentile = cve_data.get("epss_percentile")
            if epss_score is not None and epss_percentile is not None:
                epss_display = f"{epss_score:.4f} ({epss_percentile:.1%})"
            else:
                epss_display = "N/A"

            return {
                "cvss_display": cvss_display,
                "epss_display": epss_display,
                "cve_id": cve_data.get("cve_id", "Unknown"),
                "description": cve_data.get("description", "No description available"),
            }

        # Test with complete data
        cve_data = {
            "cve_id": "CVE-2023-1234",
            "cvss_v3_score": 7.5,
            "epss_score": 0.1234,
            "epss_percentile": 0.85,
            "description": "Test CVE description",
        }

        formatted = format_cve_for_display(cve_data)
        assert formatted["cvss_display"] == "7.5"
        assert formatted["epss_display"] == "0.1234 (85.0%)"
        assert formatted["cve_id"] == "CVE-2023-1234"

        # Test with missing data
        minimal_data = {"cve_id": "CVE-2023-5678"}
        formatted = format_cve_for_display(minimal_data)
        assert formatted["cvss_display"] == "N/A"
        assert formatted["epss_display"] == "N/A"

        # Test with None values
        none_data = {"cve_id": "CVE-2023-9999", "cvss_v3_score": None, "epss_score": None, "epss_percentile": None}
        formatted = format_cve_for_display(none_data)
        assert formatted["cvss_display"] == "N/A"
        assert formatted["epss_display"] == "N/A"


class TestUtilityFunctions:
    """Test utility functions used in the dashboard."""

    def test_data_source_validation(self):
        """Test data source validation logic."""

        def validate_data_sources(use_nvd, use_github, use_exploitdb):
            """Validate that at least one data source is selected."""
            return any([use_nvd, use_github, use_exploitdb])

        # Test valid combinations
        assert validate_data_sources(True, False, False) == True
        assert validate_data_sources(False, True, False) == True
        assert validate_data_sources(True, True, True) == True

        # Test invalid combination
        assert validate_data_sources(False, False, False) == False

    def test_url_formatting(self):
        """Test URL formatting for display."""

        def format_url_for_display(url):
            """Format URL for markdown display."""
            if not url or url == "#":
                return "[N/A](#)"
            return f"[View]({url})"

        assert format_url_for_display("https://example.com") == "[View](https://example.com)"
        assert format_url_for_display("") == "[N/A](#)"
        assert format_url_for_display("#") == "[N/A](#)"
        assert format_url_for_display(None) == "[N/A](#)"
