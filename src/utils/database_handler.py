"""
Database handler module for the VIPER CTI feed application.
Handles storing and retrieving CVE data using SQLite.
"""
import json
import logging
import os
import sqlite3
import sys
import traceback
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from .config import get_db_file_name

# Initialize module logger
logger = logging.getLogger(__name__)


# Add direct file logging for critical database operations
def log_to_file(message):
    """Write directly to a debug log file for database operations"""
    try:
        with open("database_debug.log", "a") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} - {message}\n")
    except Exception as e:
        # If we can't log to file, at least try the normal logger
        logger.error(f"Failed to write to debug log: {e}")


def initialize_db():
    """
    Initializes the database by creating the necessary tables if they don't exist.
    Also ensures that the database directory exists.

    This function safely handles duplicate column errors that may occur when:
    1. Multiple instances try to add the same column simultaneously
    2. A column already exists but the script tries to add it again
    3. Database schema has evolved over time with new columns

    The function will continue execution even if it encounters duplicate column errors,
    logging a warning rather than failing completely.
    """
    db_path = get_db_file_name()

    # Ensure database directory exists
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        logger.debug(f"Creating database directory: {db_dir}")
        os.makedirs(db_dir, exist_ok=True)

    conn = None
    try:
        logger.debug(f"Initializing database at: {db_path}")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Create the cves table if it doesn't exist
        cursor.execute(
            """
        CREATE TABLE IF NOT EXISTS cves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT UNIQUE NOT NULL,
            description TEXT,
            cvss_v3_score REAL,
            published_date TEXT,
            gemini_priority TEXT,
            gemini_raw_response TEXT,
            processed_at TEXT
        )
        """
        )

        # Get existing columns
        cursor.execute("PRAGMA table_info(cves)")
        existing_columns = [column[1] for column in cursor.fetchall()]
        logger.debug(f"Existing columns: {existing_columns}")

        # Define all expected columns and their types
        column_definitions = {
            "risk_score": "REAL",
            "alerts": "TEXT",
            "is_in_kev": "INTEGER DEFAULT 0",
            "kev_date_added": "TEXT",
            "msrc_id": "TEXT",
            "microsoft_product_family": "TEXT",
            "microsoft_product_name": "TEXT",
            "microsoft_severity": "TEXT",
            "patch_tuesday_date": "TEXT",
            "has_public_exploit": "INTEGER DEFAULT 0",
            "exploit_references": "TEXT",
            "epss_score": "REAL",
            "epss_percentile": "REAL",
        }

        # Add any missing columns
        for column, column_type in column_definitions.items():
            if column not in existing_columns:
                try:
                    logger.debug(f"Adding {column} column to cves table")
                    cursor.execute(f"ALTER TABLE cves ADD COLUMN {column} {column_type}")
                except sqlite3.OperationalError as e:
                    # Check if this is a "duplicate column" error
                    if "duplicate column name" in str(e):
                        logger.warning(f"Column {column} appears to already exist, skipping: {str(e)}")
                    else:
                        # Log other errors but continue with other columns
                        logger.warning(f"Error adding column {column}: {str(e)}")

        # Create the threat_articles table if it doesn't exist
        cursor.execute(
            """
        CREATE TABLE IF NOT EXISTS threat_articles (
            article_id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id_association TEXT,
            source_query TEXT,
            url TEXT UNIQUE NOT NULL,
            title TEXT,
            published_date TEXT,
            content_text TEXT,
            content_highlights TEXT,
            fetched_date TEXT,
            gemini_summary TEXT,
            extracted_iocs TEXT,
            identified_ttps TEXT,
            mentioned_actors TEXT,
            FOREIGN KEY (cve_id_association) REFERENCES cves(cve_id)
        )
        """
        )

        # Get existing columns for threat_articles table
        cursor.execute("PRAGMA table_info(threat_articles)")
        existing_articles_columns = [column[1] for column in cursor.fetchall()]
        logger.debug(f"Existing threat_articles columns: {existing_articles_columns}")

        # Define expected columns for threat_articles table
        articles_column_definitions = {
            "author": "TEXT",
            "score": "REAL",
        }

        # Add any missing columns to threat_articles table
        for column, column_type in articles_column_definitions.items():
            if column not in existing_articles_columns:
                try:
                    logger.debug(f"Adding {column} column to threat_articles table")
                    cursor.execute(f"ALTER TABLE threat_articles ADD COLUMN {column} {column_type}")
                except sqlite3.OperationalError as e:
                    # Check if this is a "duplicate column" error
                    if "duplicate column name" in str(e):
                        logger.warning(
                            f"Column {column} appears to already exist in threat_articles, skipping: {str(e)}"
                        )
                    else:
                        # Log other errors but continue with other columns
                        logger.warning(f"Error adding column {column} to threat_articles: {str(e)}")

        conn.commit()
        logger.debug("Database initialized successfully")
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {str(e)}")
        logger.error(traceback.format_exc())
        raise
    finally:
        if conn:
            conn.close()


def store_cves(cve_list):
    """
    Stores a list of CVEs in the database, skipping duplicates.

    Args:
        cve_list (list): A list of dictionaries containing CVE data.

    Returns:
        int: Number of CVEs successfully stored.
    """
    if not cve_list:
        logger.warning("No CVEs provided to store")
        return 0

    conn = None
    try:
        conn = sqlite3.connect(get_db_file_name())
        cursor = conn.cursor()

        inserted_count = 0
        for cve in cve_list:
            try:
                cursor.execute(
                    """
                INSERT OR IGNORE INTO cves (cve_id, description, cvss_v3_score, published_date)
                VALUES (?, ?, ?, ?)
                """,
                    (
                        cve.get("cve_id"),
                        cve.get("description"),
                        cve.get("cvss_v3_score"),
                        cve.get("published_date"),
                    ),
                )

                if cursor.rowcount > 0:
                    inserted_count += 1
            except sqlite3.Error as e:
                logger.error(f"Error storing CVE {cve.get('cve_id')}: {str(e)}")

        conn.commit()
        logger.debug(f"Successfully stored {inserted_count} new CVEs")
        return inserted_count

    except sqlite3.Error as e:
        logger.error(f"Database error while storing CVEs: {str(e)}")
        return 0
    finally:
        if conn:
            conn.close()


def get_unprocessed_cves():
    """
    Fetches CVEs that have not been processed by Gemini.

    Returns:
        list: A list of dictionaries containing unprocessed CVE data.
    """
    conn = None
    try:
        conn = sqlite3.connect(get_db_file_name())
        conn.row_factory = sqlite3.Row  # This enables column access by name
        cursor = conn.cursor()

        cursor.execute(
            """
        SELECT id, cve_id, description, cvss_v3_score, published_date, epss_score, epss_percentile,
               is_in_kev, kev_date_added, microsoft_severity, microsoft_product_family,
               microsoft_product_name, patch_tuesday_date, has_public_exploit, exploit_references
        FROM cves
        WHERE gemini_priority IS NULL
        """
        )

        rows = cursor.fetchall()
        unprocessed_cves = []
        for row in rows:
            # Parse exploit_references JSON if available
            exploit_refs = None
            if row["exploit_references"]:
                try:
                    exploit_refs = json.loads(row["exploit_references"])
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON in exploit_references for {row['cve_id']}")

            unprocessed_cves.append(
                {
                    "id": row["id"],
                    "cve_id": row["cve_id"],
                    "description": row["description"],
                    "cvss_v3_score": row["cvss_v3_score"],
                    "published_date": row["published_date"],
                    "epss_score": row["epss_score"],
                    "epss_percentile": row["epss_percentile"],
                    "is_in_kev": bool(row["is_in_kev"]),
                    "kev_date_added": row["kev_date_added"],
                    "microsoft_severity": row["microsoft_severity"],
                    "microsoft_product_family": row["microsoft_product_family"],
                    "microsoft_product_name": row["microsoft_product_name"],
                    "patch_tuesday_date": row["patch_tuesday_date"],
                    "has_public_exploit": bool(row["has_public_exploit"]),
                    "exploit_references": exploit_refs,
                }
            )

        logger.debug(f"Found {len(unprocessed_cves)} unprocessed CVEs")
        return unprocessed_cves

    except sqlite3.Error as e:
        logger.error(f"Database error while fetching unprocessed CVEs: {str(e)}")
        return []
    finally:
        if conn:
            conn.close()


def get_cves_missing_epss():
    """
    Fetches CVEs that are missing EPSS score data.

    Returns:
        list: A list of dictionaries containing CVE data without EPSS scores.
    """
    conn = None
    try:
        conn = sqlite3.connect(get_db_file_name())
        conn.row_factory = sqlite3.Row  # This enables column access by name
        cursor = conn.cursor()

        cursor.execute(
            """
        SELECT id, cve_id, description, cvss_v3_score, published_date
        FROM cves
        WHERE epss_score IS NULL
        """
        )

        rows = cursor.fetchall()
        missing_epss_cves = []
        for row in rows:
            missing_epss_cves.append(
                {
                    "id": row["id"],
                    "cve_id": row["cve_id"],
                    "description": row["description"],
                    "cvss_v3_score": row["cvss_v3_score"],
                    "published_date": row["published_date"],
                }
            )

        logger.debug(f"Found {len(missing_epss_cves)} CVEs missing EPSS data")
        return missing_epss_cves

    except sqlite3.Error as e:
        logger.error(f"Database error while fetching CVEs missing EPSS data: {str(e)}")
        return []
    finally:
        if conn:
            conn.close()


def update_cve_priority(cve_id, priority, raw_response=None):
    """
    Updates a CVE's priority as determined by Gemini.

    Args:
        cve_id (str): The CVE ID to update.
        priority (str): The priority assigned by Gemini (HIGH, MEDIUM, LOW, or ERROR_ANALYZING).
        raw_response (str, optional): The raw response from Gemini.

    Returns:
        bool: True if the update was successful, False otherwise.
    """
    conn = None
    try:
        conn = sqlite3.connect(get_db_file_name())
        cursor = conn.cursor()

        current_time = datetime.now(datetime.UTC).isoformat()

        cursor.execute(
            """
        UPDATE cves
        SET gemini_priority = ?, gemini_raw_response = ?, processed_at = ?
        WHERE cve_id = ?
        """,
            (priority, raw_response, current_time, cve_id),
        )

        conn.commit()

        if cursor.rowcount > 0:
            logger.debug(f"Updated CVE {cve_id} with priority: {priority}")
            return True
        else:
            logger.warning(f"No CVE found with ID {cve_id}")
            return False

    except sqlite3.Error as e:
        logger.error(f"Database error while updating CVE priority: {str(e)}")
        return False
    finally:
        if conn:
            conn.close()


def update_cve_epss_data(cve_id, epss_score, epss_percentile):
    """
    Updates a CVE's EPSS score and percentile.

    Args:
        cve_id (str): The CVE ID to update.
        epss_score (float): The EPSS score (probability of exploitation).
        epss_percentile (float): The EPSS percentile.

    Returns:
        bool: True if the update was successful, False otherwise.
    """
    conn = None
    try:
        conn = sqlite3.connect(get_db_file_name())
        cursor = conn.cursor()

        cursor.execute(
            """
        UPDATE cves
        SET epss_score = ?, epss_percentile = ?
        WHERE cve_id = ?
        """,
            (epss_score, epss_percentile, cve_id),
        )

        conn.commit()

        if cursor.rowcount > 0:
            logger.debug(f"Updated CVE {cve_id} with EPSS score: {epss_score:.4f}, percentile: {epss_percentile:.4f}")
            return True
        else:
            logger.warning(f"No CVE found with ID {cve_id} for EPSS update")
            return False

    except sqlite3.Error as e:
        logger.error(f"Database error while updating CVE EPSS data: {str(e)}")
        return False
    finally:
        if conn:
            conn.close()


def get_high_medium_priority_cves():
    """
    Fetches CVEs with HIGH or MEDIUM priority as determined by Gemini.

    Returns:
        list: A list of dictionaries containing high and medium priority CVE data.
    """
    conn = None
    try:
        conn = sqlite3.connect(get_db_file_name())
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            """
        SELECT cve_id, description, cvss_v3_score, published_date, gemini_priority, processed_at,
               epss_score, epss_percentile, is_in_kev, kev_date_added, risk_score
        FROM cves
        WHERE gemini_priority IN ('HIGH', 'MEDIUM')
        ORDER BY
            CASE
                WHEN gemini_priority = 'HIGH' THEN 1
                WHEN gemini_priority = 'MEDIUM' THEN 2
                ELSE 3
            END,
            is_in_kev DESC,
            epss_score DESC NULLS LAST,
            cvss_v3_score DESC
        """
        )

        rows = cursor.fetchall()
        priority_cves = []
        for row in rows:
            priority_cves.append(
                {
                    "cve_id": row["cve_id"],
                    "description": row["description"],
                    "cvss_v3_score": row["cvss_v3_score"],
                    "published_date": row["published_date"],
                    "gemini_priority": row["gemini_priority"],
                    "processed_at": row["processed_at"],
                    "epss_score": row["epss_score"],
                    "epss_percentile": row["epss_percentile"],
                    "is_in_kev": bool(row["is_in_kev"]),
                    "kev_date_added": row["kev_date_added"],
                    "risk_score": row["risk_score"],
                }
            )

        logger.debug(f"Found {len(priority_cves)} HIGH/MEDIUM priority CVEs")
        return priority_cves

    except sqlite3.Error as e:
        logger.error(f"Database error while fetching priority CVEs: {str(e)}")
        return []
    finally:
        if conn:
            conn.close()


def update_cve_risk_data(cve_id, risk_score, alerts):
    """
    Updates a CVE's risk score and alerts.

    Args:
        cve_id (str): The CVE ID to update.
        risk_score (float): The calculated risk score (0-1).
        alerts (list): List of alert messages.

    Returns:
        bool: True if the update was successful, False otherwise.
    """
    conn = None
    try:
        conn = sqlite3.connect(get_db_file_name())
        cursor = conn.cursor()

        # Convert alerts list to JSON string
        alerts_json = json.dumps(alerts) if alerts else None

        cursor.execute(
            """
        UPDATE cves
        SET risk_score = ?, alerts = ?
        WHERE cve_id = ?
        """,
            (risk_score, alerts_json, cve_id),
        )

        conn.commit()

        if cursor.rowcount > 0:
            logger.debug(
                f"Updated CVE {cve_id} with risk score: {risk_score:.4f}, alerts: {len(alerts) if alerts else 0}"
            )
            return True
        else:
            logger.warning(f"No CVE found with ID {cve_id} for risk data update")
            return False

    except sqlite3.Error as e:
        logger.error(f"Database error while updating CVE risk data: {str(e)}")
        return False
    finally:
        if conn:
            conn.close()


def get_cves_with_alerts():
    """
    Fetches CVEs that have alerts.

    Returns:
        list: A list of dictionaries containing CVE data with alerts.
    """
    conn = None
    try:
        conn = sqlite3.connect(get_db_file_name())
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            """
        SELECT cve_id, description, cvss_v3_score, published_date, gemini_priority,
               epss_score, epss_percentile, risk_score, alerts, is_in_kev, kev_date_added
        FROM cves
        WHERE alerts IS NOT NULL
        ORDER BY risk_score DESC
        """
        )

        rows = cursor.fetchall()
        cves_with_alerts = []
        for row in rows:
            # Parse the JSON alerts
            alerts_json = row["alerts"]
            if alerts_json:
                try:
                    alerts = json.loads(alerts_json)
                except json.JSONDecodeError:
                    alerts = []

            cves_with_alerts.append(
                {
                    "cve_id": row["cve_id"],
                    "description": row["description"],
                    "cvss_v3_score": row["cvss_v3_score"],
                    "published_date": row["published_date"],
                    "gemini_priority": row["gemini_priority"],
                    "epss_score": row["epss_score"],
                    "epss_percentile": row["epss_percentile"],
                    "risk_score": row["risk_score"],
                    "alerts": alerts,
                    "is_in_kev": bool(row["is_in_kev"]),
                    "kev_date_added": row["kev_date_added"],
                }
            )

        logger.debug(f"Found {len(cves_with_alerts)} CVEs with alerts")
        return cves_with_alerts

    except sqlite3.Error as e:
        logger.error(f"Database error while fetching CVEs with alerts: {str(e)}")
        return []
    finally:
        if conn:
            conn.close()


def update_cve_kev_status(cve_id: str, is_in_kev: bool, kev_date_added: Optional[str] = None) -> bool:
    """
    Updates a CVE's CISA KEV status.

    Args:
        cve_id (str): The CVE ID to update.
        is_in_kev (bool): Whether the CVE is in the CISA KEV catalog.
        kev_date_added (str, optional): The date the CVE was added to the KEV catalog.

    Returns:
        bool: True if the update was successful, False otherwise.
    """
    conn = None
    try:
        conn = sqlite3.connect(get_db_file_name())
        cursor = conn.cursor()

        # Convert boolean to integer for SQLite
        is_in_kev_int = 1 if is_in_kev else 0

        cursor.execute(
            """
        UPDATE cves
        SET is_in_kev = ?, kev_date_added = ?
        WHERE cve_id = ?
        """,
            (is_in_kev_int, kev_date_added, cve_id),
        )

        conn.commit()

        if cursor.rowcount > 0:
            logger.debug(f"Updated CVE {cve_id} with KEV status: {is_in_kev}, date added: {kev_date_added}")
            return True
        else:
            logger.warning(f"No CVE found with ID {cve_id} for KEV status update")
            return False

    except sqlite3.Error as e:
        logger.error(f"Database error while updating CVE KEV status: {str(e)}")
        return False
    finally:
        if conn:
            conn.close()


def get_all_cve_ids_from_db() -> List[str]:
    """
    Fetches all unique CVE IDs from the database.

    Returns:
        List[str]: A list of all CVE IDs in the database.
    """
    conn = None
    try:
        conn = sqlite3.connect(get_db_file_name())
        cursor = conn.cursor()

        cursor.execute("SELECT cve_id FROM cves")

        # Extract the first element of each row (the CVE ID)
        cve_ids = [row[0] for row in cursor.fetchall()]

        logger.debug(f"Found {len(cve_ids)} unique CVE IDs in the database")
        return cve_ids

    except sqlite3.Error as e:
        logger.error(f"Database error while fetching all CVE IDs: {str(e)}")
        return []
    finally:
        if conn:
            conn.close()


def get_all_cves_with_details() -> List[Dict[str, Any]]:
    """
    Fetches all CVEs with their complete details for the dashboard.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries containing all CVE data.
    """
    conn = None
    try:
        conn = sqlite3.connect(get_db_file_name())
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            """
        SELECT cve_id, description, cvss_v3_score, published_date, gemini_priority,
               processed_at, epss_score, epss_percentile, is_in_kev, kev_date_added,
               risk_score, alerts, msrc_id, microsoft_product_family, microsoft_product_name,
               microsoft_severity, patch_tuesday_date, has_public_exploit, exploit_references
        FROM cves
        WHERE gemini_priority IS NOT NULL
        ORDER BY
            CASE
                WHEN gemini_priority = 'HIGH' THEN 1
                WHEN gemini_priority = 'MEDIUM' THEN 2
                ELSE 3
            END,
            risk_score DESC NULLS LAST,
            is_in_kev DESC,
            epss_score DESC NULLS LAST,
            cvss_v3_score DESC
        """
        )

        rows = cursor.fetchall()
        all_cves = []
        for row in rows:
            # Parse the JSON alerts
            alerts_json = row["alerts"]
            if alerts_json:
                try:
                    alerts = json.loads(alerts_json)
                except json.JSONDecodeError:
                    alerts = []
            else:
                alerts = []

            all_cves.append(
                {
                    "cve_id": row["cve_id"],
                    "description": row["description"],
                    "cvss_v3_score": row["cvss_v3_score"],
                    "published_date": row["published_date"],
                    "gemini_priority": row["gemini_priority"],
                    "processed_at": row["processed_at"],
                    "epss_score": row["epss_score"],
                    "epss_percentile": row["epss_percentile"],
                    "is_in_kev": bool(row["is_in_kev"]),
                    "kev_date_added": row["kev_date_added"],
                    "risk_score": row["risk_score"],
                    "alerts": alerts,
                    "msrc_id": row["msrc_id"],
                    "microsoft_product_family": row["microsoft_product_family"],
                    "microsoft_product_name": row["microsoft_product_name"],
                    "microsoft_severity": row["microsoft_severity"],
                    "patch_tuesday_date": row["patch_tuesday_date"],
                    "has_public_exploit": bool(row["has_public_exploit"]),
                    "exploit_references": row["exploit_references"],
                }
            )

        logger.debug(f"Fetched {len(all_cves)} CVEs with details for dashboard")
        return all_cves

    except sqlite3.Error as e:
        logger.error(f"Database error while fetching CVEs with details: {str(e)}")
        return []
    finally:
        if conn:
            conn.close()


def get_filtered_cves(
    date_start: Optional[str] = None,
    date_end: Optional[str] = None,
    priorities: Optional[List[str]] = None,
    cvss_min: Optional[float] = None,
    cvss_max: Optional[float] = None,
    epss_min: Optional[float] = None,
    epss_max: Optional[float] = None,
    is_in_kev: Optional[bool] = None,
    has_public_exploit: Optional[bool] = None,
    keyword: Optional[str] = None,
    microsoft_severity: Optional[str] = None,
    microsoft_product: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Fetches CVEs with filtering options applied at the database level.

    Args:
        date_start (str, optional): Start date for published_date filter (ISO format).
        date_end (str, optional): End date for published_date filter (ISO format).
        priorities (List[str], optional): List of Gemini priorities to include (HIGH, MEDIUM, LOW).
        cvss_min (float, optional): Minimum CVSS score.
        cvss_max (float, optional): Maximum CVSS score.
        epss_min (float, optional): Minimum EPSS score.
        epss_max (float, optional): Maximum EPSS score.
        is_in_kev (bool, optional): Filter for CVEs in the CISA KEV catalog.
        has_public_exploit (bool, optional): Filter for CVEs with public exploits.
        keyword (str, optional): Keyword to search in the description.
        microsoft_severity (str, optional): Filter by Microsoft severity rating.
        microsoft_product (str, optional): Filter by Microsoft product family.

    Returns:
        List[Dict[str, Any]]: Filtered list of CVE dictionaries.
    """
    conn = None
    try:
        conn = sqlite3.connect(get_db_file_name())
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Build the SQL query with filter conditions
        query = """
        SELECT cve_id, description, cvss_v3_score, published_date, gemini_priority,
               processed_at, epss_score, epss_percentile, is_in_kev, kev_date_added,
               risk_score, alerts, msrc_id, microsoft_product_family, microsoft_product_name,
               microsoft_severity, patch_tuesday_date, has_public_exploit, exploit_references
        FROM cves
        WHERE 1=1
        """
        params = []

        # Apply filters
        if priorities:
            placeholders = ", ".join(["?" for _ in priorities])
            query += f" AND gemini_priority IN ({placeholders})"
            params.extend(priorities)
        else:
            query += " AND gemini_priority IS NOT NULL"

        if date_start:
            query += " AND published_date >= ?"
            params.append(date_start)

        if date_end:
            query += " AND published_date <= ?"
            params.append(date_end)

        if cvss_min is not None:
            query += " AND (cvss_v3_score >= ? OR cvss_v3_score IS NULL)"
            params.append(cvss_min)

        if cvss_max is not None:
            query += " AND (cvss_v3_score <= ? OR cvss_v3_score IS NULL)"
            params.append(cvss_max)

        if epss_min is not None:
            query += " AND (epss_score >= ? OR epss_score IS NULL)"
            params.append(epss_min)

        if epss_max is not None:
            query += " AND (epss_score <= ? OR epss_score IS NULL)"
            params.append(epss_max)

        if is_in_kev is not None:
            query += " AND is_in_kev = ?"
            params.append(1 if is_in_kev else 0)

        if has_public_exploit is not None:
            query += " AND has_public_exploit = ?"
            params.append(1 if has_public_exploit else 0)

        if keyword:
            query += " AND description LIKE ?"
            params.append(f"%{keyword}%")

        # Microsoft-specific filters
        if microsoft_severity:
            query += " AND microsoft_severity = ?"
            params.append(microsoft_severity)

        if microsoft_product:
            query += " AND microsoft_product_family LIKE ?"
            params.append(f"%{microsoft_product}%")

        # Add ordering
        query += """
        ORDER BY
            CASE
                WHEN gemini_priority = 'HIGH' THEN 1
                WHEN gemini_priority = 'MEDIUM' THEN 2
                ELSE 3
            END,
            risk_score DESC NULLS LAST,
            is_in_kev DESC,
            epss_score DESC NULLS LAST,
            cvss_v3_score DESC
        """

        cursor.execute(query, params)

        rows = cursor.fetchall()
        filtered_cves = []
        for row in rows:
            # Parse the JSON alerts
            alerts_json = row["alerts"]
            if alerts_json:
                try:
                    alerts = json.loads(alerts_json)
                except json.JSONDecodeError:
                    alerts = []
            else:
                alerts = []

            filtered_cves.append(
                {
                    "cve_id": row["cve_id"],
                    "description": row["description"],
                    "cvss_v3_score": row["cvss_v3_score"],
                    "published_date": row["published_date"],
                    "gemini_priority": row["gemini_priority"],
                    "processed_at": row["processed_at"],
                    "epss_score": row["epss_score"],
                    "epss_percentile": row["epss_percentile"],
                    "is_in_kev": bool(row["is_in_kev"]),
                    "kev_date_added": row["kev_date_added"],
                    "risk_score": row["risk_score"],
                    "alerts": alerts,
                    "msrc_id": row["msrc_id"],
                    "microsoft_product_family": row["microsoft_product_family"],
                    "microsoft_product_name": row["microsoft_product_name"],
                    "microsoft_severity": row["microsoft_severity"],
                    "patch_tuesday_date": row["patch_tuesday_date"],
                    "has_public_exploit": bool(row["has_public_exploit"]),
                    "exploit_references": row["exploit_references"],
                }
            )

        logger.debug(f"Fetched {len(filtered_cves)} CVEs with applied filters")
        return filtered_cves

    except sqlite3.Error as e:
        logger.error(f"Database error while fetching filtered CVEs: {str(e)}")
        return []
    finally:
        if conn:
            conn.close()


def update_cve_microsoft_data(
    cve_id: str,
    msrc_id: Optional[str] = None,
    product_family: Optional[str] = None,
    product_name: Optional[str] = None,
    severity: Optional[str] = None,
    pt_date: Optional[str] = None,
) -> bool:
    """
    Updates a CVE with Microsoft-specific data.

    Args:
        cve_id (str): The CVE ID to update.
        msrc_id (str, optional): Microsoft Security Response Center document ID.
        product_family (str, optional): Microsoft product family affected.
        product_name (str, optional): Specific Microsoft product affected.
        severity (str, optional): Microsoft severity rating.
        pt_date (str, optional): Patch Tuesday date (ISO format).

    Returns:
        bool: True if the update was successful, False otherwise.
    """
    conn = None
    try:
        # Ensure all parameters are strings or None
        msrc_id_str = str(msrc_id) if msrc_id is not None else None
        product_family_str = str(product_family) if product_family is not None else None
        product_name_str = str(product_name) if product_name is not None else None
        severity_str = str(severity) if severity is not None else None
        pt_date_str = str(pt_date) if pt_date is not None else None

        conn = sqlite3.connect(get_db_file_name())
        cursor = conn.cursor()

        cursor.execute(
            """
        UPDATE cves
        SET msrc_id = ?,
            microsoft_product_family = ?,
            microsoft_product_name = ?,
            microsoft_severity = ?,
            patch_tuesday_date = ?
        WHERE cve_id = ?
        """,
            (msrc_id_str, product_family_str, product_name_str, severity_str, pt_date_str, cve_id),
        )

        conn.commit()

        if cursor.rowcount > 0:
            logger.debug(
                f"Updated CVE {cve_id} with Microsoft data (severity: {severity_str}, product: {product_family_str})"
            )
            return True
        else:
            logger.warning(f"No CVE found with ID {cve_id} for Microsoft data update")
            return False

    except sqlite3.Error as e:
        logger.error(f"Database error while updating CVE Microsoft data: {str(e)}")
        return False
    finally:
        if conn:
            conn.close()


def get_cve_details(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves all details for a specific CVE from the database.

    Args:
        cve_id (str): The CVE ID to lookup (e.g. 'CVE-2023-12345')

    Returns:
        Optional[Dict[str, Any]]: A dictionary containing all CVE details, or None if not found
    """
    conn = None
    try:
        conn = sqlite3.connect(get_db_file_name())
        conn.row_factory = sqlite3.Row  # This enables column access by name
        cursor = conn.cursor()

        cursor.execute(
            """
        SELECT cve_id, description, cvss_v3_score, published_date, gemini_priority,
               processed_at, epss_score, epss_percentile, is_in_kev, kev_date_added,
               risk_score, alerts, msrc_id, microsoft_product_family, microsoft_product_name,
               microsoft_severity, patch_tuesday_date, has_public_exploit, exploit_references,
               gemini_raw_response
        FROM cves
        WHERE cve_id = ?
        """,
            (cve_id,),
        )

        row = cursor.fetchone()

        if not row:
            logger.debug(f"No CVE found with ID {cve_id}")
            return None

        # Parse the JSON alerts
        alerts_json = row["alerts"]
        if alerts_json:
            try:
                alerts = json.loads(alerts_json)
            except json.JSONDecodeError:
                alerts = []
        else:
            alerts = []

        # Extract references if stored as JSON
        references = []
        try:
            gemini_raw_response = row["gemini_raw_response"] if row["gemini_raw_response"] else None
        except (KeyError, IndexError):
            gemini_raw_response = None

        if gemini_raw_response:
            try:
                # Try to extract references from the Gemini response
                gemini_data = json.loads(gemini_raw_response)
                if "references" in gemini_data:
                    references = gemini_data["references"]
            except (json.JSONDecodeError, TypeError):
                # If JSON parsing fails, ignore references
                pass

        # Extract CPE entries if stored in Gemini response
        cpe_entries = []
        if gemini_raw_response:
            try:
                gemini_data = json.loads(gemini_raw_response)
                if "cpe_entries" in gemini_data:
                    cpe_entries = gemini_data["cpe_entries"]
            except (json.JSONDecodeError, TypeError):
                pass

        # Convert to dictionary
        cve_data = {
            "cve_id": row["cve_id"],
            "description": row["description"],
            "cvss_v3_score": row["cvss_v3_score"],
            "published_date": row["published_date"],
            "gemini_priority": row["gemini_priority"],
            "processed_at": row["processed_at"],
            "epss_score": row["epss_score"],
            "epss_percentile": row["epss_percentile"],
            "is_in_kev": bool(row["is_in_kev"]),
            "kev_date_added": row["kev_date_added"],
            "risk_score": row["risk_score"],
            "alerts": alerts,
            "msrc_id": row["msrc_id"],
            "microsoft_product_family": row["microsoft_product_family"],
            "microsoft_product_name": row["microsoft_product_name"],
            "microsoft_severity": row["microsoft_severity"],
            "patch_tuesday_date": row["patch_tuesday_date"],
            "has_public_exploit": bool(row["has_public_exploit"]),
            "exploit_references": references,
            "cpe_entries": cpe_entries,
        }

        logger.debug(f"Found CVE details for {cve_id}")
        return cve_data

    except sqlite3.Error as e:
        logger.error(f"Database error while fetching CVE details: {str(e)}")
        return None
    finally:
        if conn:
            conn.close()


def store_or_update_cve(cve_data):
    log_to_file(
        f"[DB_HANDLER_SAVE] store_or_update_cve called for {cve_data.get('cve_id')}. Processed_at in data: {cve_data.get('processed_at')}"
    )
    """
    Stores a single CVE in the database, or updates it if it already exists.
    Unlike store_cves which uses INSERT OR IGNORE, this function will update
    existing records with new debugrmation.

    Args:
        cve_data (dict): A dictionary containing CVE data.

    Returns:
        bool: True if the operation was successful, False otherwise.
    """
    if not cve_data or "cve_id" not in cve_data:
        logger.warning("Invalid CVE data provided")
        log_to_file("Invalid CVE data provided - missing cve_id")
        return False

    cve_id = cve_data.get("cve_id")
    logger.debug(f"store_or_update_cve called for {cve_id}")
    log_to_file(f"store_or_update_cve called for {cve_id}")

    # Initialize database if not already done
    try:
        initialize_db()
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        log_to_file(f"Database initialization failed: {str(e)}")
        return False

    conn = None
    try:
        # Get absolute database path
        db_path = get_db_file_name()
        if not os.path.isabs(db_path):
            abs_db_path = os.path.abspath(db_path)
        else:
            abs_db_path = db_path

        logger.debug(f"Database absolute path: {abs_db_path}")
        log_to_file(f"Database path: {abs_db_path}")

        # Check if database directory exists
        db_dir = os.path.dirname(abs_db_path)
        if db_dir and not os.path.exists(db_dir):
            log_to_file(f"Creating missing database directory: {db_dir}")
            os.makedirs(db_dir, exist_ok=True)

        # Test file permissions
        if os.path.exists(abs_db_path):
            try:
                # Test read permissions
                with open(abs_db_path, "rb"):
                    pass
                # Test write permissions by opening in append mode
                with open(abs_db_path, "ab"):
                    pass
                log_to_file(f"Database file permissions verified: {abs_db_path}")
            except (IOError, PermissionError) as e:
                log_to_file(f"Permission error on database file: {str(e)}")
                logger.error(f"Permission error on database file: {str(e)}")
                return False

        # Connect to database with timeout and isolation level settings
        conn = sqlite3.connect(abs_db_path, timeout=30.0)
        # Set WAL mode for better concurrent access
        conn.execute("PRAGMA journal_mode=WAL")
        # Set immediate locking for consistency but not exclusive
        conn.execute("PRAGMA locking_mode=NORMAL")
        cursor = conn.cursor()

        # Check if the CVE already exists
        cursor.execute("SELECT 1 FROM cves WHERE cve_id = ?", (cve_id,))
        exists = cursor.fetchone() is not None
        logger.debug(f"CVE {cve_id} exists in database: {exists}")
        log_to_file(f"CVE exists in DB: {exists}")

        if exists:
            # Update existing CVE
            logger.debug(f"Updating existing CVE {cve_id}")

            # Build the update query based on available data
            update_fields = []
            update_values = []

            if "description" in cve_data and cve_data["description"]:
                update_fields.append("description = ?")
                update_values.append(cve_data["description"])

            if "cvss_v3_score" in cve_data and cve_data["cvss_v3_score"] is not None:
                update_fields.append("cvss_v3_score = ?")
                update_values.append(cve_data["cvss_v3_score"])

            if "published_date" in cve_data and cve_data["published_date"]:
                update_fields.append("published_date = ?")
                update_values.append(cve_data["published_date"])

            if "gemini_priority" in cve_data and cve_data["gemini_priority"]:
                update_fields.append("gemini_priority = ?")
                update_values.append(cve_data["gemini_priority"])

            if "gemini_raw_response" in cve_data and cve_data["gemini_raw_response"]:
                update_fields.append("gemini_raw_response = ?")
                update_values.append(cve_data["gemini_raw_response"])

            if "processed_at" in cve_data and cve_data["processed_at"]:
                update_fields.append("processed_at = ?")
                update_values.append(cve_data["processed_at"])
            else:
                # Add current timestamp
                update_fields.append("processed_at = ?")
                update_values.append(datetime.now(datetime.UTC).isoformat())

            if "epss_score" in cve_data and cve_data["epss_score"] is not None:
                update_fields.append("epss_score = ?")
                update_values.append(cve_data["epss_score"])

            if "epss_percentile" in cve_data and cve_data["epss_percentile"] is not None:
                update_fields.append("epss_percentile = ?")
                update_values.append(cve_data["epss_percentile"])

            if "is_in_kev" in cve_data:
                update_fields.append("is_in_kev = ?")
                update_values.append(1 if cve_data["is_in_kev"] else 0)

            if "kev_date_added" in cve_data and cve_data["kev_date_added"]:
                update_fields.append("kev_date_added = ?")
                update_values.append(cve_data["kev_date_added"])

            if "risk_score" in cve_data and cve_data["risk_score"] is not None:
                update_fields.append("risk_score = ?")
                update_values.append(cve_data["risk_score"])

            if "alerts" in cve_data and cve_data["alerts"]:
                update_fields.append("alerts = ?")
                try:
                    update_values.append(json.dumps(cve_data["alerts"]))
                except Exception as e:
                    log_to_file(f"Error serializing alerts to JSON: {str(e)}")
                    # Use a string representation as fallback
                    update_values.append(str(cve_data["alerts"]))

            if "msrc_id" in cve_data and cve_data["msrc_id"]:
                update_fields.append("msrc_id = ?")
                update_values.append(cve_data["msrc_id"])

            if "microsoft_product_family" in cve_data and cve_data["microsoft_product_family"]:
                update_fields.append("microsoft_product_family = ?")
                update_values.append(cve_data["microsoft_product_family"])

            if "microsoft_product_name" in cve_data and cve_data["microsoft_product_name"]:
                update_fields.append("microsoft_product_name = ?")
                update_values.append(cve_data["microsoft_product_name"])

            if "microsoft_severity" in cve_data and cve_data["microsoft_severity"]:
                update_fields.append("microsoft_severity = ?")
                update_values.append(cve_data["microsoft_severity"])

            if "patch_tuesday_date" in cve_data and cve_data["patch_tuesday_date"]:
                update_fields.append("patch_tuesday_date = ?")
                update_values.append(cve_data["patch_tuesday_date"])

            if "has_public_exploit" in cve_data:
                update_fields.append("has_public_exploit = ?")
                update_values.append(1 if cve_data["has_public_exploit"] else 0)

            if "exploit_references" in cve_data:
                update_fields.append("exploit_references = ?")
                try:
                    update_values.append(json.dumps(cve_data["exploit_references"]))
                except Exception as e:
                    log_to_file(f"Error serializing exploit_references to JSON: {str(e)}")
                    # Use a string representation as fallback
                    update_values.append(str(cve_data["exploit_references"]))

            if not update_fields:
                logger.warning(f"No fields to update for CVE {cve_id}")
                return True  # No error, just nothing to update

            # Construct and execute update query
            update_query = f"UPDATE cves SET {', '.join(update_fields)} WHERE cve_id = ?"
            update_values.append(cve_id)

            logger.debug(f"Executing query: {update_query} with params: {update_values}")
            log_to_file(f"Executing UPDATE for {cve_id}")

            cursor.execute(update_query, update_values)
            affected_rows = cursor.rowcount
            log_to_file(f"Update affected {affected_rows} rows")
        else:
            # Insert new CVE
            logger.debug(f"Inserting new CVE {cve_id}")
            log_to_file(f"Inserting new CVE {cve_id}")

            # Prepare values for comprehensive insert
            fields = ["cve_id", "description", "cvss_v3_score", "published_date"]
            values = [
                cve_id,
                cve_data.get("description"),
                cve_data.get("cvss_v3_score"),
                cve_data.get("published_date"),
            ]

            # Add optional fields if they exist
            if "gemini_priority" in cve_data:
                fields.append("gemini_priority")
                values.append(cve_data.get("gemini_priority"))

            if "gemini_raw_response" in cve_data:
                fields.append("gemini_raw_response")
                values.append(cve_data.get("gemini_raw_response"))

            # Add processed timestamp
            fields.append("processed_at")
            values.append(cve_data.get("processed_at", datetime.now(datetime.UTC).isoformat()))

            if "epss_score" in cve_data:
                fields.append("epss_score")
                values.append(cve_data.get("epss_score"))

            if "epss_percentile" in cve_data:
                fields.append("epss_percentile")
                values.append(cve_data.get("epss_percentile"))

            if "is_in_kev" in cve_data:
                fields.append("is_in_kev")
                values.append(1 if cve_data.get("is_in_kev") else 0)

            if "kev_date_added" in cve_data:
                fields.append("kev_date_added")
                values.append(cve_data.get("kev_date_added"))

            if "risk_score" in cve_data:
                fields.append("risk_score")
                values.append(cve_data.get("risk_score"))

            if "alerts" in cve_data and cve_data["alerts"]:
                fields.append("alerts")
                try:
                    values.append(json.dumps(cve_data.get("alerts", [])))
                except Exception as e:
                    log_to_file(f"Error serializing alerts to JSON: {str(e)}")
                    # Use a string representation as fallback
                    values.append(str(cve_data.get("alerts", [])))

            if "msrc_id" in cve_data:
                fields.append("msrc_id")
                values.append(cve_data.get("msrc_id"))

            if "microsoft_product_family" in cve_data:
                fields.append("microsoft_product_family")
                values.append(cve_data.get("microsoft_product_family"))

            if "microsoft_product_name" in cve_data:
                fields.append("microsoft_product_name")
                values.append(cve_data.get("microsoft_product_name"))

            if "microsoft_severity" in cve_data:
                fields.append("microsoft_severity")
                values.append(cve_data.get("microsoft_severity"))

            if "patch_tuesday_date" in cve_data:
                fields.append("patch_tuesday_date")
                values.append(cve_data.get("patch_tuesday_date"))

            if "has_public_exploit" in cve_data:
                fields.append("has_public_exploit")
                values.append(1 if cve_data.get("has_public_exploit") else 0)

            if "exploit_references" in cve_data:
                fields.append("exploit_references")
                try:
                    values.append(json.dumps(cve_data.get("exploit_references", [])))
                except Exception as e:
                    log_to_file(f"Error serializing exploit_references to JSON: {str(e)}")
                    # Use a string representation as fallback
                    values.append(str(cve_data.get("exploit_references", [])))

            # Construct and execute insert query
            placeholders = ", ".join(["?" for _ in fields])
            insert_query = f"INSERT INTO cves ({', '.join(fields)}) VALUES ({placeholders})"

            logger.debug(f"Executing query: {insert_query}")
            log_to_file(f"Executing INSERT for {cve_id}")

            cursor.execute(insert_query, values)
            affected_rows = cursor.rowcount
            log_to_file(f"Insert affected {affected_rows} rows")

        # Commit transaction
        log_to_file(f"About to commit transaction for {cve_id}")
        try:
            conn.commit()
            log_to_file(f"Transaction committed successfully for {cve_id}")
        except Exception as commit_error:
            log_to_file(f"Commit failed for {cve_id}: {str(commit_error)}")
            raise

        # Verify the operation
        log_to_file(f"Starting verification for {cve_id}")
        cursor.execute("SELECT cve_id, processed_at FROM cves WHERE cve_id = ?", (cve_id,))
        verification = cursor.fetchone()
        if verification:
            log_to_file(f"Verification successful: CVE {cve_id} exists with timestamp {verification[1]}")
            return True
        else:
            log_to_file(f"Verification failed: CVE {cve_id} not found after save operation")
            # Let's also check if any records exist at all
            cursor.execute("SELECT COUNT(*) FROM cves")
            total_count = cursor.fetchone()[0]
            log_to_file(f"Total CVEs in database: {total_count}")
            return False

    except sqlite3.Error as e:
        logger.error(f"Database error while storing/updating CVE {cve_id}: {str(e)}")
        logger.error(f"Stack trace: {traceback.format_exc()}")
        log_to_file(f"SQLite error for {cve_id}: {str(e)}")
        log_to_file(traceback.format_exc())
        return False
    except Exception as e:
        logger.error(f"Unexpected error while storing/updating CVE {cve_id}: {str(e)}")
        logger.error(f"Stack trace: {traceback.format_exc()}")
        log_to_file(f"Unexpected error for {cve_id}: {str(e)}")
        log_to_file(traceback.format_exc())
        return False
    finally:
        if conn:
            try:
                conn.close()
                log_to_file("Database connection closed")
            except Exception as e:
                log_to_file(f"Error closing connection: {str(e)}")


def update_cve_exploit_data(cve_id: str, exploits: Optional[List[Dict[str, Any]]]) -> bool:
    """
    Updates a CVE with information about available public exploits.

    Args:
        cve_id (str): The CVE ID to update
        exploits (list): A list of dictionaries containing exploit information, or None

    Returns:
        bool: True if the update was successful, False otherwise
    """
    conn = None
    try:
        conn = sqlite3.connect(get_db_file_name())
        cursor = conn.cursor()

        # Convert exploit list to JSON string
        has_public_exploit = 0
        exploit_references = None

        if exploits and len(exploits) > 0:
            has_public_exploit = 1
            exploit_references = json.dumps(exploits)

        # Update the record
        cursor.execute(
            """
        UPDATE cves
        SET has_public_exploit = ?, exploit_references = ?
        WHERE cve_id = ?
        """,
            (has_public_exploit, exploit_references, cve_id),
        )

        if cursor.rowcount == 0:
            logger.warning(f"No CVE found with ID {cve_id} for exploit update")
            return False

        conn.commit()
        logger.debug(f"Successfully updated exploit information for {cve_id}: {has_public_exploit} exploits found")
        return True

    except sqlite3.Error as e:
        logger.error(f"Database error while updating exploit information for {cve_id}: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error updating exploit data for {cve_id}: {str(e)}")
        return False
    finally:
        if conn:
            conn.close()


def get_high_priority_cves():
    """
    Fetches only HIGH priority CVEs from the database.
    This is useful for focused exploit search to improve performance.

    Returns:
        list: A list of dictionaries containing CVE data with HIGH priority.
    """
    conn = None
    try:
        conn = sqlite3.connect(get_db_file_name())
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            """
        SELECT id, cve_id, description, cvss_v3_score, published_date, gemini_priority,
               processed_at, epss_score, epss_percentile, is_in_kev, kev_date_added,
               msrc_id, microsoft_product_family, microsoft_product_name,
               microsoft_severity, patch_tuesday_date, has_public_exploit, exploit_references
        FROM cves
        WHERE gemini_priority = 'HIGH'
        ORDER BY cvss_v3_score DESC
        """
        )

        rows = cursor.fetchall()
        high_priority_cves = []
        for row in rows:
            # Parse exploit_references JSON if available
            exploit_refs = None
            if row["exploit_references"]:
                try:
                    exploit_refs = json.loads(row["exploit_references"])
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON in exploit_references for {row['cve_id']}")

            high_priority_cves.append(
                {
                    "id": row["id"],
                    "cve_id": row["cve_id"],
                    "description": row["description"],
                    "cvss_v3_score": row["cvss_v3_score"],
                    "published_date": row["published_date"],
                    "gemini_priority": row["gemini_priority"],
                    "processed_at": row["processed_at"],
                    "epss_score": row["epss_score"],
                    "epss_percentile": row["epss_percentile"],
                    "is_in_kev": bool(row["is_in_kev"]),
                    "kev_date_added": row["kev_date_added"],
                    "microsoft_severity": row["microsoft_severity"],
                    "microsoft_product_family": row["microsoft_product_family"],
                    "microsoft_product_name": row["microsoft_product_name"],
                    "patch_tuesday_date": row["patch_tuesday_date"],
                    "has_public_exploit": bool(row["has_public_exploit"]),
                    "exploit_references": exploit_refs,
                }
            )

        logger.debug(f"Found {len(high_priority_cves)} HIGH priority CVEs")
        return high_priority_cves

    except sqlite3.Error as e:
        logger.error(f"Database error while fetching HIGH priority CVEs: {str(e)}")
        return []
    finally:
        if conn:
            conn.close()


def store_threat_articles(
    articles_data: List[Dict], cve_id_association: Optional[str] = None, source_query: Optional[str] = None
) -> int:
    """
    Stores threat articles retrieved from EXA AI searches in the database.

    Args:
        articles_data (List[Dict]): List of article dictionaries from EXA search
        cve_id_association (Optional[str]): CVE ID if the search was for a specific CVE
        source_query (Optional[str]): The query that led to these articles

    Returns:
        int: Number of newly inserted articles
    """
    if not articles_data:
        logger.warning("No articles provided to store")
        return 0

    conn = None
    try:
        conn = sqlite3.connect(get_db_file_name())
        cursor = conn.cursor()

        inserted_count = 0
        current_time = datetime.now(datetime.UTC).isoformat()

        for article in articles_data:
            try:
                # Extract data from article dictionary
                url = article.get("url", "")
                title = article.get("title", "")
                published_date = article.get("published_date")
                content_text = article.get("text", "")
                highlights = article.get("highlights", [])
                author = article.get("author")
                score = article.get("score")

                # Skip articles without URL
                if not url:
                    logger.warning("Skipping article without URL")
                    continue

                # Convert highlights list to JSON string
                content_highlights = None
                if highlights:
                    try:
                        content_highlights = json.dumps(highlights)
                    except Exception as e:
                        logger.warning(f"Error serializing highlights for {url}: {str(e)}")
                        content_highlights = str(highlights)

                # Use INSERT OR IGNORE to avoid duplicates based on URL
                cursor.execute(
                    """
                INSERT OR IGNORE INTO threat_articles (
                    cve_id_association, source_query, url, title, published_date,
                    content_text, content_highlights, fetched_date, author, score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        cve_id_association,
                        source_query,
                        url,
                        title,
                        published_date,
                        content_text,
                        content_highlights,
                        current_time,
                        author,
                        score,
                    ),
                )

                if cursor.rowcount > 0:
                    inserted_count += 1
                    logger.debug(f"Stored article: {title[:50]}...")
                else:
                    logger.debug(f"Article already exists (skipped): {url}")

            except sqlite3.Error as e:
                logger.error(f"Error storing article {article.get('url', 'unknown')}: {str(e)}")
                continue

        conn.commit()
        logger.info(f"Successfully stored {inserted_count} new threat articles")
        return inserted_count

    except sqlite3.Error as e:
        logger.error(f"Database error while storing threat articles: {str(e)}")
        return 0
    finally:
        if conn:
            conn.close()


def get_articles_for_cve(cve_id: str) -> List[Dict]:
    """
    Retrieves all threat articles associated with a specific CVE ID.

    Args:
        cve_id (str): The CVE ID to search for

    Returns:
        List[Dict]: List of article dictionaries associated with the CVE
    """
    if not cve_id:
        logger.error("No CVE ID provided")
        return []

    conn = None
    try:
        conn = sqlite3.connect(get_db_file_name())
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            """
        SELECT article_id, cve_id_association, source_query, url, title, published_date,
               content_text, content_highlights, fetched_date, gemini_summary,
               extracted_iocs, identified_ttps, mentioned_actors, author, score
        FROM threat_articles
        WHERE cve_id_association = ?
        ORDER BY fetched_date DESC
        """,
            (cve_id,),
        )

        rows = cursor.fetchall()
        articles = []

        for row in rows:
            # Parse JSON fields
            highlights = []
            if row["content_highlights"]:
                try:
                    highlights = json.loads(row["content_highlights"])
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON in content_highlights for article {row['article_id']}")

            extracted_iocs = None
            if row["extracted_iocs"]:
                try:
                    extracted_iocs = json.loads(row["extracted_iocs"])
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON in extracted_iocs for article {row['article_id']}")

            identified_ttps = None
            if row["identified_ttps"]:
                try:
                    identified_ttps = json.loads(row["identified_ttps"])
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON in identified_ttps for article {row['article_id']}")

            mentioned_actors = None
            if row["mentioned_actors"]:
                try:
                    mentioned_actors = json.loads(row["mentioned_actors"])
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON in mentioned_actors for article {row['article_id']}")

            articles.append(
                {
                    "article_id": row["article_id"],
                    "cve_id_association": row["cve_id_association"],
                    "source_query": row["source_query"],
                    "url": row["url"],
                    "title": row["title"],
                    "published_date": row["published_date"],
                    "content_text": row["content_text"],
                    "content_highlights": highlights,
                    "fetched_date": row["fetched_date"],
                    "gemini_summary": row["gemini_summary"],
                    "extracted_iocs": extracted_iocs,
                    "identified_ttps": identified_ttps,
                    "mentioned_actors": mentioned_actors,
                    "author": row["author"],
                    "score": row["score"],
                }
            )

        logger.debug(f"Found {len(articles)} articles for CVE {cve_id}")
        return articles

    except sqlite3.Error as e:
        logger.error(f"Database error while fetching articles for CVE {cve_id}: {str(e)}")
        return []
    finally:
        if conn:
            conn.close()


def get_articles_needing_analysis() -> List[Dict]:
    """
    Retrieves threat articles that need Gemini analysis (where gemini_summary is NULL).

    Returns:
        List[Dict]: List of article dictionaries that need analysis
    """
    conn = None
    try:
        conn = sqlite3.connect(get_db_file_name())
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            """
        SELECT article_id, cve_id_association, source_query, url, title, published_date,
               content_text, content_highlights, fetched_date, author, score
        FROM threat_articles
        WHERE gemini_summary IS NULL
        ORDER BY fetched_date DESC
        LIMIT 50
        """,
        )

        rows = cursor.fetchall()
        articles = []

        for row in rows:
            # Parse highlights JSON
            highlights = []
            if row["content_highlights"]:
                try:
                    highlights = json.loads(row["content_highlights"])
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON in content_highlights for article {row['article_id']}")

            articles.append(
                {
                    "article_id": row["article_id"],
                    "cve_id_association": row["cve_id_association"],
                    "source_query": row["source_query"],
                    "url": row["url"],
                    "title": row["title"],
                    "published_date": row["published_date"],
                    "content_text": row["content_text"],
                    "content_highlights": highlights,
                    "fetched_date": row["fetched_date"],
                    "author": row["author"],
                    "score": row["score"],
                }
            )

        logger.debug(f"Found {len(articles)} articles needing analysis")
        return articles

    except sqlite3.Error as e:
        logger.error(f"Database error while fetching articles needing analysis: {str(e)}")
        return []
    finally:
        if conn:
            conn.close()


def get_all_threat_articles(limit: Optional[int] = None) -> List[Dict]:
    """
    Retrieves all threat articles from the database.

    Args:
        limit (Optional[int]): Maximum number of articles to return

    Returns:
        List[Dict]: List of all article dictionaries
    """
    conn = None
    try:
        conn = sqlite3.connect(get_db_file_name())
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = """
        SELECT article_id, cve_id_association, source_query, url, title, published_date,
               content_text, content_highlights, fetched_date, gemini_summary,
               extracted_iocs, identified_ttps, mentioned_actors, author, score
        FROM threat_articles
        ORDER BY fetched_date DESC
        """

        if limit:
            query += f" LIMIT {limit}"

        cursor.execute(query)
        rows = cursor.fetchall()
        articles = []

        for row in rows:
            # Parse JSON fields
            highlights = []
            if row["content_highlights"]:
                try:
                    highlights = json.loads(row["content_highlights"])
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON in content_highlights for article {row['article_id']}")

            extracted_iocs = None
            if row["extracted_iocs"]:
                try:
                    extracted_iocs = json.loads(row["extracted_iocs"])
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON in extracted_iocs for article {row['article_id']}")

            identified_ttps = None
            if row["identified_ttps"]:
                try:
                    identified_ttps = json.loads(row["identified_ttps"])
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON in identified_ttps for article {row['article_id']}")

            mentioned_actors = None
            if row["mentioned_actors"]:
                try:
                    mentioned_actors = json.loads(row["mentioned_actors"])
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON in mentioned_actors for article {row['article_id']}")

            articles.append(
                {
                    "article_id": row["article_id"],
                    "cve_id_association": row["cve_id_association"],
                    "source_query": row["source_query"],
                    "url": row["url"],
                    "title": row["title"],
                    "published_date": row["published_date"],
                    "content_text": row["content_text"],
                    "content_highlights": highlights,
                    "fetched_date": row["fetched_date"],
                    "gemini_summary": row["gemini_summary"],
                    "extracted_iocs": extracted_iocs,
                    "identified_ttps": identified_ttps,
                    "mentioned_actors": mentioned_actors,
                    "author": row["author"],
                    "score": row["score"],
                }
            )

        logger.debug(f"Retrieved {len(articles)} threat articles")
        return articles

    except sqlite3.Error as e:
        logger.error(f"Database error while fetching all threat articles: {str(e)}")
        return []
    finally:
        if conn:
            conn.close()
