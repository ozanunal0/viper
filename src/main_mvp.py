"""
Main module for the VIPER CTI feed application.
Orchestrates the workflow for fetching, analyzing, and displaying CVEs.
"""
import asyncio
import logging
import os
import time
from datetime import datetime

import yaml

from src.clients.cisa_kev_client import fetch_kev_catalog
from src.clients.epss_client import get_epss_score, get_epss_scores_batch
from src.clients.exa_client import search_cve_related_content, search_general_threat_intelligence
from src.clients.exploit_search_client import find_public_exploits
from src.clients.microsoft_update_client import (
    fetch_latest_patch_tuesday_data,
    fetch_patch_tuesday_data,
)
from src.clients.nvd_client import fetch_recent_cves
from src.llm_analyzer import analyze_cve_async
from src.risk_analyzer import analyze_cve_risk, calculate_combined_risk_score, generate_alerts

# Import configuration getters
from src.utils.config import (
    get_exa_api_key,
    get_exa_general_queries,
    get_exa_results_per_query,
    get_exploit_db_api_url,
    get_gemini_api_key,
    get_gemini_concurrent_requests,
    get_github_token,
    get_log_file_name,
    get_log_level,
    get_nvd_days_published_ago,
)
from src.utils.database_handler import (
    get_all_cve_ids_from_db,
    get_articles_needing_analysis,
    get_cve_details,
    get_cves_missing_epss,
    get_cves_with_alerts,
    get_high_medium_priority_cves,
    get_unprocessed_cves,
    initialize_db,
    store_cves,
    store_threat_articles,
    update_cve_epss_data,
    update_cve_exploit_data,
    update_cve_kev_status,
    update_cve_microsoft_data,
    update_cve_priority,
    update_cve_risk_data,
)

# Configure logging
log_level = get_log_level()
log_file = get_log_file_name()
numeric_log_level = getattr(logging, log_level.upper(), logging.INFO)

logging.basicConfig(
    level=numeric_log_level,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
    force=True,  # Allow re-configuration if other modules called basicConfig
)
logger = logging.getLogger(__name__)


def display_cve(cve):
    """
    Formats and displays a CVE in a readable format.

    Args:
        cve (dict): The CVE to display.
    """
    # Format CVSS score
    cvss_score = cve.get("cvss_v3_score", "N/A")
    if cvss_score is not None:
        cvss_display = f"{cvss_score:.1f}" if isinstance(cvss_score, (float, int)) else "N/A"
    else:
        cvss_display = "N/A"

    # Format EPSS score and percentile
    epss_score = cve.get("epss_score")
    epss_percentile = cve.get("epss_percentile")
    if epss_score is not None and epss_percentile is not None:
        epss_display = f"{epss_score:.4f} ({epss_percentile:.1%})"
    else:
        epss_display = "N/A"

    # Format the dates for better readability
    published_date = cve.get("published_date", "")
    if published_date:
        try:
            dt = datetime.fromisoformat(published_date.replace("Z", "+00:00"))
            published_date = dt.strftime("%Y-%m-%d")
        except (ValueError, TypeError):
            pass

    processed_at = cve.get("processed_at", "")
    if processed_at:
        try:
            dt = datetime.fromisoformat(processed_at.replace("Z", "+00:00"))
            processed_at = dt.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            pass

    # Format KEV information
    is_in_kev = cve.get("is_in_kev", False)
    kev_date_added = cve.get("kev_date_added", "")
    if kev_date_added:
        try:
            dt = datetime.fromisoformat(kev_date_added.replace("Z", "+00:00"))
            kev_date_added = dt.strftime("%Y-%m-%d")
        except (ValueError, TypeError):
            pass

    kev_display = "No"
    if is_in_kev:
        kev_display = f"Yes (Added: {kev_date_added})" if kev_date_added else "Yes"

    # Format Microsoft information
    ms_severity = cve.get("microsoft_severity")
    ms_product = cve.get("microsoft_product_family")
    patch_tuesday = cve.get("patch_tuesday_date", "")

    if patch_tuesday:
        try:
            dt = datetime.fromisoformat(patch_tuesday.replace("Z", "+00:00"))
            patch_tuesday = dt.strftime("%Y-%m-%d")
        except (ValueError, TypeError):
            pass

    ms_display = ""
    if ms_severity:
        ms_display = f"\nMicrosoft Severity: {ms_severity} | Product: {ms_product or 'N/A'} | Patch Tuesday: {patch_tuesday or 'N/A'}"

    # Create a nicely formatted output
    print(f"\n{'=' * 80}")
    print(f"CVE ID: {cve.get('cve_id')}")
    print(
        f"Priority: {cve.get('gemini_priority')} | CVSS: {cvss_display} | EPSS: {epss_display} | Published: {published_date}"
    )
    print(f"In CISA KEV: {kev_display}")
    if ms_display:
        print(ms_display)
    print(f"{'-' * 80}")
    print(f"Description: {cve.get('description')}")
    print(f"{'=' * 80}")


def display_cve_with_alerts(cve):
    """
    Formats and displays a CVE with its alerts in a readable format.

    Args:
        cve (dict): The CVE to display with alerts.
    """
    # Format CVSS score
    cvss_score = cve.get("cvss_v3_score", "N/A")
    if cvss_score is not None:
        cvss_display = f"{cvss_score:.1f}" if isinstance(cvss_score, (float, int)) else "N/A"
    else:
        cvss_display = "N/A"

    # Format EPSS score and percentile
    epss_score = cve.get("epss_score")
    epss_percentile = cve.get("epss_percentile")
    if epss_score is not None and epss_percentile is not None:
        epss_display = f"{epss_score:.4f} ({epss_percentile:.1%})"
    else:
        epss_display = "N/A"

    # Format risk score
    risk_score = cve.get("risk_score")
    if risk_score is not None:
        risk_display = f"{risk_score:.4f}"
    else:
        risk_display = "N/A"

    # Format the dates for better readability
    published_date = cve.get("published_date", "")
    if published_date:
        try:
            dt = datetime.fromisoformat(published_date.replace("Z", "+00:00"))
            published_date = dt.strftime("%Y-%m-%d")
        except (ValueError, TypeError):
            pass

    # Format KEV information
    is_in_kev = cve.get("is_in_kev", False)
    kev_date_added = cve.get("kev_date_added", "")
    if kev_date_added:
        try:
            dt = datetime.fromisoformat(kev_date_added.replace("Z", "+00:00"))
            kev_date_added = dt.strftime("%Y-%m-%d")
        except (ValueError, TypeError):
            pass

    kev_display = "No"
    if is_in_kev:
        kev_display = f"Yes (Added: {kev_date_added})" if kev_date_added else "Yes"

    # Create a nicely formatted output
    print(f"\n{'=' * 80}")
    print(f"⚠️  ALERT - CVE ID: {cve.get('cve_id')}")
    print(
        f"Risk Score: {risk_display} | Priority: {cve.get('gemini_priority')} | CVSS: {cvss_display} | EPSS: {epss_display}"
    )
    print(f"In CISA KEV: {kev_display} | Published: {published_date}")
    print(f"{'-' * 80}")
    print(f"Description: {cve.get('description')}")
    print(f"{'-' * 80}")

    # Display alerts
    alerts = cve.get("alerts", [])
    if alerts:
        print("ALERTS:")
        for alert in alerts:
            print(f"• {alert}")

    print(f"{'=' * 80}")


async def sync_cisa_kev_data():
    """
    Synchronizes CISA Known Exploited Vulnerabilities (KEV) catalog data with the local database.

    Returns:
        tuple: (kev_count, updated_count) representing the number of KEV entries fetched and
               the number of local CVEs updated with KEV status.
    """
    try:
        logger.info("Fetching CISA KEV catalog")

        # Fetch the KEV catalog
        kev_entries = fetch_kev_catalog()

        if not kev_entries:
            logger.warning("No KEV entries fetched or error occurred")
            return 0, 0

        logger.info(f"Fetched {len(kev_entries)} entries from CISA KEV catalog")

        # Create a dictionary mapping CVE IDs to KEV entries for quick lookup
        kev_dict = {entry["cve_id"]: entry for entry in kev_entries}

        # Get all CVE IDs from the database
        cve_ids_in_db = get_all_cve_ids_from_db()

        # Update KEV status for CVEs in database
        updated_count = 0
        for cve_id in cve_ids_in_db:
            if cve_id in kev_dict:
                # CVE is in KEV catalog, update status
                kev_entry = kev_dict[cve_id]
                if update_cve_kev_status(cve_id, True, kev_entry["date_added"]):
                    updated_count += 1

        logger.info(f"Updated {updated_count} CVEs with KEV status")
        return len(kev_entries), updated_count

    except Exception as e:
        logger.error(f"Error synchronizing CISA KEV data: {str(e)}")
        return 0, 0


async def sync_microsoft_patch_tuesday_data():
    """
    Synchronizes Microsoft Patch Tuesday data with the local database.

    Returns:
        tuple: (vuln_count, updated_count) representing the number of vulnerabilities fetched
               and the number of local CVEs updated with Microsoft data.
    """
    try:
        logger.info("Fetching Microsoft Patch Tuesday data")

        # Fetch the latest Patch Tuesday data
        ms_vulnerabilities = fetch_latest_patch_tuesday_data()

        if not ms_vulnerabilities:
            logger.warning("No Microsoft Patch Tuesday data fetched or error occurred")
            return 0, 0

        logger.info(f"Fetched {len(ms_vulnerabilities)} vulnerabilities from Microsoft Patch Tuesday")

        # Update CVEs with Microsoft data
        updated_count = 0
        for vuln in ms_vulnerabilities:
            cve_id = vuln.get("cve_id")
            if not cve_id:
                continue

            # Extract relevant data
            msrc_id = vuln.get("msrc_id")
            product_family = vuln.get("product_family")
            product_name = vuln.get("product_name")
            severity = vuln.get("severity")
            release_date = vuln.get("release_date")

            # Update the database
            if update_cve_microsoft_data(cve_id, msrc_id, product_family, product_name, severity, release_date):
                updated_count += 1

        logger.info(f"Updated {updated_count} CVEs with Microsoft Patch Tuesday data")
        return len(ms_vulnerabilities), updated_count

    except Exception as e:
        logger.error(f"Error synchronizing Microsoft Patch Tuesday data: {str(e)}")
        return 0, 0


async def process_cve(cve, semaphore):
    """
    Process a single CVE with Gemini and update the database.

    Args:
        cve (dict): The CVE to process
        semaphore (asyncio.Semaphore): Semaphore for rate limiting

    Returns:
        tuple: (cve_id, priority) for status reporting
    """
    cve_id = cve.get("cve_id")
    try:
        async with semaphore:
            logger.info(f"Processing CVE: {cve_id}")

            # Analyze the CVE asynchronously
            priority, justification, raw_response = await analyze_cve_async(cve)

            # Update the database with the priority (database operations are synchronous)
            update_cve_priority(cve_id, priority, raw_response)

            return cve_id, priority
    except Exception as e:
        logger.error(f"Error processing CVE {cve_id}: {str(e)}")
        return cve_id, "ERROR_ANALYZING"


async def process_cves_concurrently(unprocessed_cves_list):
    """
    Process multiple CVEs concurrently using async/await pattern.

    Args:
        unprocessed_cves_list (list): List of unprocessed CVEs

    Returns:
        int: Number of successfully processed CVEs
    """
    if not unprocessed_cves_list:
        return 0

    # Get the concurrency limit from config
    concurrency_limit = get_gemini_concurrent_requests()
    logger.info(f"Using concurrency limit of {concurrency_limit} for Gemini API calls")

    # Create a semaphore to limit concurrent API calls
    semaphore = asyncio.Semaphore(concurrency_limit)

    # Create a task for each CVE
    tasks = [process_cve(cve, semaphore) for cve in unprocessed_cves_list]

    logger.info(f"Starting concurrent processing of {len(tasks)} CVEs")
    start_time = time.time()

    # Execute all tasks concurrently
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Count successes and log any failures
    success_count = 0
    for result in results:
        if isinstance(result, Exception):
            logger.error(f"Task failed with exception: {result}")
        else:
            cve_id, priority = result
            if priority != "ERROR_ANALYZING":
                success_count += 1
            else:
                logger.warning(f"Failed to analyze {cve_id} properly")

    elapsed_time = time.time() - start_time
    logger.info(f"Completed concurrent processing of {len(tasks)} CVEs in {elapsed_time:.2f} seconds")
    logger.info(f"Successfully processed {success_count} out of {len(tasks)} CVEs")

    return success_count


async def enrich_cves_with_epss():
    """
    Fetches EPSS scores for CVEs missing this data and updates the database.

    Returns:
        int: Number of CVEs successfully enriched with EPSS data
    """
    # Get CVEs missing EPSS data
    cves_missing_epss = get_cves_missing_epss()

    if not cves_missing_epss:
        logger.info("No CVEs need EPSS enrichment")
        return 0

    logger.info(f"Enriching {len(cves_missing_epss)} CVEs with EPSS data")

    # Extract CVE IDs
    cve_ids = [cve["cve_id"] for cve in cves_missing_epss if cve.get("cve_id")]

    # Use batch fetch for efficiency
    if len(cve_ids) > 1:
        epss_results = get_epss_scores_batch(cve_ids)
    else:
        # For a single CVE, use the single fetch method
        epss_results = {}
        if cve_ids:
            result = get_epss_score(cve_ids[0])
            if result:
                epss_results[cve_ids[0]] = result

    # Update database with fetched EPSS data
    success_count = 0
    for cve_id, epss_data in epss_results.items():
        if epss_data:
            if update_cve_epss_data(cve_id, epss_data.get("epss"), epss_data.get("percentile")):
                success_count += 1

    logger.info(f"Successfully enriched {success_count} CVEs with EPSS data")
    return success_count


async def process_risk_scoring_alerts(cves_list):
    """
    Processes CVEs for risk scoring and alert generation.

    Args:
        cves_list (list): List of CVEs to process

    Returns:
        int: Number of CVEs with alerts
    """
    if not cves_list:
        return 0

    logger.info(f"Calculating risk scores and generating alerts for {len(cves_list)} CVEs")

    cves_with_alerts_count = 0
    for cve in cves_list:
        cve_id = cve.get("cve_id")
        if not cve_id:
            continue

        # Calculate risk score and generate alerts
        risk_score, alerts = analyze_cve_risk(cve)

        # Update database with risk score and alerts
        if update_cve_risk_data(cve_id, risk_score, alerts):
            if alerts:
                cves_with_alerts_count += 1

    logger.info(f"Generated alerts for {cves_with_alerts_count} CVEs")
    return cves_with_alerts_count


async def enrich_cves_with_exploits(cves_list):
    """
    Searches for public exploits for CVEs and updates the database.

    Args:
        cves_list (list): List of CVEs to process

    Returns:
        tuple: (processed_count, found_exploits_count) tuple
    """
    if not cves_list:
        logger.info("No CVEs to check for public exploits")
        return 0, 0

    # Check if GitHub token is configured
    github_token = get_github_token()
    exploit_db_url = get_exploit_db_api_url()

    if not github_token and not exploit_db_url:
        logger.warning("No exploit search sources configured. Set GITHUB_TOKEN or EXPLOIT_DB_API_URL in .env file.")
        print("\nWarning: Public exploit search is not configured. Add GITHUB_TOKEN to your .env file.")
        return 0, 0

    if not github_token:
        logger.warning("GitHub token not configured. GitHub exploit search will be skipped.")
        print(
            "\nNote: GitHub exploit search is disabled. Add GITHUB_TOKEN to your .env file for more comprehensive results."
        )

    logger.info(f"Searching for public exploits for {len(cves_list)} CVEs")

    processed_count = 0
    found_exploits_count = 0

    # Process CVEs one by one to avoid overwhelming APIs
    for cve in cves_list:
        cve_id = cve.get("cve_id")
        if not cve_id:
            continue

        try:
            # Search for public exploits
            exploits = find_public_exploits(cve_id)

            # Update the database with exploit information
            if update_cve_exploit_data(cve_id, exploits):
                processed_count += 1

                if exploits and len(exploits) > 0:
                    found_exploits_count += 1
                    logger.info(f"Found {len(exploits)} public exploit(s) for {cve_id}")

            # Add a delay to avoid rate limiting
            await asyncio.sleep(2)

        except Exception as e:
            logger.error(f"Error checking for exploits for {cve_id}: {str(e)}")

    logger.info(f"Processed {processed_count} CVEs, found exploits for {found_exploits_count}")
    return processed_count, found_exploits_count


async def scan_all_cves_for_exploits(max_cves=None, include_processed=False):
    """
    Scan all CVEs in the database for public exploits.
    This is useful for periodic rescanning as new exploits may emerge over time.

    Args:
        max_cves (int, optional): Maximum number of CVEs to check. If None, checks all CVEs.
        include_processed (bool, optional): Whether to include CVEs that already have exploit data.

    Returns:
        tuple: (processed_count, found_exploits_count) tuple
    """
    # Get all CVE IDs from the database
    all_cve_ids = get_all_cve_ids_from_db()
    logger.info(f"Found {len(all_cve_ids)} total CVEs in the database")

    # Check if GitHub token is configured
    github_token = get_github_token()
    exploit_db_url = get_exploit_db_api_url()

    if not github_token and not exploit_db_url:
        logger.warning("No exploit search sources configured. Set GITHUB_TOKEN or EXPLOIT_DB_API_URL in .env file.")
        return 0, 0

    if not github_token:
        logger.warning("GitHub token not configured. GitHub exploit search will be skipped.")

    # If requested, limit the number of CVEs to process
    if max_cves and len(all_cve_ids) > max_cves:
        logger.info(f"Limiting scan to {max_cves} CVEs")
        all_cve_ids = all_cve_ids[:max_cves]

    # Create list of CVE data dictionaries with just the CVE ID
    cves_to_process = [{"cve_id": cve_id} for cve_id in all_cve_ids]

    # Process the CVEs for exploit data
    return await enrich_cves_with_exploits(cves_to_process)


async def perform_semantic_searches(cve_list_for_context=None, general_queries=None):
    """
    Performs semantic searches using EXA AI for threat intelligence gathering.

    Args:
        cve_list_for_context (Optional[List[Dict]]): List of high/medium priority CVEs to search for
        general_queries (Optional[List[str]]): List of general threat intelligence queries

    Returns:
        int: Total number of articles stored from all searches
    """
    total_articles_stored = 0

    # Check if EXA API key is configured
    try:
        get_exa_api_key()
    except ValueError:
        logger.warning("EXA_API_KEY not configured. Skipping semantic searches.")
        return 0

    logger.info("Starting EXA AI semantic searches for threat intelligence")

    # Search for CVE-specific content
    if cve_list_for_context:
        logger.info(f"Searching for content related to {len(cve_list_for_context)} high/medium priority CVEs")

        for cve in cve_list_for_context:
            cve_id = cve.get("cve_id")
            if not cve_id:
                continue

            try:
                logger.info(f"Searching for content related to {cve_id}")
                articles = await search_cve_related_content(cve_id=cve_id, num_results=get_exa_results_per_query())

                if articles:
                    stored_count = store_threat_articles(
                        articles_data=articles,
                        cve_id_association=cve_id,
                        source_query=f"technical analysis and exploitation of {cve_id}",
                    )
                    total_articles_stored += stored_count
                    logger.info(f"Stored {stored_count} articles for {cve_id}")
                else:
                    logger.info(f"No articles found for {cve_id}")

            except Exception as e:
                logger.error(f"Error searching for CVE {cve_id}: {str(e)}")
                continue

    # Search for general threat intelligence
    if general_queries:
        logger.info(f"Performing {len(general_queries)} general threat intelligence searches")

        try:
            articles = await search_general_threat_intelligence(
                queries=general_queries, num_results=get_exa_results_per_query()
            )

            if articles:
                stored_count = store_threat_articles(
                    articles_data=articles,
                    cve_id_association=None,  # Not associated with a specific CVE
                    source_query="general_threat_intelligence",
                )
                total_articles_stored += stored_count
                logger.info(f"Stored {stored_count} general threat intelligence articles")
            else:
                logger.info("No general threat intelligence articles found")

        except Exception as e:
            logger.error(f"Error performing general threat intelligence searches: {str(e)}")

    logger.info(f"Semantic searches completed. Total articles stored: {total_articles_stored}")
    return total_articles_stored


def run_cti_feed(days_back=None, scan_all_exploits=False, max_cves_for_exploit_scan=None):
    """
    Runs the full CTI feed workflow:
    1. Initialize the database
    2. Fetch recent CVEs
    3. Store CVEs in the database
    4. Sync with CISA KEV catalog
    5. Sync with Microsoft Patch Tuesday data
    6. Enrich CVEs with EPSS data
    7. Analyze unprocessed CVEs with Gemini
    8. Search for public exploits (only for HIGH priority CVEs)
    9. Calculate risk scores and generate alerts
    10. Display high/medium priority CVEs and alerts

    Args:
        days_back (int, optional): Number of days to look back for CVEs.
            If None, uses the value from configuration.
        scan_all_exploits (bool, optional): Whether to scan all CVEs in the database
            for exploits, not just newly added ones. Default is False.
        max_cves_for_exploit_scan (int, optional): Maximum number of CVEs to check for
            exploits when scan_all_exploits is True. Default is None (all CVEs).
    """
    try:
        logger.info("Starting VIPER CTI feed workflow")

        # Use configuration if not specified
        if days_back is None:
            days_back = get_nvd_days_published_ago()

        # Verify Gemini API key is available
        try:
            get_gemini_api_key()
        except ValueError as e:
            logger.error(f"Gemini API key error: {str(e)}")
            print("\nERROR: Gemini API key not found. Please add it to your .env file as GEMINI_API_KEY.")
            return

        # Step 1: Initialize the database
        logger.info("Initializing database")
        initialize_db()

        # Step 2: Fetch recent CVEs from NVD
        logger.info(f"Fetching CVEs published in the last {days_back} days")
        recent_cves = fetch_recent_cves(days_published_ago=days_back)

        if not recent_cves:
            logger.warning("No recent CVEs found")
            print("\nNo recent CVEs found. Try increasing the number of days to look back.")
            return

        # Step 3: Store CVEs in the database
        logger.info("Storing CVEs in the database")
        stored_count = store_cves(recent_cves)
        print(f"\nFetched {len(recent_cves)} CVEs, stored {stored_count} new entries in the database.")

        # Step 4: Sync with CISA KEV catalog
        logger.info("Syncing with CISA KEV catalog")
        kev_count, kev_updated_count = asyncio.run(sync_cisa_kev_data())
        if kev_count > 0:
            print(
                f"\nFetched {kev_count} entries from CISA KEV catalog and updated {kev_updated_count} CVEs with KEV status."
            )

        # Step 5: Sync with Microsoft Patch Tuesday data
        logger.info("Syncing with Microsoft Patch Tuesday data")
        ms_count, ms_updated_count = asyncio.run(sync_microsoft_patch_tuesday_data())
        if ms_count > 0:
            print(
                f"\nFetched {ms_count} Microsoft Patch Tuesday vulnerabilities and updated {ms_updated_count} CVEs with Microsoft data."
            )

        # Step 6: Enrich CVEs with EPSS data
        logger.info("Enriching CVEs with EPSS data")
        epss_enriched_count = asyncio.run(enrich_cves_with_epss())
        if epss_enriched_count > 0:
            print(f"\nEnriched {epss_enriched_count} CVEs with EPSS data.")

        # Step 7: Get unprocessed CVEs from the database
        unprocessed_cves = get_unprocessed_cves()

        if unprocessed_cves:
            logger.info(f"Found {len(unprocessed_cves)} unprocessed CVEs to analyze")
            print(f"\nAnalyzing {len(unprocessed_cves)} unprocessed CVEs with Gemini concurrently...")

            # Process CVEs concurrently using asyncio
            success_count = asyncio.run(process_cves_concurrently(unprocessed_cves))

            print(f"\nCompleted analysis of {success_count}/{len(unprocessed_cves)} CVEs successfully.")
        else:
            logger.info("No unprocessed CVEs found")
            print("\nNo new CVEs to analyze.")

        # Step 8: Get high/medium priority CVEs for risk scoring and alert generation
        logger.info("Retrieving high and medium priority CVEs for risk scoring")
        priority_cves = get_high_medium_priority_cves()

        if priority_cves:
            # Step 9: Search for public exploits ONLY for HIGH priority CVEs
            # Filter for only HIGH priority CVEs to improve performance
            high_priority_cves = [cve for cve in priority_cves if cve.get("gemini_priority") == "HIGH"]

            if high_priority_cves:
                logger.info(f"Searching for public exploits for {len(high_priority_cves)} HIGH priority CVEs")
                print(f"\nSearching for public exploits only for {len(high_priority_cves)} HIGH priority CVEs...")
                processed_exploit_count, found_exploit_count = asyncio.run(
                    enrich_cves_with_exploits(high_priority_cves)
                )

                if processed_exploit_count > 0:
                    print(
                        f"\nSearched for public exploits for {processed_exploit_count} HIGH priority CVEs, found exploits for {found_exploit_count} CVes."
                    )
            else:
                logger.info("No HIGH priority CVEs found, skipping exploit search")
                print("\nNo HIGH priority CVEs found, skipping exploit search.")

            # Step 8b: Optionally scan all CVEs in the database for exploits if explicitly requested
            if scan_all_exploits:
                logger.info("Scanning all CVEs in the database for public exploits (as explicitly requested)")
                print("\nScanning all CVEs in the database for public exploits. This may take some time...")
                all_processed_count, all_found_count = asyncio.run(
                    scan_all_cves_for_exploits(max_cves_for_exploit_scan)
                )
                if all_processed_count > 0:
                    print(
                        f"\nScanned {all_processed_count} CVes for public exploits, found exploits for {all_found_count} CVes."
                    )

            # Step 10: Calculate risk scores and generate alerts
            logger.info("Calculating risk scores and generating alerts")
            cves_with_alerts_count = asyncio.run(process_risk_scoring_alerts(priority_cves))

            # Step 11: Perform semantic searches for threat intelligence
            logger.info("Performing semantic searches for threat intelligence")
            print("\nPerforming semantic searches for threat intelligence...")

            # Get general queries from configuration
            general_queries = get_exa_general_queries()

            # Perform semantic searches
            articles_stored = asyncio.run(
                perform_semantic_searches(cve_list_for_context=priority_cves, general_queries=general_queries)
            )

            if articles_stored > 0:
                print(f"\nStored {articles_stored} threat intelligence articles from semantic searches.")

            print(f"\n{'=' * 80}")
            print(f"FOUND {len(priority_cves)} HIGH/MEDIUM PRIORITY CVes")
            print(f"{'=' * 80}")

            for cve in priority_cves:
                display_cve(cve)

            # Step 12: Display CVes with alerts
            if cves_with_alerts_count > 0:
                logger.info("Retrieving and displaying CVes with alerts")
                cves_with_alerts = get_cves_with_alerts()

                print(f"\n{'=' * 80}")
                print(f"⚠️  ALERTS DETECTED FOR {len(cves_with_alerts)} CVes ⚠️")
                print(f"{'=' * 80}")

                for cve in cves_with_alerts:
                    display_cve_with_alerts(cve)
        else:
            print("\nNo high or medium priority CVes found.")

        logger.info("VIPER CTI feed workflow completed successfully")

    except Exception as e:
        logger.error(f"Error in VIPER CTI feed workflow: {str(e)}")
        print(f"\nError: {str(e)}")


if __name__ == "__main__":
    run_cti_feed()
