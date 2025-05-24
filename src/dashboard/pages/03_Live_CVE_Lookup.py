"""
VIPER CTI Dashboard - Live CVE Lookup Page
"""
import asyncio
import logging
import os
import re
import sqlite3  # Added for database connection check
import sys  # sys.stderr için eklendi
import traceback  # Add for better error logging
import uuid  # For unique identifiers
from datetime import datetime  # datetime için eklendi

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

page_logger = logging.getLogger(__name__)


# Add the project root directory to the path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from src.clients.cisa_kev_client import fetch_kev_catalog
from src.clients.epss_client import get_epss_score
from src.clients.exploit_search_client import find_public_exploits, search_exploit_db, search_github
from src.clients.nvd_client import fetch_single_cve_details
from src.gemini_analyzer import analyze_cve_with_gemini_async
from src.risk_analyzer import analyze_cve_risk
from src.utils.config import get_db_file_name
from src.utils.database_handler import (
    get_cve_details,
    store_cves,
    store_or_update_cve,
    update_cve_epss_data,
    update_cve_exploit_data,
    update_cve_kev_status,
    update_cve_priority,
    update_cve_risk_data,
)

# Initialize session state for tracking operations
if "save_attempted" not in st.session_state:
    st.session_state.save_attempted = False

if "save_success" not in st.session_state:
    st.session_state.save_success = False

if "saved_cve_data" not in st.session_state:
    st.session_state.saved_cve_data = None

if "operation_id" not in st.session_state:
    st.session_state.operation_id = str(uuid.uuid4())

# Set the page title and add refresh button at the top right
title_col, refresh_col = st.columns([6, 1])
with title_col:
    st.title("🔎 Live CVE Lookup")
with refresh_col:
    st.markdown("<div style='margin-top: 15px;'></div>", unsafe_allow_html=True)  # Adding some vertical space
    if st.button("🔄 Refresh", type="primary", use_container_width=True):
        st.rerun()

# Sidebar with information about the tool
st.sidebar.header("About this Tool")
st.sidebar.markdown(
    """
This tool allows you to look up information about a specific CVE (Common Vulnerabilities and Exposures).

1. Enter a valid CVE ID in the format CVE-YYYY-NNNNN
2. The tool will first check the local database for information
3. You can fetch live data from external sources if needed
4. Analyze the vulnerability with Gemini AI
5. Save the results to your local database
"""
)

# Layout for the main function - CVE search
st.markdown("### Enter a CVE ID to lookup")

# Create a form for CVE lookup
with st.form(key="cve_lookup_form"):
    cve_id = st.text_input("CVE ID", placeholder="e.g. CVE-2023-12345")

    # Add data source options
    st.markdown("### Data Sources")
    data_source_cols = st.columns(3)

    with data_source_cols[0]:
        use_nvd = st.checkbox("National Vulnerability Database (NVD)", value=True)

    with data_source_cols[1]:
        use_github = st.checkbox("GitHub Exploits", value=True)

    with data_source_cols[2]:
        use_exploitdb = st.checkbox("Exploit-DB", value=False)

    lookup_button = st.form_submit_button("Look up CVE", type="primary")


# Function to validate CVE ID format
def is_valid_cve_id(cve_id: str) -> bool:
    """Validate CVE ID format (CVE-YYYY-NNNNN where NNNNN can be multiple digits)"""
    return bool(re.match(r"^CVE-\d{4}-\d+$", cve_id))


# Function to display the results from the exploit search
def display_exploit_results(cve_id, exploit_results):
    """Display the results from an exploit search in a structured format"""
    if exploit_results and len(exploit_results) > 0:
        st.warning(f"⚠️ **{len(exploit_results)} potential exploit(s) found**")

        # Create a dataframe for better display
        exploit_data = []
        for exploit in exploit_results:
            # Extract data
            source = exploit.get("source", "Unknown")
            title = exploit.get("title", "Unknown")
            url = exploit.get("url", "#")
            exploit_type = exploit.get("type", "Unknown")
            date = exploit.get("date_published", "Unknown")

            # Handle stars correctly - convert to string to ensure consistent type
            stars = exploit.get("stars", 0) if "stars" in exploit else 0
            # Ensure stars is always a string to avoid type conversion issues
            stars_str = str(stars) if stars is not None else "0"

            desc = exploit.get("description", "") if "description" in exploit else ""

            # Add to data
            exploit_data.append(
                {
                    "Source": source,
                    "Title": title,
                    "Type": exploit_type,
                    "Published": date,
                    "Stars": stars_str,  # Use string value
                    "URL": url,
                    "Description": desc[:100] + "..." if desc and len(desc) > 100 else desc,
                }
            )

        exploit_df = pd.DataFrame(exploit_data)

        # Convert URLs to markdown links
        exploit_df["URL"] = exploit_df["URL"].apply(lambda x: f"[View]({x})")

        # Display the dataframe
        st.dataframe(exploit_df, use_container_width=True)

        # Warning about exploits
        st.error(
            """
        **⚠️ Warning:** The presence of these repositories suggests that exploit code may be available for this vulnerability.
        This significantly increases the risk as attackers may use these exploits for malicious purposes.
        """
        )

        # Update the database with exploit information if we have the CVE in our database
        if st.button("Save exploit data to database", type="primary"):
            try:
                result = update_cve_exploit_data(cve_id, exploit_results)
                if result:
                    st.success(f"Successfully saved exploit data for {cve_id} to the database")
                else:
                    st.error("Failed to save data to database. The CVE might not exist in your database yet.")
                    st.info("You may need to run the NVD ingestion process first to add this CVE to your database.")
            except Exception as e:
                st.error(f"Error saving to database: {str(e)}")
    else:
        st.success("No public exploits found for this vulnerability.")


# Function to check for CVE in KEV catalog
def check_cve_in_kev(cve_id: str, kev_catalog: list) -> tuple:
    """Check if a CVE is in the KEV catalog and return status and date added if found"""
    for entry in kev_catalog:
        if entry.get("cve_id") == cve_id:
            return True, entry.get("date_added")
    return False, None


# Function to display CVE details
def display_cve_details(cve_data: dict, source: str = "Local Database"):
    """Display details for a CVE in a structured format"""
    st.markdown(f"## {cve_data.get('cve_id')}")

    # Display source and metadata
    st.markdown(f"**Source:** {source}")

    if source == "Local Database" and cve_data.get("processed_at"):
        st.markdown(f"**Last analyzed:** {cve_data.get('processed_at')}")

    # Display badges for priority, KEV status, etc.
    badges_html = '<div style="display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 15px;">'

    # Priority badge
    priority = cve_data.get("gemini_priority")
    if priority:
        priority_colors = {
            "HIGH": "red",
            "MEDIUM": "orange",
            "LOW": "green",
            "ERROR_ANALYZING": "gray",
        }
        priority_color = priority_colors.get(priority, "gray")
        badges_html += f'<span style="background-color: {priority_color}; color: white; padding: 5px 10px; border-radius: 5px; font-weight: bold;">{priority} Priority</span>'

    # KEV status badge
    if cve_data.get("is_in_kev"):
        badges_html += '<span style="background-color: #d9534f; color: white; padding: 5px 10px; border-radius: 5px; font-weight: bold;">CISA KEV</span>'

    # Microsoft severity badge if available
    ms_severity = cve_data.get("microsoft_severity")
    if ms_severity:
        severity_color = {
            "Critical": "red",
            "Important": "orange",
            "Moderate": "blue",
            "Low": "green",
        }.get(ms_severity, "gray")

        badges_html += f'<span style="background-color: {severity_color}; color: white; padding: 5px 10px; border-radius: 5px; font-weight: bold;">MS {ms_severity}</span>'

    badges_html += "</div>"
    st.markdown(badges_html, unsafe_allow_html=True)

    # Description and publication info
    st.markdown("### Description")
    st.markdown(cve_data.get("description", "No description available."))

    # Publication details
    pub_date = cve_data.get("published_date")
    if pub_date:
        try:
            if isinstance(pub_date, str):
                pub_date = datetime.fromisoformat(pub_date.replace("Z", "+00:00"))
            st.markdown(f"**Published Date:** {pub_date.strftime('%Y-%m-%d')}")
        except:
            st.markdown(f"**Published Date:** {pub_date}")

    # KEV details if available
    if cve_data.get("is_in_kev") and cve_data.get("kev_date_added"):
        kev_date = cve_data.get("kev_date_added")
        st.markdown(f"**Added to KEV:** {kev_date}")

    # Microsoft details if available
    if ms_severity:
        ms_product = cve_data.get("microsoft_product_family", "Unknown")
        ms_specific = cve_data.get("microsoft_product_name", "Unknown")
        patch_date = cve_data.get("patch_tuesday_date")

        ms_info_html = f"""
        <div style="background-color: rgba(0,0,0,0.05); padding: 10px; border-radius: 5px; margin-top: 10px; border-left: 4px solid {severity_color};">
            <span style="font-weight: bold; color: {severity_color};">Microsoft {ms_severity}</span><br>
            <b>Product Family:</b> {ms_product}<br>
            <b>Specific Product:</b> {ms_specific}<br>
            <b>Patch Tuesday:</b> {patch_date if patch_date else 'Unknown'}
        </div>
        """
        st.markdown(ms_info_html, unsafe_allow_html=True)

    # Metrics section
    st.markdown("### Risk Metrics")

    # Use columns for metrics
    metric_cols = st.columns(4)

    with metric_cols[0]:
        cvss = cve_data.get("cvss_v3_score")
        st.metric("CVSS Score", f"{cvss:.1f}" if cvss is not None else "N/A")

    with metric_cols[1]:
        epss = cve_data.get("epss_score")
        st.metric("EPSS Score", f"{epss:.4f}" if epss is not None else "N/A")

    with metric_cols[2]:
        epss_percentile = cve_data.get("epss_percentile")
        st.metric("EPSS Percentile", f"{epss_percentile:.2f}" if epss_percentile is not None else "N/A")

    with metric_cols[3]:
        risk_score = cve_data.get("risk_score")
        st.metric("Risk Score", f"{risk_score:.2f}" if risk_score is not None else "N/A")

    # Alerts section
    alerts = cve_data.get("alerts", [])
    if alerts:
        st.markdown("### Alerts")
        for alert in alerts:
            st.warning(alert)

    # References section if available
    references = cve_data.get("references", [])
    if references:
        st.markdown("### References")
        for ref in references:
            url = ref.get("url")
            source = ref.get("source")
            if url:
                st.markdown(f"- [{source if source else url}]({url})")

    # CPE entries if available
    cpe_entries = cve_data.get("cpe_entries", [])
    if cpe_entries:
        st.markdown("### Affected Products (CPE)")
        for cpe in cpe_entries[:10]:  # Limit to 10 to avoid cluttering the UI
            criteria = cpe.get("criteria", "")
            vulnerable = cpe.get("vulnerable", True)
            status = "Vulnerable" if vulnerable else "Not Vulnerable"
            status_color = "red" if vulnerable else "green"

            st.markdown(
                f'<span style="color: {status_color};">{status}</span>: `{criteria}`',
                unsafe_allow_html=True,
            )

        if len(cpe_entries) > 10:
            st.markdown(f"*...and {len(cpe_entries) - 10} more CPE entries*")


# Add direct file logging for debugging
def log_debug(message):
    """Write debug message directly to a file for troubleshooting"""
    operation_id = st.session_state.get("operation_id", str(uuid.uuid4())[:8])

    # Set operation ID in session state if not present
    if "operation_id" not in st.session_state:
        st.session_state.operation_id = operation_id

    try:
        with open("debug.log", "a") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} - [{operation_id}] {message}\n")
    except Exception as e:
        st.error(f"Error writing to debug log: {str(e)}")


# Function to check database status
def check_database_connection():
    """Check if database is accessible and return status info"""
    try:
        db_path = get_db_file_name()
        log_debug(f"Database path: {db_path}")

        # Check if file exists
        if not os.path.exists(db_path):
            return False, f"Database file does not exist at: {db_path}"

        # Test connection
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT sqlite_version()")
        version = cursor.fetchone()[0]
        conn.close()

        return True, f"Connected to SQLite version {version}, database at {db_path}"
    except Exception as e:
        log_debug(f"Database connection error: {str(e)}")
        return False, f"Database error: {str(e)}"


# Function to save CVE to database
def save_cve_to_database(cve_data):
    """Save or update CVE data in the database with comprehensive error handling"""
    cve_id = cve_data.get("cve_id", "Unknown")
    log_debug(f"Attempting to save CVE {cve_id} to database")

    # Add timestamp if not present
    if "processed_at" not in cve_data:
        cve_data["processed_at"] = datetime.now().isoformat()

    # Add operation ID for tracking
    cve_data["operation_id"] = st.session_state.operation_id

    # Check database connection first
    db_ok, db_message = check_database_connection()
    if not db_ok:
        log_debug(f"Database connection check failed: {db_message}")
        st.error(f"Database connection issue: {db_message}")
        return False

    # Show pre-save status
    with st.status(f"Saving {cve_id} to database...", expanded=True) as status:
        try:
            st.write("🔍 Checking database connection...")
            log_debug(f"Database connection verified for {cve_id}")

            st.write("💾 Executing save operation...")
            # Use store_or_update_cve for reliable saving
            save_result = store_or_update_cve(cve_data)
            log_debug(f"store_or_update_cve result: {save_result}")

            if not save_result:
                st.write("❌ Save operation returned False")
                log_debug(f"Save operation failed for {cve_id}")
                status.update(label=f"❌ Failed to save {cve_id}", state="error")
                return False

            st.write("✅ Save operation completed")

            # Verify the save by reading back from database
            st.write("🔍 Verifying saved data...")
            verification_data = get_cve_details(cve_id)
            if verification_data:
                log_debug(f"Verification successful - CVE found in database")
                log_debug(f"Saved timestamp: {verification_data.get('processed_at')}")
                st.write(
                    f"✅ Verification successful - CVE found with timestamp: {verification_data.get('processed_at')}"
                )

                # Update session state
                st.session_state.save_attempted = True
                st.session_state.save_success = True
                st.session_state.saved_cve_data = cve_data

                status.update(label=f"✅ Successfully saved {cve_id}", state="complete")
                return True
            else:
                log_debug(f"Verification failed - CVE not found in database after save")
                st.write("❌ Verification failed - CVE not found in database")
                st.warning("Save operation completed but verification failed - CVE not found in database")
                status.update(label=f"⚠️ Save completed but verification failed for {cve_id}", state="error")
                return False

        except Exception as e:
            error_msg = f"Exception during save operation: {str(e)}"
            log_debug(error_msg)
            log_debug(f"Stack trace: {traceback.format_exc()}")
            st.write(f"❌ Error: {error_msg}")
            st.error(f"Error saving to database: {str(e)}")
            status.update(label=f"❌ Error saving {cve_id}", state="error")
            return False


# Log session state at the start
log_debug(
    f"Page loaded/reloaded. Session state: save_attempted={st.session_state.save_attempted}, save_success={st.session_state.save_success}"
)

# Main execution flow
if lookup_button and cve_id:
    # Validate the CVE ID format
    if not is_valid_cve_id(cve_id):
        st.error("Please enter a valid CVE ID in the format CVE-YYYY-NNNNN.")
    else:
        log_debug(f"Looking up CVE: {cve_id}")

        # Check if we have a database connection
        db_ok, db_message = check_database_connection()
        if not db_ok:
            st.error(f"Cannot connect to the database: {db_message}")
        else:
            # Check if this CVE is in our local database first
            local_data = get_cve_details(cve_id)

            if local_data:
                # We found the CVE in our local database
                st.success(f"Found {cve_id} in local database!")

                # Display the local data
                display_cve_details(local_data)

                # Set up tabs for additional actions
                tabs = []
                tab_names = ["Manual Analysis", "Update Data"]

                # Add exploit search tab if requested
                if use_github or use_exploitdb:
                    tab_names.append("Search Exploits")

                tabs = st.tabs(tab_names)

                # Tab for manual analysis
                with tabs[0]:
                    st.markdown("### Manual Risk Analysis")
                    st.info("The AI analyzer can help assess the risk of this vulnerability.")

                    if st.button("Analyze with Gemini AI", type="primary"):
                        with st.spinner("Running AI analysis..."):
                            try:
                                # Run the Gemini analysis
                                analysis_result = asyncio.run(analyze_cve_with_gemini_async(local_data))

                                if analysis_result:
                                    st.success("Analysis completed!")

                                    # Update the database with the analysis results
                                    update_result = update_cve_priority(cve_id, analysis_result[0], analysis_result[1])

                                    if update_result:
                                        st.success("Database updated with analysis results")

                                        # Set the session state for saving
                                        st.session_state.save_attempted = True
                                        st.session_state.save_success = True

                                        # Rerun to refresh the data shown
                                        st.rerun()
                                    else:
                                        st.error("Failed to update database with analysis results")
                                else:
                                    st.error("Analysis failed. No results returned.")
                            except Exception as e:
                                st.error(f"Error during analysis: {str(e)}")
                                log_debug(f"Analysis error: {traceback.format_exc()}")

                # Tab for updating the CVE data
                with tabs[1]:
                    st.markdown("### Update CVE Data")
                    st.info("You can update the CVE data from official sources.")

                    # Add buttons for different update options
                    update_options = st.columns(2)

                    with update_options[0]:
                        if st.button("Update from NVD", type="primary"):
                            with st.spinner(f"Fetching {cve_id} data from NVD..."):
                                try:
                                    nvd_data = fetch_single_cve_details(cve_id)
                                    if nvd_data:
                                        # Update the local database with the NVD data
                                        update_result = store_or_update_cve(nvd_data)
                                        if update_result:
                                            st.success("Successfully updated from NVD")

                                            # Set the session state for saving
                                            st.session_state.save_attempted = True
                                            st.session_state.save_success = True

                                            # Rerun to refresh the data shown
                                            st.rerun()
                                        else:
                                            st.error("Failed to update database with NVD data")
                                    else:
                                        st.error(f"Could not find {cve_id} in NVD")
                                except Exception as e:
                                    st.error(f"Error updating from NVD: {str(e)}")
                                    log_debug(f"NVD update error: {traceback.format_exc()}")

                    with update_options[1]:
                        if st.button("Update EPSS Score", type="primary"):
                            with st.spinner("Fetching EPSS data..."):
                                try:
                                    epss_data = get_epss_score(cve_id)
                                    if epss_data:
                                        score, percentile = epss_data
                                        nvd_data["epss_score"] = score
                                        nvd_data["epss_percentile"] = percentile
                                        st.info(
                                            f"EPSS score: {score:.4f}"
                                            if score is not None
                                            else "EPSS score not available"
                                        )
                                    else:
                                        st.error(f"Could not find EPSS data for {cve_id}")
                                except Exception as e:
                                    st.error(f"Error fetching EPSS data: {str(e)}")
                                    log_debug(f"EPSS update error: {traceback.format_exc()}")

                # Tab for exploit search if requested
                if use_github or use_exploitdb:
                    with tabs[2]:
                        st.markdown("### Public Exploit Search")

                        with st.spinner(f"Searching for public exploits for {cve_id}..."):
                            try:
                                # Find public exploits
                                exploit_results = []

                                if use_github:
                                    github_exploits = search_github(cve_id)
                                    if github_exploits:
                                        exploit_results.extend(github_exploits)

                                if use_exploitdb:
                                    try:
                                        exploitdb_results = search_exploit_db(cve_id)
                                        if exploitdb_results:
                                            exploit_results.extend(exploitdb_results)
                                    except Exception as ex:
                                        st.warning(f"Error searching Exploit-DB: {str(ex)}")

                                # Display the results
                                display_exploit_results(cve_id, exploit_results)

                                # Update local_data with exploit information
                                if exploit_results and len(exploit_results) > 0:
                                    # Make a copy of local_data to avoid modifying the original
                                    updated_data = local_data.copy()
                                    updated_data["has_public_exploit"] = True
                                    updated_data["exploit_references"] = exploit_results

                                    if st.button("Save exploit data to database", key="save_exploit_data"):
                                        save_result = save_cve_to_database(updated_data)
                                        if save_result:
                                            st.success(f"Successfully saved exploit data for {cve_id}")
                                            st.rerun()
                                        else:
                                            st.error("Failed to save exploit data to database")
                            except Exception as e:
                                st.error(f"Error searching for exploits: {str(e)}")
                                log_debug(f"Exploit search error: {traceback.format_exc()}")

            else:
                # Not in local database, fetch from external sources
                st.info(f"{cve_id} not found in local database. Fetching live data...")

                # Collect data from all sources sequentially
                nvd_data = None
                exploit_results = []

                # 1. Fetch from NVD
                if use_nvd:
                    with st.spinner(f"Looking up {cve_id} from NVD..."):
                        nvd_data = fetch_single_cve_details(cve_id)
                        if nvd_data:
                            st.success(f"✅ Data successfully fetched from NVD!")
                            log_debug(f"NVD data fetched successfully for {cve_id}")
                        else:
                            st.error(f"❌ Could not find {cve_id} in NVD database.")
                            st.info("💡 **Possible reasons:**")
                            st.info("- The CVE ID doesn't exist yet")
                            st.info("- The CVE was published very recently and not yet in NVD")
                            st.info("- There was a network error")
                            st.info("- Try a known CVE like CVE-2023-12345")
                            log_debug(f"NVD lookup failed for {cve_id}")
                            st.stop()  # Stop execution if we can't find the CVE

                # 2. Fetch EPSS score if NVD data was found
                if nvd_data:
                    with st.spinner("Fetching EPSS score..."):
                        try:
                            epss_data = get_epss_score(cve_id)
                            if epss_data:
                                score, percentile = epss_data
                                nvd_data["epss_score"] = score
                                nvd_data["epss_percentile"] = percentile
                                st.info(f"EPSS score: {score:.4f}" if score is not None else "EPSS score not available")
                        except Exception as e:
                            st.error(f"Error fetching EPSS data: {str(e)}")

                # 3. Check KEV status if NVD data was found
                if nvd_data:
                    with st.spinner("Checking CISA KEV status..."):
                        try:
                            kev_catalog = fetch_kev_catalog()
                            if kev_catalog:
                                is_in_kev, kev_date_added = check_cve_in_kev(cve_id, kev_catalog)
                                nvd_data["is_in_kev"] = is_in_kev
                                nvd_data["kev_date_added"] = kev_date_added

                                if is_in_kev:
                                    st.warning(
                                        f"This vulnerability is in the CISA Known Exploited Vulnerabilities catalog! Added on {kev_date_added}"
                                    )
                        except Exception as e:
                            st.error(f"Error checking KEV status: {str(e)}")

                # 4. Run Gemini analysis if NVD data was found
                if nvd_data:
                    with st.spinner("Analyzing with Gemini AI..."):
                        try:
                            analysis_result = asyncio.run(analyze_cve_with_gemini_async(nvd_data))

                            if analysis_result:
                                priority, explanation = analysis_result
                                nvd_data["gemini_priority"] = priority
                                nvd_data["gemini_raw_response"] = explanation

                                # Display priority prominently in a colored box
                                priority_colors = {
                                    "HIGH": "red",
                                    "MEDIUM": "orange",
                                    "LOW": "green",
                                    "ERROR_ANALYZING": "gray",
                                }
                                priority_color = priority_colors.get(priority, "gray")

                                st.markdown(
                                    f"""
                                <div style="background-color: {priority_color}; color: white; padding: 15px; border-radius: 5px; text-align: center; margin: 10px 0;">
                                <span style="font-size: 20px; font-weight: bold;">Gemini Priority: {priority}</span>
                                </div>
                                """,
                                    unsafe_allow_html=True,
                                )
                        except Exception as e:
                            st.error(f"Error analyzing with Gemini: {str(e)}")

                # 5. Calculate risk score if NVD data was found
                if nvd_data:
                    with st.spinner("Calculating risk score..."):
                        try:
                            risk_score, alerts = analyze_cve_risk(nvd_data)
                            if risk_score is not None:
                                nvd_data["risk_score"] = risk_score
                                nvd_data["alerts"] = alerts

                                st.info(f"Risk score: {risk_score:.2f}")
                        except Exception as e:
                            st.error(f"Error calculating risk score: {str(e)}")

                # 6. Search for exploits if requested
                if nvd_data and (use_github or use_exploitdb):
                    with st.spinner(f"Searching for public exploits for {cve_id}..."):
                        try:
                            exploit_results = []

                            if use_github:
                                github_exploits = search_github(cve_id)
                                if github_exploits:
                                    exploit_results.extend(github_exploits)

                            if use_exploitdb:
                                try:
                                    exploitdb_results = search_exploit_db(cve_id)
                                    if exploitdb_results:
                                        exploit_results.extend(exploitdb_results)
                                except Exception as ex:
                                    st.warning(f"Error searching Exploit-DB: {str(ex)}")

                            if exploit_results and len(exploit_results) > 0:
                                nvd_data["has_public_exploit"] = True
                                nvd_data["exploit_references"] = exploit_results
                                st.warning(f"⚠️ **{len(exploit_results)} potential exploit(s) found**")

                                # Display exploit results
                                display_exploit_results(cve_id, exploit_results)
                        except Exception as e:
                            st.error(f"Error searching for exploits: {str(e)}")
                            log_debug(f"Exploit search error: {traceback.format_exc()}")

                # 7. Display details and save option
                if nvd_data:
                    # Store CVE data in session state for saving
                    st.session_state.current_cve_data = nvd_data
                    st.session_state.current_cve_id = cve_id

                    # Display detailed results
                    st.markdown("## Analysis Results")
                    display_cve_details(nvd_data, source="Live Data")

                    # Debug message
                    log_debug(f"About to show save button for {cve_id}")
                    st.info("💾 You can now save this CVE to your database")
                else:
                    st.error(f"Could not find {cve_id} in NVD database or an error occurred.")
                    log_debug(f"No nvd_data available for {cve_id}, save button not shown")

# Save button section - OUTSIDE the main lookup logic to avoid form interference
if "current_cve_data" in st.session_state and st.session_state.current_cve_data:
    st.markdown("---")

    current_cve_id = st.session_state.get("current_cve_id", "Unknown")

    # Add save to database option with enhanced visibility
    st.markdown("### 💾 Save to Database")
    st.markdown("Click the button below to save this CVE analysis to your local database:")

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        # Add immediate debug logging before button check
        save_button_clicked = st.button(
            "💾 Save to database", type="primary", key=f"save_isolated_{current_cve_id}", use_container_width=True
        )
        log_debug(f"Save button state for {current_cve_id}: {save_button_clicked}")

        if save_button_clicked:
            log_debug(f"✅ BUTTON CLICKED! Save button clicked for {current_cve_id}")
            st.info("🎯 Save button was clicked! Processing...")

            try:
                save_result = save_cve_to_database(st.session_state.current_cve_data)
                if save_result:
                    st.success(f"Successfully saved {current_cve_id} to the database")
                    # Clear the current CVE data after successful save
                    del st.session_state.current_cve_data
                    del st.session_state.current_cve_id
                    st.rerun()
                else:
                    st.error("Failed to save to database")
            except Exception as e:
                st.error(f"Error saving to database: {str(e)}")
                log_debug(f"Save error for {current_cve_id}: {str(e)}")

    # Add explicit instructions
    st.markdown("**Instructions:**")
    st.markdown("1. ☝️ Click the blue 'Save to database' button above")
    st.markdown("2. 📊 Check the debug section below for confirmation")
    st.markdown("3. 🔍 Verify in the main dashboard that your CVE was saved")

    # Test button for debugging
    test_button_clicked = st.button("🔧 Test Save Function", key=f"test_isolated_{current_cve_id}")
    log_debug(f"Test button state for {current_cve_id}: {test_button_clicked}")

    if test_button_clicked:
        log_debug(f"✅ TEST BUTTON CLICKED! Test save button clicked for {current_cve_id}")
        st.info("🎯 Test button clicked! Check the debug logs to confirm this is working.")
        st.session_state.save_attempted = True
        st.session_state.save_success = False  # Mark as test

# Display saved CVE information
if st.session_state.save_attempted and st.session_state.save_success and st.session_state.saved_cve_data:
    st.markdown("---")
    st.markdown("### Saved CVE Details")

    # Create an expandable section with details
    with st.expander("View saved data", expanded=False):
        saved_data = st.session_state.saved_cve_data
        st.markdown(f"**CVE ID:** {saved_data.get('cve_id')}")
        st.markdown(f"**Priority:** {saved_data.get('gemini_priority', 'N/A')}")
        st.markdown(f"**CVSS Score:** {saved_data.get('cvss_v3_score', 'N/A')}")
        st.markdown(f"**Risk Score:** {saved_data.get('risk_score', 'N/A')}")
        st.markdown(f"**Saved at:** {saved_data.get('processed_at', 'N/A')}")

# Debug section
st.markdown("---")
with st.expander("🔧 Debug Information", expanded=False):
    st.markdown("### Database Status")

    # Check database connection
    db_ok, db_message = check_database_connection()
    if db_ok:
        st.success(f"✅ {db_message}")
    else:
        st.error(f"❌ {db_message}")

    # Show session state info
    st.markdown("### Session State")
    st.json(
        {
            "save_attempted": st.session_state.get("save_attempted", False),
            "save_success": st.session_state.get("save_success", False),
            "operation_id": st.session_state.get("operation_id", "None"),
            "has_saved_data": st.session_state.get("saved_cve_data") is not None,
        }
    )

    # Show recent debug log entries
    st.markdown("### Recent Debug Logs")
    try:
        if os.path.exists("debug.log"):
            with open("debug.log", "r") as f:
                lines = f.readlines()
                recent_lines = lines[-20:] if len(lines) > 20 else lines  # Show last 20 lines
                if recent_lines:
                    st.text_area("Debug Log (last 20 entries):", "\n".join(recent_lines), height=200)
                else:
                    st.info("Debug log is empty")
        else:
            st.info("Debug log file not found")
    except Exception as e:
        st.error(f"Error reading debug log: {str(e)}")

    # Show database debug logs
    st.markdown("### Database Debug Logs")
    try:
        if os.path.exists("database_debug.log"):
            with open("database_debug.log", "r") as f:
                lines = f.readlines()
                recent_lines = lines[-20:] if len(lines) > 20 else lines  # Show last 20 lines
                if recent_lines:
                    st.text_area("Database Debug Log (last 20 entries):", "\n".join(recent_lines), height=200)
                else:
                    st.info("Database debug log is empty")
        else:
            st.info("Database debug log file not found")
    except Exception as e:
        st.error(f"Error reading database debug log: {str(e)}")

    # Add button to clear session state
    if st.button("Clear Session State", type="secondary"):
        st.session_state.save_attempted = False
        st.session_state.save_success = False
        st.session_state.saved_cve_data = None
        st.session_state.operation_id = str(uuid.uuid4())
        st.rerun()
