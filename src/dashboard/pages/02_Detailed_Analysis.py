"""
VIPER CTI Dashboard - Detailed Vulnerability Analysis Page
"""
import json
import os
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Add the project root directory to the path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from src.clients.nvd_client import fetch_single_cve_details
from src.utils.database_handler import (
    get_all_cves_with_details,
    get_articles_for_cve,
    get_cve_details,
    get_filtered_cves,
    update_cve_exploit_data,
)
from src.utils.pdf_generator import generate_cve_report

# Set the page title and add refresh button at the top right
title_col, refresh_col = st.columns([6, 1])
with title_col:
    st.title("🔍 Detailed Vulnerability Analysis")
with refresh_col:
    st.markdown("<div style='margin-top: 15px;'></div>", unsafe_allow_html=True)  # Adding some vertical space
    if st.button("🔄 Refresh", type="primary", use_container_width=True):
        st.rerun()

# Sidebar for filtering
st.sidebar.header("Find Vulnerability")

# Search by CVE ID
cve_search = st.sidebar.text_input("Search by CVE ID", placeholder="e.g., CVE-2023-1234")

# Search by keyword
keyword_search = st.sidebar.text_input("Search by Keyword", placeholder="Search in description...")

# Priority filter
priority_filter = st.sidebar.multiselect("Filter by Priority", options=["HIGH", "MEDIUM", "LOW"], default=[])

# KEV filter
kev_filter = st.sidebar.checkbox("Only show CISA KEV entries", value=False)

# Apply search/filters
search_button = st.sidebar.button("Search", type="primary")

# Add a note about the Live CVE Lookup page
st.sidebar.markdown("---")
st.sidebar.info(
    "For detailed lookup of a specific CVE ID, including exploit search, please use the [Live CVE Lookup](Live_CVE_Lookup) page."
)


# Load all CVEs with details
@st.cache_data(ttl=300)  # Cache for 5 minutes
def load_cve_data():
    return get_all_cves_with_details()


# Get filtered data based on search criteria
def get_search_results(cve_id=None, keyword=None, priorities=None, is_in_kev=None):
    if cve_id and re.match(r"^CVE-\d{4}-\d+$", cve_id):
        # If specific CVE ID is provided, get just that one
        results = get_filtered_cves(keyword=cve_id)
    else:
        # Otherwise apply filters
        results = get_filtered_cves(
            keyword=keyword if keyword else None,
            priorities=priorities if priorities else None,
            is_in_kev=is_in_kev,
        )
    return results


# Get the CVE data
if search_button or "detailed_cve_data" not in st.session_state:
    with st.spinner("Loading vulnerability data..."):
        if search_button:
            # Apply filters when search button is clicked
            st.session_state.detailed_cve_data = get_search_results(
                cve_id=cve_search,
                keyword=keyword_search if keyword_search else None,
                priorities=priority_filter if priority_filter else None,
                is_in_kev=True if kev_filter else None,
            )
        else:
            # Initial load - get all CVEs
            st.session_state.detailed_cve_data = load_cve_data()

# If no data, display a message
if not st.session_state.detailed_cve_data:
    st.info("No vulnerabilities found with the current search criteria. Try adjusting your search.")
    st.stop()

# Convert to DataFrame
df = pd.DataFrame(st.session_state.detailed_cve_data)

# Convert date strings to datetime with error handling
if "published_date" in df.columns:
    # Use utc=True to handle mixed timezones properly
    df["published_date"] = pd.to_datetime(df["published_date"], errors="coerce", utc=True)
if "kev_date_added" in df.columns:
    df["kev_date_added"] = pd.to_datetime(df["kev_date_added"], errors="coerce", utc=True)
if "patch_tuesday_date" in df.columns:
    df["patch_tuesday_date"] = pd.to_datetime(df["patch_tuesday_date"], errors="coerce", utc=True)

# Get a list of CVE IDs for selection
cve_list = df["cve_id"].tolist()

# Right-side selection box
selected_cve = st.selectbox("Select a vulnerability for detailed analysis:", options=cve_list, index=0)

# Get the selected CVE data
selected_data = df[df["cve_id"] == selected_cve].iloc[0].to_dict()

# Display the CVE details
st.markdown("---")

# Title and badges row
col1, col2 = st.columns([2, 3])

with col1:
    st.markdown(f"## {selected_cve}")

    # Generate badges
    priority_colors = {"HIGH": "red", "MEDIUM": "orange", "LOW": "green"}
    priority = selected_data.get("gemini_priority", "UNKNOWN")
    priority_color = priority_colors.get(priority, "gray")

    # Format badges - use simplified HTML format to avoid rendering issues
    badges_html = '<div style="display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 15px;">'

    # Priority badge
    badges_html += f'<span style="background-color: {priority_color}; color: white; padding: 5px 10px; border-radius: 5px; font-weight: bold;">{priority} Priority</span>'

    # Add KEV badge if applicable
    if selected_data.get("is_in_kev"):
        badges_html += '<span style="background-color: #d9534f; color: white; padding: 5px 10px; border-radius: 5px; font-weight: bold;">CISA KEV</span>'

    badges_html += "</div>"
    st.markdown(badges_html, unsafe_allow_html=True)

    # Basic metadata
    pub_date = selected_data.get("published_date")
    st.markdown(f"**Published Date:** {pub_date.strftime('%Y-%m-%d') if pd.notnull(pub_date) else 'Unknown'}")

    if selected_data.get("is_in_kev") and pd.notnull(selected_data.get("kev_date_added")):
        kev_date = selected_data.get("kev_date_added")
        st.markdown(f"**Added to KEV:** {kev_date.strftime('%Y-%m-%d') if pd.notnull(kev_date) else 'Unknown'}")

    # Microsoft-specific information if available
    ms_severity = selected_data.get("microsoft_severity")
    if ms_severity:
        try:
            ms_product = selected_data.get("microsoft_product_family", "Unknown")
            ms_specific = selected_data.get("microsoft_product_name", "Unknown")
            patch_date = selected_data.get("patch_tuesday_date")

            # Format Microsoft information with styling based on severity
            severity_color = {
                "Critical": "red",
                "Important": "orange",
                "Moderate": "blue",
                "Low": "green",
            }.get(ms_severity, "gray")

            # Use simplified HTML format to avoid rendering issues
            ms_info_html = f"""<div style="background-color: rgba(0,0,0,0.05); padding: 10px; border-radius: 5px; margin-top: 10px; border-left: 4px solid {severity_color};">
<span style="font-weight: bold; color: {severity_color};">Microsoft {ms_severity}</span><br>
<b>Product Family:</b> {ms_product}<br>
<b>Specific Product:</b> {ms_specific}<br>
<b>Patch Tuesday:</b> {patch_date.strftime('%Y-%m-%d') if pd.notnull(patch_date) else 'Unknown'}
</div>"""
            st.markdown(ms_info_html, unsafe_allow_html=True)
        except Exception as e:
            st.error(f"Error processing Microsoft information: {str(e)}")

with col2:
    st.markdown("### Description")
    st.markdown(selected_data.get("description", "No description available"))

# Metrics row
st.markdown("---")
st.markdown("### Risk Metrics")

metric_cols = st.columns(5)

with metric_cols[0]:
    cvss = selected_data.get("cvss_v3_score")
    cvss_color = "normal"
    if cvss is not None and cvss >= 7.0:
        cvss_color = "off"
    st.metric("CVSS Score", f"{cvss:.1f}" if pd.notnull(cvss) else "N/A", delta_color=cvss_color)

with metric_cols[1]:
    epss = selected_data.get("epss_score")
    epss_color = "normal"
    if epss is not None and epss >= 0.5:
        epss_color = "off"
    st.metric("EPSS Score", f"{epss:.4f}" if pd.notnull(epss) else "N/A", delta_color=epss_color)

with metric_cols[2]:
    epss_percentile = selected_data.get("epss_percentile")
    st.metric("EPSS Percentile", f"{epss_percentile:.2f}" if pd.notnull(epss_percentile) else "N/A")

with metric_cols[3]:
    risk_score = selected_data.get("risk_score")
    risk_color = "normal"
    if risk_score is not None and risk_score >= 0.7:
        risk_color = "off"
    st.metric(
        "Risk Score",
        f"{risk_score:.2f}" if pd.notnull(risk_score) else "N/A",
        delta_color=risk_color,
    )

with metric_cols[4]:
    ms_severity_value = selected_data.get("microsoft_severity")
    if pd.notnull(ms_severity_value):
        # Use color based on severity
        ms_delta_color = {
            "Critical": "off",
            "Important": "off",
            "Moderate": "normal",
            "Low": "normal",
        }.get(ms_severity_value, "normal")

        st.metric("MS Severity", ms_severity_value, delta_color=ms_delta_color)
    else:
        st.metric("MS Severity", "N/A")

# AI Analysis section
st.markdown("---")
st.markdown("### AI Analysis")

# Extract the priority explanation from the alerts
alerts = selected_data.get("alerts", [])
priority_reasoning = None

for alert in alerts:
    if "Priority assigned based on" in alert:
        priority_reasoning = alert
        break

if priority_reasoning:
    st.info(priority_reasoning)
else:
    st.info("The AI has assigned a priority level based on the vulnerability characteristics and context.")

# Alert cards for any additional alerts
if alerts:
    other_alerts = [a for a in alerts if a != priority_reasoning]
    if other_alerts:
        st.markdown("### Alerts and Concerns")
        for alert in other_alerts:
            st.warning(alert)

# External Threat Intelligence section
st.markdown("---")

# Fetch analyzed articles for this CVE
try:
    threat_articles = get_articles_for_cve(selected_cve)

    if threat_articles:
        st.subheader("🌐 External Threat Intelligence Analysis")
        st.markdown(
            f"Found {len(threat_articles)} analyzed threat intelligence article(s) related to this vulnerability:"
        )

        # Loop through each article
        for article in threat_articles:
            title = article.get("title", "Unknown Title")
            url = article.get("url", "#")

            # Create an expander for each article
            with st.expander(f"📄 {title}"):
                # Display the source URL
                st.markdown(f"**Source:** [View Original Article]({url})")

                # AI Summary
                summary = article.get("llm_summary", "No summary available.")
                if summary and summary.strip():
                    st.info(f"**AI Summary:** {summary}")

                # Create columns for better layout
                col1, col2 = st.columns(2)

                # Column 1: Actors & Malware
                with col1:
                    st.write("**Mentioned Threat Actors:**")
                    try:
                        actors_json = article.get("llm_mentioned_actors", "[]")
                        if actors_json:
                            actors = json.loads(actors_json) if isinstance(actors_json, str) else actors_json
                            if actors and len(actors) > 0:
                                # Convert to DataFrame if it's a simple list
                                if isinstance(actors, list) and all(isinstance(x, str) for x in actors):
                                    actors_df = pd.DataFrame(actors, columns=["Threat Actor"])
                                else:
                                    actors_df = pd.DataFrame(actors)
                                col1.dataframe(actors_df, hide_index=True, use_container_width=True)
                            else:
                                col1.write("*No threat actors mentioned*")
                        else:
                            col1.write("*No threat actors mentioned*")
                    except (json.JSONDecodeError, Exception) as e:
                        col1.write("*Error parsing threat actor data*")

                    st.write("")  # Add some spacing

                    st.write("**Mentioned Malware:**")
                    try:
                        malware_json = article.get("llm_mentioned_malware", "[]")
                        if malware_json:
                            malware = json.loads(malware_json) if isinstance(malware_json, str) else malware_json
                            if malware and len(malware) > 0:
                                # Convert to DataFrame if it's a simple list
                                if isinstance(malware, list) and all(isinstance(x, str) for x in malware):
                                    malware_df = pd.DataFrame(malware, columns=["Malware Family"])
                                else:
                                    malware_df = pd.DataFrame(malware)
                                col1.dataframe(malware_df, hide_index=True, use_container_width=True)
                            else:
                                col1.write("*No malware families mentioned*")
                        else:
                            col1.write("*No malware families mentioned*")
                    except (json.JSONDecodeError, Exception) as e:
                        col1.write("*Error parsing malware data*")

                # Column 2: TTPs & IOCs
                with col2:
                    st.write("**Identified TTPs (MITRE ATT&CK):**")
                    try:
                        ttps_json = article.get("llm_identified_ttps", "[]")
                        if ttps_json:
                            ttps = json.loads(ttps_json) if isinstance(ttps_json, str) else ttps_json
                            if ttps and len(ttps) > 0:
                                # Convert to DataFrame if it's a simple list
                                if isinstance(ttps, list) and all(isinstance(x, str) for x in ttps):
                                    ttps_df = pd.DataFrame(ttps, columns=["TTP ID"])
                                else:
                                    ttps_df = pd.DataFrame(ttps)
                                col2.dataframe(ttps_df, hide_index=True, use_container_width=True)
                            else:
                                col2.write("*No TTPs identified*")
                        else:
                            col2.write("*No TTPs identified*")
                    except (json.JSONDecodeError, Exception) as e:
                        col2.write("*Error parsing TTP data*")

                    st.write("")  # Add some spacing

                    st.write("**Extracted IOCs:**")
                    try:
                        iocs_json = article.get("llm_extracted_iocs", "[]")
                        if iocs_json:
                            iocs = json.loads(iocs_json) if isinstance(iocs_json, str) else iocs_json
                            if iocs and len(iocs) > 0:
                                # IOCs should be a list of dictionaries with 'value' and 'type'
                                if isinstance(iocs, list) and len(iocs) > 0:
                                    iocs_df = pd.DataFrame(iocs)
                                    col2.dataframe(iocs_df, hide_index=True, use_container_width=True)
                                else:
                                    col2.write("*No IOCs extracted*")
                            else:
                                col2.write("*No IOCs extracted*")
                        else:
                            col2.write("*No IOCs extracted*")
                    except (json.JSONDecodeError, Exception) as e:
                        col2.write("*Error parsing IOC data*")

                # Add article metadata at the bottom
                fetched_date = article.get("fetched_date", "Unknown")
                if fetched_date != "Unknown":
                    try:
                        fetched_dt = datetime.fromisoformat(fetched_date.replace("Z", "+00:00"))
                        fetched_date = fetched_dt.strftime("%Y-%m-%d %H:%M")
                    except (ValueError, TypeError):
                        pass

                st.caption(f"Article fetched: {fetched_date}")

    else:
        # Only show this message if the user specifically searched for a CVE
        if cve_search and re.match(r"^CVE-\d{4}-\d+$", cve_search):
            st.info(
                "🔍 No external threat intelligence articles found for this CVE. Articles are fetched for HIGH and MEDIUM priority vulnerabilities during the regular analysis workflow."
            )

except Exception as e:
    st.error(f"Error loading threat intelligence data: {str(e)}")

# Technical Details section
st.markdown("---")
st.markdown("### Technical Context")

# Historical trends for EPSS and CVE publication
context_cols = st.columns(2)

with context_cols[0]:
    # Show the EPSS history if we had it (would need additional data)
    st.markdown("#### Exploitation Probability")
    st.info(
        "This vulnerability has an EPSS score that indicates the probability of exploitation within the next 30 days."
    )

    # Create a gauge chart for EPSS
    if pd.notnull(selected_data.get("epss_score")):
        epss_value = selected_data.get("epss_score")
        fig = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=epss_value,
                number={"valueformat": ".4f"},
                domain={"x": [0, 1], "y": [0, 1]},
                title={"text": "EPSS Score"},
                gauge={
                    "axis": {"range": [0, 1], "tickwidth": 1},
                    "bar": {"color": "darkred"},
                    "steps": [
                        {"range": [0, 0.1], "color": "lightgreen"},
                        {"range": [0.1, 0.3], "color": "yellow"},
                        {"range": [0.3, 0.5], "color": "orange"},
                        {"range": [0.5, 1], "color": "red"},
                    ],
                    "threshold": {
                        "line": {"color": "black", "width": 4},
                        "thickness": 0.75,
                        "value": epss_value,
                    },
                },
            )
        )
        fig.update_layout(height=250)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.write("EPSS data not available for this vulnerability.")

with context_cols[1]:
    st.markdown("#### Risk Factors")

    # Create a bullet chart for risk factors
    risk_factors = [
        {
            "name": "Base CVSS",
            "value": selected_data.get("cvss_v3_score", 0) if pd.notnull(selected_data.get("cvss_v3_score")) else 0,
        },
        {
            "name": "EPSS Factor",
            "value": selected_data.get("epss_score", 0) * 10 if pd.notnull(selected_data.get("epss_score")) else 0,
        },
        {"name": "KEV Factor", "value": 10 if selected_data.get("is_in_kev") else 0},
    ]

    # Add public exploit factor to the risk factors
    if selected_data.get("has_public_exploit"):
        risk_factors.append({"name": "Public Exploit", "value": 8.5})  # Value reflects the boost from config

    # Create a horizontal bar chart
    risk_df = pd.DataFrame(risk_factors)
    fig = px.bar(
        risk_df,
        x="value",
        y="name",
        orientation="h",
        color="value",
        color_continuous_scale=["green", "yellow", "orange", "red"],
        range_color=[0, 10],
        title="Risk Factor Breakdown",
    )
    fig.update_layout(height=250)
    st.plotly_chart(fig, use_container_width=True)

# Public Exploits section
if selected_data.get("has_public_exploit"):
    st.markdown("---")
    st.markdown("### Public Exploits")

    exploit_references = selected_data.get("exploit_references")

    # Check if we have exploit information in the right format
    if exploit_references:
        try:
            # If it's a string, try to parse it as JSON
            if isinstance(exploit_references, str):
                import json

                exploit_references = json.loads(exploit_references)

            # Check if we have a list of exploits
            if isinstance(exploit_references, list) and len(exploit_references) > 0:
                st.error(f"⚠️ **{len(exploit_references)} public exploit(s) found for this vulnerability**")

                # Group exploits by source
                exploits_by_source = {}
                for exploit in exploit_references:
                    source = exploit.get("source", "Unknown")
                    if source not in exploits_by_source:
                        exploits_by_source[source] = []
                    exploits_by_source[source].append(exploit)

                # Display exploits by source in expandable sections
                for source, exploits in exploits_by_source.items():
                    with st.expander(f"{source} ({len(exploits)})", expanded=True):
                        for i, exploit in enumerate(exploits):
                            title = exploit.get("title", "Unknown Title")
                            url = exploit.get("url", "#")
                            exploit_type = exploit.get("type", "Unknown Type")
                            published = exploit.get("date_published", "Unknown")

                            # Format the date if it's not "Unknown"
                            if published != "Unknown":
                                try:
                                    published_date = datetime.fromisoformat(published.replace("Z", "+00:00"))
                                    published = published_date.strftime("%Y-%m-%d")
                                except (ValueError, TypeError):
                                    pass

                            # Display exploit information in a card-like format
                            st.markdown(
                                f"""
                            <div style="border: 1px solid #f63366; border-radius: 5px; padding: 10px; margin-bottom: 10px;">
                                <h4 style="margin-top:0;">{title}</h4>
                                <p><strong>Type:</strong> {exploit_type}</p>
                                <p><strong>Published:</strong> {published}</p>
                                <a href="{url}" target="_blank" rel="noopener noreferrer">
                                    <button style="background-color: #f63366; color: white; border: none; padding: 5px 10px; border-radius: 5px; cursor: pointer;">
                                        View Exploit
                                    </button>
                                </a>
                            </div>
                            """,
                                unsafe_allow_html=True,
                            )

                # Add a warning note
                st.warning(
                    """
                **Warning**: The exploits listed above are publicly available and may be used by threat actors.
                It is strongly recommended to apply patches or mitigations as soon as possible.
                """
                )
            else:
                st.info("Exploit information is available but could not be displayed in detail.")
        except Exception as e:
            st.error(f"Error processing exploit data: {str(e)}")
    else:
        st.info("Public exploits have been found, but detailed information is not available.")
else:
    # Don't display anything if no public exploits
    pass

# Mitigation recommendations
st.markdown("---")
st.markdown("### Recommended Actions")

# Generate generic recommendations based on priority
priority = selected_data.get("gemini_priority")
if priority == "HIGH":
    st.error(
        """
    ### Immediate Action Required

    - Apply patches or updates as soon as they become available
    - Implement temporary mitigations or workarounds if patches are not yet available
    - Monitor systems for signs of exploitation
    - Consider isolating vulnerable systems if mitigation is not possible
    """
    )
elif priority == "MEDIUM":
    st.warning(
        """
    ### Action Recommended

    - Plan to apply patches during the next maintenance window
    - Review and implement available mitigations
    - Monitor for increases in exploitation activity
    - Include in regular vulnerability management processes
    """
    )
else:
    st.info(
        """
    ### Standard Remediation

    - Address according to normal vulnerability management procedures
    - Apply patches during regular maintenance cycles
    - Document in vulnerability tracking system
    """
    )

# If this has public exploits, add specific recommendations
if selected_data.get("has_public_exploit"):
    st.error(
        """
    ### Public Exploit Mitigation

    This vulnerability has publicly available exploits, which means:

    - Attackers can easily weaponize this vulnerability
    - Patch immediately, even outside regular patching cycles
    - Consider additional preventive controls like WAF rules or IPS signatures
    - Increase monitoring for exploitation attempts
    """
    )

# If this is a KEV, add additional KEV-specific recommendation
if selected_data.get("is_in_kev"):
    st.error(
        """
    ### CISA KEV Directive

    This vulnerability is in CISA's Known Exploited Vulnerabilities (KEV) catalog, which means:

    - Federal agencies are required to remediate according to CISA timelines
    - Active exploitation has been observed in the wild
    - This vulnerability should be prioritized for remediation regardless of CVSS score
    """
    )

# If this has Microsoft patch information, add specific guidance
ms_severity = selected_data.get("microsoft_severity")
if ms_severity:
    if ms_severity == "Critical":
        st.error(
            """
        ### Microsoft Critical Guidance

        Microsoft has rated this as a Critical vulnerability:

        - Deploy patches immediately, even outside regular patching cycles
        - Critical vulnerabilities often involve remote code execution or privilege escalation
        - Prioritize systems directly exposed to the internet
        - Consider emergency change approval if needed
        """
        )
    elif ms_severity == "Important":
        st.warning(
            """
        ### Microsoft Important Guidance

        Microsoft has rated this as an Important vulnerability:

        - Apply patches according to your standard patching schedule (typically within 30 days)
        - Important vulnerabilities represent significant security risks but might require additional factors to exploit
        - Prioritize based on system exposure and criticality
        """
        )
    else:
        st.info(
            f"""
        ### Microsoft {ms_severity} Guidance

        Microsoft has rated this as a {ms_severity} vulnerability:

        - Apply patches during regular maintenance cycles
        - These vulnerabilities typically represent lower security risks
        - Prioritize based on system exposure and criticality
        """
        )

# Generate PDF report for the selected CVE
try:
    pdf_bytes = generate_cve_report(selected_data)

    # Add a button to export the analysis as PDF
    st.download_button(
        label="Export Analysis Report (PDF)",
        data=pdf_bytes,
        file_name=f"{selected_cve}_analysis.pdf",
        mime="application/pdf",
    )
except Exception as e:
    st.error(f"Error generating PDF report: {str(e)}")
    # Keep the disabled button as a fallback
    st.download_button(
        label="Export Analysis Report (PDF)",
        data="Error generating PDF",
        file_name=f"{selected_cve}_analysis.pdf",
        mime="application/pdf",
        disabled=True,
    )

# Add footer with timestamp
st.markdown("---")
st.markdown(f"*Analysis generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
