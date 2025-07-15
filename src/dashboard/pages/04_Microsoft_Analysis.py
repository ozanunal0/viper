"""
VIPER CTI Dashboard - Microsoft Patch Tuesday Analysis Page
"""
import calendar
import os
import sys
from datetime import datetime, timedelta

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Add the project root directory to the path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from src.utils.database_handler import get_all_cves_with_details, get_filtered_cves

# Set the page title and add refresh button at the top right
title_col, refresh_col = st.columns([6, 1])
with title_col:
    st.title("🪟 Microsoft Vulnerability Analysis")
with refresh_col:
    st.markdown("<div style='margin-top: 15px;'></div>", unsafe_allow_html=True)  # Adding some vertical space
    if st.button("🔄 Refresh", type="primary", use_container_width=True):
        st.rerun()


# Load all CVEs with details
@st.cache_data(ttl=300)  # Cache for 5 minutes
def load_all_cve_data():
    return get_all_cves_with_details()


# Get all Microsoft CVEs
@st.cache_data(ttl=300)  # Cache for 5 minutes
def load_microsoft_cves():
    all_cves = load_all_cve_data()
    # Filter only CVEs with Microsoft data
    microsoft_cves = [cve for cve in all_cves if cve.get("microsoft_severity") is not None]
    return microsoft_cves


# Get the CVE data
with st.spinner("Loading Microsoft vulnerability data..."):
    microsoft_cves = load_microsoft_cves()

# If no data, display a message
if not microsoft_cves:
    st.info("No Microsoft Patch Tuesday data available. Make sure to run the CLI application to fetch the latest data.")
    st.stop()

# Convert to DataFrame
df = pd.DataFrame(microsoft_cves)

# Convert date strings to datetime with error handling
if "published_date" in df.columns:
    df["published_date"] = pd.to_datetime(df["published_date"], errors="coerce", utc=True)
if "patch_tuesday_date" in df.columns:
    df["patch_tuesday_date"] = pd.to_datetime(df["patch_tuesday_date"], errors="coerce", utc=True)

# Sidebar filters
st.sidebar.header("Microsoft Filters")

# Severity filter
severity_filter = st.sidebar.multiselect(
    "Microsoft Severity",
    options=df["microsoft_severity"].dropna().unique().tolist(),
    default=["Critical"] if "Critical" in df["microsoft_severity"].dropna().unique().tolist() else [],
)

# Product family filter
if "microsoft_product_family" in df.columns:
    # Extract unique product families (handling comma-separated values)
    all_product_families = []
    for products in df["microsoft_product_family"].dropna():
        all_product_families.extend([p.strip() for p in products.split(",")])
    unique_product_families = sorted(list(set(all_product_families)))

    product_filter = st.sidebar.multiselect("Product Family", options=unique_product_families, default=[])

# Date range filter
if "patch_tuesday_date" in df.columns:
    # Check if there are any valid dates in the column
    valid_dates = df["patch_tuesday_date"].dropna()

    if not valid_dates.empty:
        min_date = valid_dates.min().date()
        max_date = valid_dates.max().date()

        date_range = st.sidebar.date_input(
            "Patch Tuesday Date Range",
            value=(min_date, max_date),
            min_value=min_date,
            max_value=max_date,
        )
    else:
        st.sidebar.info("No valid Patch Tuesday dates available for filtering.")
        date_range = None

    if date_range is not None and len(date_range) == 2:
        start_date, end_date = date_range
        if start_date and end_date:
            # First drop rows with NaN patch_tuesday_date to avoid the .dt accessor error
            df_valid_dates = df.dropna(subset=["patch_tuesday_date"])

            # Apply the date filter only on valid dates
            if not df_valid_dates.empty:
                df = df_valid_dates[
                    (df_valid_dates["patch_tuesday_date"].dt.date >= start_date)
                    & (df_valid_dates["patch_tuesday_date"].dt.date <= end_date)
                ]
            else:
                st.warning("No valid patch Tuesday dates found. Cannot apply date filter.")
                df = pd.DataFrame()  # Empty dataframe if no valid dates

# Apply severity filter
if severity_filter:
    df = df[df["microsoft_severity"].isin(severity_filter)]

# Apply product filter
if "microsoft_product_family" in df.columns and product_filter:
    # Filter for any product family that contains any of the selected products
    df = df[
        df["microsoft_product_family"].apply(
            lambda x: any(product in str(x).split(",") for product in product_filter) if pd.notnull(x) else False
        )
    ]

# Show metrics
st.subheader("Microsoft Vulnerability Metrics")
metric_cols = st.columns(4)

with metric_cols[0]:
    st.metric("Total Microsoft CVEs", len(df))

with metric_cols[1]:
    critical_count = len(df[df["microsoft_severity"] == "Critical"]) if "microsoft_severity" in df.columns else 0
    st.metric("Critical Vulnerabilities", critical_count)

with metric_cols[2]:
    if "patch_tuesday_date" in df.columns:
        latest_patch = df["patch_tuesday_date"].max()
        latest_patch_str = latest_patch.strftime("%Y-%m-%d") if pd.notnull(latest_patch) else "N/A"
        latest_count = len(df[df["patch_tuesday_date"] == latest_patch])
        st.metric("Latest Patch Tuesday", latest_patch_str, delta=f"{latest_count} CVEs")
    else:
        st.metric("Latest Patch Tuesday", "N/A")

with metric_cols[3]:
    # Count CVEs that are also in the KEV catalog
    kev_count = int(df["is_in_kev"].sum()) if "is_in_kev" in df.columns else 0
    kev_pct = f"{kev_count/len(df)*100:.1f}%" if len(df) > 0 else "0%"
    st.metric("In CISA KEV", kev_count, delta=kev_pct, delta_color="off")

# Severity distribution chart
st.subheader("Microsoft Severity Distribution")
severity_cols = st.columns(2)

with severity_cols[0]:
    if "microsoft_severity" in df.columns:
        severity_counts = df["microsoft_severity"].value_counts().reset_index()
        severity_counts.columns = ["Severity", "Count"]

        # Define colors for severities
        colors = {
            "Critical": "#ff4b4b",
            "Important": "#ffa64b",
            "Moderate": "#4b9fff",
            "Low": "#4bff4b",
        }

        fig_severity = px.pie(
            severity_counts,
            values="Count",
            names="Severity",
            color="Severity",
            color_discrete_map=colors,
            title="Distribution by Severity",
        )
        fig_severity.update_traces(textposition="inside", textinfo="percent+label")
        st.plotly_chart(fig_severity, use_container_width=True)

with severity_cols[1]:
    if "patch_tuesday_date" in df.columns and "microsoft_severity" in df.columns:
        # Only proceed if we have valid dates
        df_valid_dates = df.dropna(subset=["patch_tuesday_date"])

        if not df_valid_dates.empty:
            # Group by month and severity
            df_valid_dates["month"] = df_valid_dates["patch_tuesday_date"].dt.to_period("M")
            severity_by_month = (
                df_valid_dates.groupby(["month", "microsoft_severity"]).size().unstack(fill_value=0).reset_index()
            )
            severity_by_month["month_start"] = severity_by_month["month"].dt.to_timestamp()

            # Get available severity columns (some might be missing)
            available_severities = [
                col for col in ["Critical", "Important", "Moderate", "Low"] if col in severity_by_month.columns
            ]

            if available_severities:
                # Create stacked bar chart
                fig_severity_time = px.bar(
                    severity_by_month,
                    x="month_start",
                    y=available_severities,
                    title="Severity Distribution by Month",
                    labels={"value": "Number of CVEs", "month_start": "Month"},
                    color_discrete_map=colors,
                )
                st.plotly_chart(fig_severity_time, use_container_width=True)
            else:
                st.info("No severity data available for time series chart.")
        else:
            st.info("No valid patch Tuesday dates available for time series analysis.")

# Product distribution
st.subheader("Product Analysis")
product_cols = st.columns(2)

with product_cols[0]:
    if "microsoft_product_family" in df.columns:
        # Process product families (they might be comma-separated)
        all_products = []
        for products in df["microsoft_product_family"].dropna():
            all_products.extend([p.strip() for p in products.split(",")])

        # Count occurrences
        product_counts = pd.Series(all_products).value_counts().reset_index()
        product_counts.columns = ["Product", "Count"]

        # Take top 10 products
        top_products = product_counts.head(10)

        # Create bar chart
        fig_products = px.bar(
            top_products,
            x="Count",
            y="Product",
            orientation="h",
            title="Top 10 Affected Products",
            color="Count",
            color_continuous_scale=["lightblue", "blue", "darkblue"],
        )
        st.plotly_chart(fig_products, use_container_width=True)

with product_cols[1]:
    if "microsoft_product_family" in df.columns and "microsoft_severity" in df.columns:
        # Count critical vulnerabilities by product
        critical_df = df[df["microsoft_severity"] == "Critical"]

        if not critical_df.empty:
            critical_products = []
            for products in critical_df["microsoft_product_family"].dropna():
                critical_products.extend([p.strip() for p in products.split(",")])

            critical_product_counts = pd.Series(critical_products).value_counts().reset_index()
            critical_product_counts.columns = ["Product", "Count"]

            # Take top 10 products
            top_critical = critical_product_counts.head(10)

            # Create bar chart
            fig_critical_products = px.bar(
                top_critical,
                x="Count",
                y="Product",
                orientation="h",
                title="Top Products with Critical Vulnerabilities",
                color="Count",
                color_continuous_scale=["orange", "red", "darkred"],
            )
            st.plotly_chart(fig_critical_products, use_container_width=True)
        else:
            st.info("No critical vulnerabilities in the selected data.")

# Microsoft vs CVSS/EPSS correlation
st.subheader("Correlation with Other Metrics")
metric_cols = st.columns(2)

with metric_cols[0]:
    if "microsoft_severity" in df.columns and "cvss_v3_score" in df.columns:
        # Box plot of CVSS by Microsoft severity
        fig_cvss = px.box(
            df.dropna(subset=["cvss_v3_score"]),
            x="microsoft_severity",
            y="cvss_v3_score",
            color="microsoft_severity",
            color_discrete_map=colors,
            title="CVSS Score by Microsoft Severity",
            category_orders={"microsoft_severity": ["Critical", "Important", "Moderate", "Low"]},
        )
        st.plotly_chart(fig_cvss, use_container_width=True)

with metric_cols[1]:
    if "microsoft_severity" in df.columns and "epss_score" in df.columns:
        # Box plot of EPSS by Microsoft severity
        fig_epss = px.box(
            df.dropna(subset=["epss_score"]),
            x="microsoft_severity",
            y="epss_score",
            color="microsoft_severity",
            color_discrete_map=colors,
            title="EPSS Score by Microsoft Severity",
            category_orders={"microsoft_severity": ["Critical", "Important", "Moderate", "Low"]},
        )
        fig_epss.update_layout(yaxis_range=[0, min(1.0, df["epss_score"].max() * 1.1)])
        st.plotly_chart(fig_epss, use_container_width=True)

# Detailed CVE table
st.subheader("Microsoft Vulnerability Table")

# Format the dataframe for display
display_df = df.copy()
if "published_date" in display_df.columns:
    display_df["published_date"] = display_df["published_date"].apply(
        lambda x: x.strftime("%Y-%m-%d") if pd.notnull(x) else "Unknown"
    )
if "patch_tuesday_date" in display_df.columns:
    display_df["patch_tuesday_date"] = display_df["patch_tuesday_date"].apply(
        lambda x: x.strftime("%Y-%m-%d") if pd.notnull(x) else "Unknown"
    )

# Format floating point numbers
if "cvss_v3_score" in display_df.columns:
    display_df["cvss_v3_score"] = display_df["cvss_v3_score"].apply(lambda x: f"{x:.1f}" if pd.notnull(x) else "N/A")
if "epss_score" in display_df.columns:
    display_df["epss_score"] = display_df["epss_score"].apply(lambda x: f"{x:.4f}" if pd.notnull(x) else "N/A")

# Create a KEV indicator column
if "is_in_kev" in display_df.columns:
    display_df["KEV Status"] = display_df["is_in_kev"].apply(lambda x: "🚨 Yes" if x else "No")

# Select columns for display
display_cols = [
    "cve_id",
    "microsoft_severity",
    "microsoft_product_family",
    "patch_tuesday_date",
    "KEV Status",
    "cvss_v3_score",
    "epss_score",
    "gemini_priority",
    "description",
]
display_cols = [col for col in display_cols if col in display_df.columns]

# Rename columns for better display
column_names = {
    "cve_id": "CVE ID",
    "microsoft_severity": "MS Severity",
    "microsoft_product_family": "Product Family",
    "patch_tuesday_date": "Patch Tuesday",
    "cvss_v3_score": "CVSS",
    "epss_score": "EPSS",
    "gemini_priority": "AI Priority",
    "description": "Description",
}
display_df = display_df[display_cols].rename(columns=column_names)

# Display the table
st.dataframe(
    display_df,
    use_container_width=True,
    column_config={
        "CVE ID": st.column_config.TextColumn("CVE ID", width="medium"),
        "MS Severity": st.column_config.TextColumn("MS Severity", width="small"),
        "Description": st.column_config.TextColumn("Description", width="large"),
    },
)

# Add a download button for the data
csv = display_df.to_csv(index=False)
st.download_button(
    label="Download Microsoft CVE Data as CSV",
    data=csv,
    file_name=f"microsoft_cves_{datetime.now().strftime('%Y%m%d')}.csv",
    mime="text/csv",
)

# Add footer with timestamp
st.markdown("---")
st.markdown(f"*Microsoft Patch Tuesday analysis generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

# For the time-based analysis
if not df.empty and "patch_tuesday_date" in df.columns:
    # Use only valid dates for this analysis
    df_dates = df.dropna(subset=["patch_tuesday_date"])

    if not df_dates.empty:
        # Group by month
        df_dates["month"] = df_dates["patch_tuesday_date"].dt.to_period("M")
        severity_by_month = df_dates.groupby(["month", "microsoft_severity"]).size().reset_index(name="count")
        severity_by_month["month_start"] = severity_by_month["month"].dt.to_timestamp()

        # Create a time series plot
        fig3 = px.line(
            severity_by_month,
            x="month_start",
            y="count",
            color="microsoft_severity",
            markers=True,
            color_discrete_map={
                "Critical": "#d9534f",
                "Important": "#f0ad4e",
                "Moderate": "#5bc0de",
                "Low": "#5cb85c",
            },
        )

        fig3.update_layout(
            title="Microsoft Vulnerabilities by Month and Severity",
            xaxis_title="Month",
            yaxis_title="Number of Vulnerabilities",
            legend_title="Severity",
        )

        st.plotly_chart(fig3, use_container_width=True)
    else:
        st.info("No valid patch Tuesday dates available for time-based analysis.")
else:
    st.info("No Microsoft patch data available for time-based analysis.")
