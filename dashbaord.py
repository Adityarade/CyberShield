import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import os
import time
from datetime import datetime

# Load data safely with caching
@st.cache_data
def load_data(uploaded_file):
    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
    else:
        df = pd.DataFrame()
    return df

st.set_page_config(page_title="Cybersecurity Monitoring Dashboard", layout="wide")
st.title("Cybersecurity Monitoring Dashboard")

# Sidebar navigation
menu = st.sidebar.radio("Navigation", ["Overview", "Logs", "Threats", "Run Agent"])

# File uploader
st.sidebar.subheader("Upload Log File")
uploaded_log = st.sidebar.file_uploader("Upload CSV Log", type="csv")

df = load_data(uploaded_log)

# Overview Page
if menu == "Overview":
    st.header("Dashboard Overview")
    
    if not df.empty:
        st.subheader("Summary Stats")
        st.write(df.describe(include='all'))

        if 'Threat Level' in df.columns:
            st.subheader("Threat Level Pie Chart")
            threat_counts = df['Threat Level'].value_counts()
            fig1, ax1 = plt.subplots()
            ax1.pie(threat_counts, labels=threat_counts.index, autopct='%1.1f%%')
            ax1.axis('equal')
            st.pyplot(fig1)

        if 'IP Address' in df.columns:
            st.subheader("Top 5 Suspicious IPs")
            ip_counts = df['IP Address'].value_counts().head(5)
            fig2, ax2 = plt.subplots()
            ip_counts.plot(kind='bar', ax=ax2)
            ax2.set_ylabel("Attempt Count")
            st.pyplot(fig2)

# Logs Page
elif menu == "Logs":
    st.header("System Logs")

    if not df.empty:
        with st.expander("Filter Options"):
            date_col = None
            for col in df.columns:
                if pd.api.types.is_datetime64_any_dtype(df[col]) or 'date' in col.lower():
                    date_col = col
                    break

            if date_col:
                df[date_col] = pd.to_datetime(df[date_col], errors='coerce')
                start_date, end_date = st.date_input("Filter by Date Range", [df[date_col].min(), df[date_col].max()])
                df = df[(df[date_col] >= pd.to_datetime(start_date)) & (df[date_col] <= pd.to_datetime(end_date))]

            ip_filter = st.multiselect("Filter by IP Address", df['IP Address'].unique() if 'IP Address' in df.columns else [])
            if ip_filter:
                df = df[df['IP Address'].isin(ip_filter)]

        st.dataframe(df, use_container_width=True)
    else:
        st.warning("No log data available.")

# Threats Page
elif menu == "Threats":
    st.header("Threat Analysis")

    if not df.empty and 'Threat Level' in df.columns:
        threat_df = df[df['Threat Level'].notnull()]
        st.dataframe(threat_df, use_container_width=True)

        st.subheader("Download Threat Report")
        csv = threat_df.to_csv(index=False).encode('utf-8')
        st.download_button("Download CSV", data=csv, file_name='threat_report.csv', mime='text/csv')
    else:
        st.warning("Threat data not found in uploaded logs.")

# Run Agent Page
elif menu == "Run Agent":
    st.header("Run AI Monitoring Agent")

    if st.button("Start Monitoring Agent"):
        with st.spinner("Running agent..."):
            try:
                os.system("python agent.py")
                st.success("Agent run complete. Check updated logs.")
            except Exception as e:
                st.error(f"Error running agent: {e}")

st.markdown("---")
st.caption("CyberAgent © 2025 | Developed by Aditya")
