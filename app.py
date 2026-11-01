
import streamlit as st
import pandas as pd
import plotly.express as px

from detector import analyze_traffic

st.set_page_config(
    page_title="NetGuard",
    page_icon="🛡️",
    layout="wide"
)


st.title("🛡️ NetGuard")
st.subheader("Network Traffic Analyzer & Cybersecurity Dashboard")

st.write(
    "Monitor network traffic and identify "
    "potentially suspicious activities."
)

st.info(
    "Educational project: alerts indicate rule matches, "
    "not confirmed cyberattacks."
)

uploaded_file = st.file_uploader(
    "Upload Network Traffic CSV",
    type=["csv"]
)

if uploaded_file is not None:

    try:
        df = pd.read_csv(uploaded_file)

        traffic, alerts = analyze_traffic(df)

        if traffic.empty:
            st.warning("No valid traffic records found.")
            st.stop()

        st.markdown("## Network Overview")

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "Total Traffic Records",
            len(traffic)
        )

        col2.metric(
            "Unique IP Addresses",
            traffic["src_ip"].nunique()
        )

        col3.metric(
            "Security Alerts",
            len(alerts)
        )

      
        st.markdown("## Protocol Distribution")

        protocol_counts = (
            traffic["protocol"].value_counts()
            .reset_index()
        )

        protocol_counts.columns = [
            "Protocol", "Count"
        ]

        fig = px.pie(
            protocol_counts,
            names="Protocol",
            values="Count",
            title="Network Protocol Usage"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

   
        st.markdown("## Top Source IP Addresses")

        top_ips = (
            traffic["src_ip"].value_counts()
            .head(10)
            .reset_index()
        )

        top_ips.columns = ["IP Address", "Count"]

        fig2 = px.bar(
            top_ips,
            x="IP Address",
            y="Count",
            title="Top 10 Traffic Sources"
        )

        st.plotly_chart(
            fig2,
            use_container_width=True
        )

      
        st.markdown("## Security Alerts")

        if alerts.empty:
            st.success(
                "No alerts triggered by the current rules."
            )
        else:
            st.dataframe(
                alerts,
                use_container_width=True
            )

            csv = alerts.to_csv(index=False)

            st.download_button(
                "Download Security Report",
                csv,
                "netguard_report.csv",
                "text/csv"
            )

        st.markdown("## Traffic Records")

        st.dataframe(
            traffic,
            use_container_width=True
        )

    except (ValueError, pd.errors.ParserError) as error:
        st.error(f"Unable to analyze file: {error}")

    except Exception as error:
        st.error(f"Unexpected error: {error}")

else:
    st.warning(
        "Please upload a network traffic CSV file to begin."
    )
