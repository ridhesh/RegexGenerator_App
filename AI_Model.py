import streamlit as st
import pandas as pd

# Title for the app
st.title("Data Processing and Display App")

# Sidebar options for file upload or URL input
st.sidebar.header("Load Data")
data_source = st.sidebar.selectbox("Select Data Source", ("Upload File", "Enter URL"))

# Initialize an empty DataFrame
df = pd.DataFrame()

# Function to load data from a URL
def load_data_from_url(url):
    try:
        df = pd.read_csv(url)
        return df
    except Exception as e:
        st.error(f"Failed to load data from the URL. Error: {e}")
        return None

# Function to display data and summary
def display_data_info(df):
    st.write("### Data Preview")
    st.write(df)

    st.write("### Column Names and Data Types")
    st.write(df.dtypes)

    st.write("### Basic Data Summary")
    st.write(df.describe())

# Load data based on the selected source
if data_source == "Upload File":
    uploaded_file = st.sidebar.file_uploader("Upload a CSV file", type="csv")
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
elif data_source == "Enter URL":
    url = st.sidebar.text_input("Enter the URL of a CSV file")
    if url:
        df = load_data_from_url(url)

# Data submission button
if not df.empty:
    if st.button("Submit and Process Data"):
        st.success("Data successfully submitted for processing.")
        display_data_info(df)
else:
    st.warning("Please load data to proceed.")

# Instructions to run the app
st.markdown("""
### Instructions to Run the App:
1. Select a data source from the sidebar (either upload a file or enter a URL).
2. Click on "Submit and Process Data" to display the data and a basic summary.
3. You can view data columns, types, and a basic summary including mean, median, etc.
4. Run this app with the command: streamlit run your_file_name.py
""")