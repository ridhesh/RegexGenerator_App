import re
import pandas as pd
import logging
from flask import Flask, request, render_template, send_file
import tempfile
from collections import defaultdict

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@app.route('/')
def home():
    """Render the homepage with the CSV upload form."""
    return render_template('upload.html')

@app.route('/generate_regex', methods=['POST'])
def generate_regex():
    """Handles the file upload and regex generation process."""
    file = request.files['csv_file']

    if file and file.filename.endswith('.csv'):
        df = pd.read_csv(file)
        result_df = pd.DataFrame()

        # Process each column to generate regex patterns
        for column in df.columns:
            token_patterns = []  # List to hold detected patterns
            regex_patterns = []  # List to hold generated regex

            for value in df[column].dropna().astype(str):
                tokens = tokenize(value)  # Tokenize the entry
                patterns = detect_patterns(tokens)  # Detect patterns based on tokens
                regex = generate_regex_from_patterns(patterns)  # Create regex from patterns

                token_patterns.append(' '.join(tokens))
                regex_patterns.append(regex)

            # Populate the result DataFrame
            result_df[column] = df[column]  # Retain original column
            result_df[column + ' - Detected Tokens'] = token_patterns
            result_df[column + ' - Generated Regex'] = regex_patterns

        # Save to a temporary CSV file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.csv')
        result_df.to_csv(temp_file.name, index=False)

        logging.info(f"Regex generation complete for column: {column}")
        return render_template(
            'results.html',
            patterns=result_df.to_html(classes='table table-striped'),
            download_file=temp_file.name
        )

    return "Invalid file format. Please upload a CSV file."

def tokenize(text):
    """Tokenize the input text using regex to split into words, numbers, and symbols."""
    regex_pattern = r'\S+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\b\w+\.[a-zA-Z]{2,}\b|(?:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})|(?:\+?[0-9]{1,4}[\\s-]?[0-9]{1,15})|\\d{4}-\\d{2}-\\d{2}|\\d{2}:\\d{2}:\\d{2}|0x[0-9A-Fa-f]+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    return re.findall(regex_pattern, text)  # Find appropriate tokens

def detect_patterns(tokens):
    """Analyze tokens to detect patterns based on their structure."""
    patterns = defaultdict(int)

    for token in tokens:
        # Check for numbers
        if token.isdigit():
            patterns['numeric'] += 1
        # Check for alphabetic strings
        elif token.isalpha():
            patterns['alpha'] += 1
        # Check for decimal numbers (floating-point numbers)
        elif re.match(r'^\d+\.\d+$', token):
            patterns['float'] += 1
        # Check for emails
        elif re.match(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', token):
            patterns['email'] += 1
        # Check for URLs
        elif re.match(r'https?://[^\s/$.?#].[^\s]*', token):
            patterns['url'] += 1
        # Check for date formats (yyyy-mm-dd)
        elif re.match(r'\d{4}-\d{2}-\d{2}', token):
            patterns['date'] += 1
        # Check for time formats (hh:mm:ss)
        elif re.match(r'\d{2}:\d{2}:\d{2}', token):
            patterns['time'] += 1
        # Check for hexadecimal numbers
        elif re.match(r'0x[0-9A-Fa-f]+', token):
            patterns['hex'] += 1
        # Check for IP addresses
        elif re.match(r'\d{1,3}(\.\d{1,3}){3}', token):
            patterns['ipv4'] += 1
        # Check for UUIDs
        elif re.match(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', token):
            patterns['uuid'] += 1
        else:
            patterns['other'] += 1

        # Dynamic count for digits within the text
        digit_count = sum(c.isdigit() for c in token)
        if digit_count > 0:
            patterns['digit'] += digit_count

    return patterns

def generate_regex_from_patterns(patterns):
    """Generate regex dynamically based on detected patterns."""
    regex_sections = []

    # For each pattern type detected, generate a corresponding regex
    if patterns.get('numeric', 0) > 0:
        regex_sections.append(r'\d+')  # Match numeric values
    if patterns.get('alpha', 0) > 0:
        regex_sections.append(r'[a-zA-Z]+')  # Match alphabetic strings
    if patterns.get('float', 0) > 0:
        regex_sections.append(r'\d+\.\d+')  # Match floating-point numbers
    if patterns.get('email', 0) > 0:
        regex_sections.append(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')  # Email format
    if patterns.get('url', 0) > 0:
        regex_sections.append(r'https?://[^\s/$.?#].[^\s]*')  # URL format
    if patterns.get('date', 0) > 0:
        regex_sections.append(r'\d{4}-\d{2}-\d{2}')  # Date format
    if patterns.get('time', 0) > 0:
        regex_sections.append(r'\d{2}:\d{2}:\d{2}')  # Time format
    if patterns.get('hex', 0) > 0:
        regex_sections.append(r'0x[0-9A-Fa-f]+')  # Hexadecimal format
    if patterns.get('ipv4', 0) > 0:
        regex_sections.append(r'\d{1,3}(\.\d{1,3}){3}')  # IPv4 address
    if patterns.get('uuid', 0) > 0:
        regex_sections.append(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')  # UUID format
    if patterns.get('digit', 0) > 0:
        regex_sections.append(r'\d+')  # Match digit patterns (specific count)

    # Add other pattern as fallback
    if patterns.get('other', 0) > 0:
        regex_sections.append(r'\S+')  # Match any other string

    # Combine all regex sections using alternation (|), simulating dynamic pattern matching
    return '|'.join(regex_sections)

if __name__ == '__main__':
    app.run(debug=True)
