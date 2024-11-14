from flask import Flask, request, render_template, send_file
import pandas as pd
import re
import tempfile
import logging
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
    return re.findall(r'\S+', text)  # Splitting by whitespace while keeping non-whitespace parts

def detect_patterns(tokens):
    """Analyze tokens to detect patterns based on their structure."""
    patterns = defaultdict(int)
    length_counts = defaultdict(int)

    for token in tokens:
        if token.isdigit():
            patterns['digit'] += 1
            patterns['<DIGIT>'] = True
        elif token.isalpha():
            patterns['alpha'] += 1
            patterns['<ALPHA>'] = True
        elif re.search(r'\W', token):
            patterns['special'] += 1
            patterns['<SPECIAL>'] = True
        else:
            patterns['mixed'] += 1
            patterns['<MIXED>'] = True
            
        # Count lengths
        length_counts[len(token)] += 1

    patterns['length_counts'] = length_counts  # Adding length counts to patterns
    return patterns

def generate_regex_from_patterns(patterns):
    """Construct a regex pattern from detected token patterns."""
    
    # Collect sections for regex construction
    regex_sections = []
    
    # Adding basic type patterns
    if patterns.get('digit', 0):
        regex_sections.append(r'\d+')
    if patterns.get('alpha', 0):
        regex_sections.append(r'[A-Za-z]+')
    if patterns.get('special', 0):
        regex_sections.append(r'[\W]+')

    # Add dynamic lengths for specific counts
    for length, count in sorted(patterns['length_counts'].items()):
        if length > 0:
            regex_sections.append(r'.{%d}' % length)  # Match any sequence of that length
    
    # Combine the sections dynamically
    if regex_sections:
        combined_pattern = '|'.join(regex_sections)
        return rf'({combined_pattern})*'
    
    return r'.*'  # Fallback if no patterns were found

@app.route('/download/<path:filename>', methods=['GET'])
def download_file(filename):
    """Serve the generated CSV file for download."""
    return send_file(filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
