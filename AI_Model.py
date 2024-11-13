import re
from collections import namedtuple, defaultdict
from typing import List, Optional
from flask import Flask, render_template, request, redirect, url_for, flash
import csv
import os

# Define Token namedtuple for lexer tokens
Token = namedtuple("Token", ["type", "value"])

class Lexer:
    """Lexer for tokenizing regex patterns."""
    def __init__(self, pattern: str):
        self.pattern = pattern
        self.position = 0
        self.tokens = []
        self.current_char = self.pattern[self.position] if self.pattern else None

    def advance(self):
        """Advances the `position` and updates the current character."""
        self.position += 1
        self.current_char = self.pattern[self.position] if self.position < len(self.pattern) else None

    def skip_whitespace(self):
        """Skips any whitespace characters in the regex pattern."""
        while self.current_char is not None and self.current_char.isspace():
            self.advance()

    def lex(self):
        """Lexical analysis for the regex pattern."""
        while self.current_char is not None:
            if self.current_char.isspace():
                self.skip_whitespace()
                continue
            if self.current_char == '*':
                self.tokens.append(Token("STAR", "*"))
                self.advance()
            elif self.current_char == '+':
                self.tokens.append(Token("PLUS", "+"))
                self.advance()
            elif self.current_char == '?':
                self.tokens.append(Token("QUESTION", "?"))
                self.advance()
            elif self.current_char == '.':
                self.tokens.append(Token("DOT", "."))
                self.advance()
            elif self.current_char.isalnum() or self.current_char == '-':  # Allow '-', add it to literals
                value = self.current_char
                self.advance()
                while self.current_char is not None and (self.current_char.isalnum() or self.current_char in '._-'):
                    value += self.current_char
                    self.advance()
                self.tokens.append(Token("LITERAL", value))
            elif self.current_char == '(':
                self.tokens.append(Token("LPAREN", "("))
                self.advance()
            elif self.current_char == ')':
                self.tokens.append(Token("RPAREN", ")"))
                self.advance()
            elif self.current_char == '[':
                self.tokens.append(Token("LBRACKET", "["))
                self.advance()
            elif self.current_char == ']':
                self.tokens.append(Token("RBRACKET", "]"))
                self.advance()
            elif self.current_char == '{':
                self.tokens.append(Token("LBRACE", "{"))
                self.advance()
            elif self.current_char == '}':
                self.tokens.append(Token("RBRACE", "}"))
                self.advance()
            elif self.current_char == '\\':
                self.advance()  # Escape character
                if self.current_char is not None:
                    self.tokens.append(Token("LITERAL", self.current_char))
                    self.advance()
            elif self.current_char == '|':
                self.tokens.append(Token("OR", "|"))
                self.advance()
            elif self.current_char == '^':
                self.tokens.append(Token("BEGIN", "^"))  # Handle start of string
                self.advance()
            elif self.current_char == '$':
                self.tokens.append(Token("END", "$"))  # Handle end of string
                self.advance()
            else:
                raise Exception(f"Invalid character: {self.current_char}")

        return self.tokens


class Parser:
    """Parser for generating an Abstract Syntax Tree (AST) from tokens."""
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.position = 0

    def parse(self):
        """Parses tokens into an abstract syntax tree."""
        ast = self.expr()
        return ast

    def expr(self):
        """Handles expressions, including concatenation and alternation."""
        nodes = [self.term()]
        while self.current_token() and self.current_token().type == 'OR':
            self.advance()  # Consume '|'
            nodes.append(self.term())
        return ['OR', nodes]  # This will be a list of operation nodes

    def term(self):
        """Handles sequences of literals or groups."""
        nodes = []
        while True:
            token = self.current_token()
            if token and token.type in ['LITERAL', 'LPAREN', 'LBRACKET']:
                nodes.append(self.factor())
            else:
                break
        return nodes  # This will be a list of nodes

    def factor(self):
        """Handles literals, groups, and quantifiers."""
        token = self.current_token()
        if token.type == 'LITERAL':
            self.advance()  # Consume literal
            node = {'type': 'LITERAL', 'value': token.value}
            if self.current_token() and self.current_token().type in ['STAR', 'PLUS', 'QUESTION']:
                quantifier = self.current_token().type
                node['quantifier'] = quantifier
                self.advance()  # Consume quantifier
            return node
        elif token.type == 'LPAREN':
            self.advance()  # Consume '('
            group = self.expr()
            self.expect('RPAREN')  # Expect a closing parenthesis
            return {'type': 'GROUP', 'children': group}
        elif token.type == 'LBRACKET':
            return self.handle_character_class()
        else:
            raise Exception("Invalid factor")

    def handle_character_class(self):
        """Handles character classes like [abc]."""
        self.advance()  # Consume '['
        characters = []
        while self.current_token() and self.current_token().type != 'RBRACKET':
            characters.append(self.current_token().value)
            self.advance()
        self.expect('RBRACKET')
        return {'type': 'CHAR_CLASS', 'characters': characters}

    def current_token(self) -> Optional[Token]:
        """Gets the current token."""
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def advance(self):
        """Advances to the next token."""
        self.position += 1

    def expect(self, token_type: str):
        """Expects the current token to be of a specific type."""
        if self.current_token() and self.current_token().type == token_type:
            self.advance()
        else:
            raise Exception(f"Expected {token_type}, found {self.current_token()}")


class NFA:
    """Nondeterministic Finite Automaton for regex representation."""
    def __init__(self):
        self.start_state = "q0"  # Starting state
        self.accept_states = set()
        self.transitions = defaultdict(dict)

    def add_transition(self, from_state: str, to_state: str, symbol: str):
        """Adds a transition to the NFA."""
        if symbol not in self.transitions[from_state]:
            self.transitions[from_state][symbol] = set()
        self.transitions[from_state][symbol].add(to_state)

    def visualize(self):
        """Visualize the NFA structure."""
        result = "NFA Transitions:\n"
        for state, trans in self.transitions.items():
            for symbol, states in trans.items():
                result += f"From {state} -- '{symbol}' --> {', '.join(states)}\n"
        return result


class DFA:
    """Deterministic Finite Automaton for regex matching."""
    def __init__(self):
        self.start_state = None
        self.accept_states = set()
        self.transitions = {}

    def add_transition(self, from_state: str, to_state: str, symbol: str):
        """Adds a transition to the DFA."""
        if from_state not in self.transitions:
            self.transitions[from_state] = {}
        self.transitions[from_state][symbol] = to_state

    def visualize(self):
        """Visualizes the DFA structure."""
        result = "DFA Transitions:\n"
        for state, trans in self.transitions.items():
            for symbol, next_state in trans.items():
                result += f"From {state} -- '{symbol}' --> {next_state}\n"
        return result


class RegexEngine:
    """Main Regex engine to compile and match regex patterns."""
    def __init__(self, pattern: str):
        self.pattern = pattern
        self.nfa = NFA()
        self.dfa = DFA()

    def compile(self):
        """Compiles the regex pattern into an NFA and then converts it to a DFA."""
        lexer = Lexer(self.pattern)
        tokens = lexer.lex()
        parser = Parser(tokens)
        ast = parser.parse()
        # Convert AST into NFA
        self.build_nfa(ast)

    def build_nfa(self, ast):
        """Builds an NFA from the abstract syntax tree."""
        current_state = self.nfa.start_state
        self.nfa.accept_states.add("q_accept")  # Add accept state

        for node in ast:
            if isinstance(node, dict):  # Literal or Group
                if node['type'] == 'LITERAL':
                    next_state = f"q{len(self.nfa.transitions) + 1}"
                    self.nfa.add_transition(current_state, next_state, node['value'])
                    current_state = next_state
                elif node['type'] == 'GROUP':
                    # Handle group structure
                    for child in node['children']:
                        self.build_nfa([child])  # Recursive call
                elif node['type'] == 'CHAR_CLASS':
                    char_class_state = f"q{len(self.nfa.transitions) + 1}"
                    for char in node['characters']:
                        self.nfa.add_transition(current_state, char_class_state, char)
                    current_state = char_class_state

        self.nfa.add_transition(current_state, "q_accept", '')

    def match(self, string: str) -> bool:
        """Matches input string against the compiled regex."""
        print(f"Matching '{string}' against pattern '{self.pattern}' (not implemented yet)")
        return True  # Placeholder for actual matching logic


def dynamic_regex_generate(data: List[str]) -> str:
    """Generates a regex pattern based on the provided data."""
    patterns = []
    for item in data:
        if re.fullmatch(r'\d+', item):  # Contains only digits
            patterns.append(r'\d+')
        elif re.fullmatch(r'[A-Za-z]+', item):  # Contains only letters
            patterns.append(r'[A-Za-z]+')
        elif re.fullmatch(r'\w+', item):  # Contains alphanumeric
            patterns.append(r'\w+')

    if patterns:
        return f"({'|'.join(set(patterns))})"
    return r'.*'  # Match anything if no specific patterns found


def validate_regex(pattern: str) -> bool:
    """Validates a regex pattern to check if it's well-formed."""
    try:
        re.compile(pattern)
        return True
    except re.error as e:
        flash(f'Invalid regex pattern: {e}')
        return False


# Set up Flask app and routes
app = Flask(__name__)
app.secret_key = os.urandom(24)  # For flash messages

@app.route("/", methods=["GET", "POST"])
def index():
    match_result = None
    if request.method == "POST":
        regex = request.form.get("regex")
        test_string = request.form.get("test_string")
        
        if regex == '':
            # Process uploaded CSV file
            csv_file = request.files.get("csv_file")
            if csv_file and allowed_file(csv_file.filename):
                file_content = csv_file.stream.read().decode("utf-8").splitlines()
                csv_reader = csv.reader(file_content)
                extracted_data = [cell for row in csv_reader for cell in row]
                dynamic_regex = dynamic_regex_generate(extracted_data)

                print(f"Generated Regex: {dynamic_regex}")

                if not validate_regex(dynamic_regex):
                    return render_template("index.html", match_result="Invalid dynamic regex generated.")

                engine = RegexEngine(dynamic_regex)  # Use dynamically generated regex
                engine.compile()

                if test_string:
                    match_result = engine.match(test_string)

                csv_matches = [cell for cell in extracted_data if validate_regex(dynamic_regex) and engine.match(cell)]
                if csv_matches:
                    match_result = "CSV Matches Found: " + ", ".join(csv_matches)
                else:
                    match_result = "No matches found in CSV."
            else:
                flash('Please upload a valid CSV file.')
        else:
            # Use user-supplied regex
            if not validate_regex(regex):
                return render_template("index.html", match_result="Invalid user-supplied regex.")

            engine = RegexEngine(regex)
            engine.compile()
            if test_string:
                match_result = engine.match(test_string)
        
    return render_template("index.html", match_result=match_result)

def allowed_file(filename):
    """Checks if the uploaded file has an acceptable extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'csv'


if __name__ == "__main__":
    app.run(debug=True)