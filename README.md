# Secret Scanner

A professional CLI tool for detecting hardcoded secrets in code repositories using regex patterns and entropy analysis.

## Features

- 🔍 **Regex Pattern Matching** - Detects known secret formats (AWS keys, GitHub tokens, API keys, private keys)
- 🎲 **Entropy Analysis** - Finds high-randomness strings that might be secrets
- ⚠️ **Risk Scoring** - Labels findings as HIGH, MEDIUM, or LOW risk
- 🎨 **Color-Coded Output** - Easy-to-read terminal output with ANSI colors
- 📄 **JSON Export** - Save results for automation and integration

## Installation

```bash
git clone https://github.com/ctrix20/secret-scanner.git
cd secret-scanner
```

No dependencies required - uses only Python standard library!

## Usage

### Basic Scan

Scan a single file:
```bash
python secret_scanner.py test_samples.py
```

Scan a directory:
```bash
python secret_scanner.py .
```

### JSON Export

Save results to a JSON file:
```bash
python secret_scanner.py . --json results.json
```

Output in JSON format to stdout:
```bash
python secret_scanner.py . --format json
```

## Example Output

```
==================================================
Found 9 potential secrets
  HIGH: 7 | MEDIUM: 2 | LOW: 0
==================================================

[AWS Access Key] - Risk: HIGH
  File: test_samples.py
  Line: 5
  Value: AKIAIOSFODNN7EXAMPLE
  Context: aws_access_key = "AKIAIOSFODNN7EXAMPLE"...

[High Entropy String] - Risk: MEDIUM
  File: test_samples.py
  Line: 6
  Value: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  Entropy: 4.66
  Context: aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"...
```

## How It Works

### 1. Regex Pattern Detection
The scanner uses predefined regex patterns to identify known secret formats:
- AWS Access Keys: `AKIA[0-9A-Z]{16}`
- GitHub Tokens: `ghp_[0-9a-zA-Z]{36}`
- Private Keys: `-----BEGIN .* PRIVATE KEY-----`
- Generic API Keys

### 2. Entropy Analysis
Calculates Shannon entropy to detect random-looking strings:
- Entropy ≥ 5.0 = HIGH risk
- Entropy ≥ 4.5 = MEDIUM risk
- Entropy < 4.5 = LOW risk

### 3. Risk Scoring
Each finding is assigned a risk level:
- **HIGH**: Known secret patterns (AWS keys, GitHub tokens, private keys)
- **MEDIUM**: Generic API keys, medium-entropy strings
- **LOW**: Low-entropy strings

## Project Structure

```
secret-scanner/
├── secret_scanner.py    # Main scanner implementation
├── test_samples.py      # Test file with fake secrets
├── README.md           # This file
└── .gitignore          # Git ignore rules
```

## Development

Built with Python 3 using:
- `argparse` - Command-line argument parsing
- `re` - Regular expression matching
- `math` - Entropy calculations
- `pathlib` - Modern file path handling
- `json` - JSON export functionality

## Security Note

This tool is for educational and security testing purposes. Always:
- Test on your own code or with permission
- Never commit real secrets to version control
- Use environment variables or secret management tools for production secrets

## License

MIT License - Feel free to use and modify!

## Author

Built by ctrix20 as a learning project to understand:
- Python development
- Security scanning techniques
- Git/GitHub workflows
- CLI tool design

## Contributing

Contributions welcome! Feel free to:
- Report bugs
- Suggest new secret patterns
- Improve detection algorithms
- Add new features
