# Secret Scanner

It's a command-line scanner that hunts for hardcoded secrets in your code using two methods: pattern matching for known secret formats (like AWS keys) and entropy analysis to catch random-looking strings that might be passwords or tokens.

## What It Does
- 🔍 **Finds Known Secrets** - Spots AWS keys, GitHub tokens, API keys, and private keys using regex patterns
- � **Detec-ts Random Strings** - Uses entropy analysis to find high-randomness strings that look suspicious
- ⚠️ **Scores Risk Levels** - Tells you if something is HIGH, MEDIUM, or LOW risk so you know what to fix first
- 🎨 **Pretty Terminal Output** - Color-coded results that are actually readable
- 📄 **JSON Export** - Save results to a file for automation or CI/CD pipelines

## Getting Started

Clone it and run it - that's it:

```bash
git clone https://github.com/ctrix20/secret-scanner.git
cd secret-scanner
```

No pip installs, no virtual environments, no headaches. Just Python 3 and you're good to go.

## How to Use It

**Scan a single file:**
```bash
python secret_scanner.py test_samples.py
```

**Scan your entire project:**
```bash
python secret_scanner.py .
```

**Save results to a file:**
```bash
python secret_scanner.py . --json results.json
```

**Get JSON output for piping:**
```bash
python secret_scanner.py . --format json
```

## What the Output Looks Like

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

Red means danger, yellow means caution, green means you're probably alright.

## How It Actually Works

### Pattern Matching
The scanner knows what common secrets look like:
- AWS keys start with `AKIA` followed by 16 characters
- GitHub tokens start with `ghp_` followed by 36 characters
- Private keys have that telltale `-----BEGIN PRIVATE KEY-----` header
- API keys usually have "api_key" or "apikey" in the variable name

### Entropy Analysis
This is the clever bit. The tool calculates how "random" a string looks using Shannon entropy (fancy maths that measures unpredictability). 

Think about it: `"password123"` isn't very random, but `"aB3$xZ9kL2mN"` definitely is. High randomness = probably a secret.

### Risk Scoring

**HIGH Risk** (fix these immediately):
- AWS Access Keys, GitHub Tokens, Private Keys
- Any string with entropy ≥ 5.0 (super random)

**MEDIUM Risk** (probably worth checking):
- Generic API key patterns
- Strings with entropy between 4.5 and 5.0 (pretty random)

**LOW Risk** (might be fine):
- Strings with entropy < 4.5 (not very random)

The default threshold is 4.5, which catches most real secrets without too many false positives.

## What's Inside

```
secret-scanner/
├── secret_scanner.py    # The main tool (~300 lines)
├── test_samples.py      # Fake secrets for testing
├── test_scanner.py      # Automated tests
├── README.md           # You are here
└── .gitignore          # Keeps junk out of Git
```

## Tech Stack

Just Python 3 standard library:
- `argparse` for command-line arguments
- `re` for regex pattern matching
- `math` for entropy calculations
- `pathlib` for file handling
- `json` for export functionality

No external dependencies means no dependency hell. You're welcome.

## Important Security Note

This tool is for **finding** secrets, not storing them. A few rules:

- ✅ Use it to scan your own code
- ✅ Use it in CI/CD to catch secrets before they're pushed
- ✅ Use environment variables or proper secret managers for real credentials
- ❌ Don't commit real secrets to test it (use the fake ones in test_samples.py)
- ❌ Don't use it to scan code you don't have permission to scan

## Why I Built This

I'm learning Python and security concepts, and this seemed like a good way to combine both. It's also genuinely useful - I've already caught a few API keys I forgot to remove from test files.

If you're learning too, feel free to poke around the code. I tried to comment it well and keep it readable.

## Want to Contribute?

Found a bug? Have an idea for a new feature? Want to add more secret patterns? Pull requests are welcome!

Some ideas for improvements:
- Add more secret patterns (Slack tokens, database URLs, etc.)
- Implement a whitelist/ignore feature
- Add support for custom regex patterns via config file
- Make it faster with parallel file scanning
- Create a web interface

## Licence

MIT Licence - do whatever you want with it. Just don't blame me if it misses something or flags your variable named `super_random_string_123`.

---

Built by [ctrix20](https://github.com/ctrix20) while learning Python, Git, and security concepts.
