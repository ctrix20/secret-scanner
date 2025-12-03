Secret Scanner CLI Tool using Python and storing it on GitHub

The Plan
Input: We accept a directory path from the user.

File Walking: We recursively look through every file in that directory.

Detection Method A (Regex): We compare text against known patterns (like AWS keys).

Detection Method B (Entropy): We calculate the mathematical "randomness" of strings to find high-entropy secrets (like random passwords) that don't match a specific regex.

Output: We print the findings to the terminal.

Additional Features 
1Risk Scoring: Instead of just saying "Found something," the tool will label findings as HIGH, MEDIUM, or LOW risk. This mimics real enterprise tools.

JSON Reporting: We will add a feature to save the results to a .json file. This makes your tool "automation-ready" (a huge plus for security roles).

Visual Flair: We will use simple ANSI color codes so your terminal output looks like a professional hacker tool (Red for danger, Green for safe).