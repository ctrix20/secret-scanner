# Test file with fake secrets for testing your scanner
# DO NOT use real credentials!

# Fake AWS credentials
aws_access_key = "AKIAIOSFODNN7EXAMPLE"
aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Fake GitHub token
github_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

# Fake API key (high entropy)
api_key = "sk_live_51H8K9jL2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6"

# Private key header
private_key = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890...
-----END RSA PRIVATE KEY-----
"""

# Regular code (should not trigger)
username = "john_doe"
email = "user@example.com"
port = 8080
