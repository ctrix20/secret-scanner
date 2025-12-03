# Test file with fake secrets for testing your scanner
# DO NOT use real credentials!

# Fake AWS credentials
aws_access_key = "AKIAIOSFODNN7EXAMPLE"
aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Fake GitHub token
github_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

# Fake API key (high entropy)
api_key = "sk_test_FaKeApIkEy123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ"

# Private key header
private_key = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890...
-----END RSA PRIVATE KEY-----
"""

# Regular code (should not trigger)
username = "tom_white"
email = "user@example.com"
port = 8080
