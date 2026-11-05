# Vulnerable Demo Project (Educational Testing)

> [!WARNING]
> This repository contains intentional vulnerabilities designed to test the AI Code Intelligence & Security Reviewer. Do not use in production.

### Identified Vulnerabilities:
1. **Hardcoded Credentials**: Plaintext API secrets and database passwords.
2. **Dynamic Code Execution**: `eval()` used on unvalidated user input.
3. **OS Command Injection**: `subprocess.call` executed with `shell=True`.
4. **SQL Injection**: Dynamic queries constructed using f-strings and string interpolation.
5. **Weak Cryptography**: Insecure MD5 hashing for passwords.
6. **Improper Exception Handling**: Bare `except:` and silent `pass` error suppression.
