# ElGamal Digital Signature Implementation

This project implements a **Digital Signature Algorithm (DSA)** based on the **ElGamal signature scheme** using a **discrete logarithm problem (DLP)**. It provides both a **graphical user interface** and a **command-line interface** for key generation, file signing, and signature verification.

## Contents

- `ElGamal_signature.java` — core implementation of the ElGamal signature scheme.
- `Utils.java` — utility class for file hashing using SHA-256.
- `ElGamalGUITool.java` — main application class with both GUI and CLI modes.

## Features

- Generation of **cryptographically secure parameters**: a safe prime `p = 2q + 1` where `q` is also prime.
- **SHA-256** hashing of file content for signature binding.
- Support for **metadata** in keys: full name, email, and creation date.
- **Base64-encoded** public parameters in certificates for readability and compatibility.
- **Swing-based GUI** with three tabs:
  - Key Generation
  - File Signing
  - Signature Verification
- Fully functional **CLI mode** for scripting and automation.
## Build and Run

### 1. Compilation

```bash
javac ElGamal_signature.java Utils.java ElGamalGUITool.java
```

### 2. Launch GUI (default)

```bash
java ElGamalGUITool
```

### 3. Command-Line Usage

```bash
# Generate key pair
java ElGamalGUITool -g

# Sign a file
java ElGamalGUITool -s document.txt private.key

# Verify a signature
java ElGamalGUITool -c document.txt document.txt.sig public.cert

# Show help
java ElGamalGUITool -h
```

## Security Notes
- Uses Java’s `SecureRandom` for cryptographically strong randomness.
- Default key size: **512 bits** (suitable for educational purposes; **not recommended for production**.

> **Important**: This implementation wal developed as an educational project and is intended for **demonstration purposes only**. Do not use it in production systems without a thorough security review and parameter hardening.

## File Formats

### `private.key`
```
# ЗАКРЫТЫЙ КЛЮЧ ЭЦП - ХРАНИТЕ В СЕКРЕТЕ!
# Владелец: John Doe
name:John Doe
email:john@example.com
p:<hex>
g:<hex>
x:<hex>
```

### `public.cert`
```
-----BEGIN ELGAMAL CERTIFICATE-----
Owner: John Doe
Email: john@example.com
Created: 2025-12-29
p:<base64>
g:<base64>
y:<base64>
-----END ELGAMAL CERTIFICATE-----
```

### `<file>.sig`
```
-----BEGIN ELGAMAL SIGNATURE-----
File: document.txt
Owner: John Doe
Email: john@example.com
Hash:<base64>
r:<base64>
s:<base64>
-----END ELGAMAL SIGNATURE-----
```
