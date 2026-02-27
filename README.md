# nullsec-cryptwrap

```
    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
   ░ ▒░   ▒ ▒ ░▒▓▒ ▒ ▒ ░ ▒░▓  ░░ ▒░▓  ░▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ░▒ ▒  ░
   ░ ░░   ░ ▒░░░▒░ ░ ░ ░ ░ ▒  ░░ ░ ▒  ░░ ░▒  ░ ░ ░ ░  ░  ░  ▒   
      ░   ░ ░  ░░░ ░ ░   ░ ░     ░ ░   ░  ░  ░     ░   ░        
            ░                          ░    ░           ░        
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █░░░░░░░░░░░░░░░ C R Y P T W R A P ░░░░░░░░░░░░░░░░░░░░░░░█
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                       bad-antics
```

![Ada](https://img.shields.io/badge/Ada-02F88C?style=for-the-badge&logo=ada&logoColor=black)

## Overview

**nullsec-cryptwrap** is a formally verified cryptographic wrapper written in Ada/SPARK. Leverages Ada's strong typing and SPARK's formal verification for provably correct cryptographic operations.

## Features

- 🔐 **Verified Crypto** - SPARK-verified AES, ChaCha20, RSA
- 📝 **Secure Memory** - Guaranteed memory zeroing
- 🛡️ **Type Safety** - Strong typing prevents crypto misuse
- ⏱️ **Constant Time** - Timing-attack resistant operations
- 📋 **Auditable** - Human-readable verification proofs
- 🔑 **Key Management** - Secure key generation and storage

## Requirements

- GNAT 2023+
- SPARK 2014 (for verification)

## Installation

```bash
git clone https://github.com/bad-antics/nullsec-cryptwrap.git
cd nullsec-cryptwrap
gprbuild -P cryptwrap.gpr
```

## Usage

```bash
# Encrypt file
./cryptwrap encrypt -i secret.txt -o secret.enc -k keyfile.key

# Decrypt file
./cryptwrap decrypt -i secret.enc -o decrypted.txt -k keyfile.key

# Generate key
./cryptwrap keygen -a aes256 -o key.key

# Hash file
./cryptwrap hash -i file.txt -a sha256

# Verify signatures
./cryptwrap verify -i file.txt -s file.sig -k public.key
```

## Verified Properties

SPARK verification proves:
- No buffer overflows
- No integer overflows
- No uninitialized memory access
- Correct key material handling
- Constant-time comparisons
- Memory properly zeroed after use

## Supported Algorithms

| Algorithm | Verified | Notes |
|-----------|----------|-------|
| AES-128/256 | ✅ | CBC, GCM modes |
| ChaCha20 | ✅ | With Poly1305 |
| SHA-256/512 | ✅ | HMAC variants |
| RSA | Partial | 2048/4096 bit |
| Ed25519 | ✅ | Signatures |
| X25519 | ✅ | Key exchange |

## Disclaimer

For authorized use only. Cryptographic tools may be restricted.

## License

NullSec Proprietary License

## Author

**bad-antics** - NullSec Security Team

---

*Part of the NullSec Security Toolkit*

---

[![GitHub](https://img.shields.io/badge/GitHub-bad--antics-181717?style=flat&logo=github&logoColor=white)](https://github.com/bad-antics)
[![Discord](https://img.shields.io/badge/Twitter-AnonAntics-1DA1F2?style=flat&logo=discord&logoColor=white)](https://x.com/AnonAntics)
