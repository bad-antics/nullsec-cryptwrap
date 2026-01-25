# Cryptographic Wrapper Guide

## Overview
Secure wrapper implementations for cryptographic operations.

## Key Wrapping

### Algorithms
- AES Key Wrap (RFC 3394)
- AES-GCM-SIV wrapping
- RSA-OAEP wrapping
- ECDH key agreement

### Use Cases
- Key transport
- Key backup
- Key escrow
- Hardware integration

## Envelope Encryption

### Pattern
- Generate DEK
- Encrypt data with DEK
- Wrap DEK with KEK
- Store wrapped DEK

### Benefits
- Key rotation
- Access control
- Audit logging
- Performance

## Implementation

### Secure Defaults
- Strong algorithms
- Proper key sizes
- Authenticated encryption
- Safe IV handling

### Error Handling
- Constant time operations
- Safe error messages
- Cleanup on failure
- Exception safety

## Integration

### HSM Support
- PKCS#11 interface
- Key generation
- Wrap/unwrap operations
- Access controls

### Cloud KMS
- AWS KMS
- Azure Key Vault
- Google Cloud KMS
- HashiCorp Vault

## Best Practices
- Never log keys
- Secure memory
- Key rotation
- Audit trails

## Legal Notice
For secure implementations only.
