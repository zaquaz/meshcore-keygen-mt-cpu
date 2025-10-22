# Meshcore Keygen

Highly optimized Ed25519 vanity key generator for Meshcore devices.

## Overview

This tool generates Ed25519 keypairs with custom hex prefixes for the public key. It uses a highly optimized multi-threaded CPU implementation.


## Performance

Multi-threaded CPU implementation achieves:
- **16-core CPU**: ~400,000-800,000 keys/s (depending on CPU model)
- **32-core CPU**: ~800,000-1,500,000 keys/s (depending on CPU model)

Performance scales nearly linearly with core count on modern CPUs.

## How It Works

The optimized key generation pipeline works as follows:

1. **Parallel seed generation**: Each worker thread generates random 32-byte seeds
2. **Ed25519 key derivation**: Uses PyNaCl's RFC 8032 compliant implementation
3. **Early byte filtering**: Checks first bytes directly before expensive hex conversion
4. **Fast hex conversion**: Custom lookup-table based hex conversion (faster than Python's .hex())
5. **Prefix matching**: Only full string comparison for candidates that pass byte filter
6. **Automatic verification**: Found keys are re-derived from seed to verify correctness

Workers check for matches from other threads infrequently (every 100 keys) to minimize shared state overhead. Batch sizes of 50,000 keys reduce synchronization while keeping latency reasonable.

### Key Verification

Every generated key undergoes automatic verification before being returned:
- Public key is re-derived from the seed using PyNaCl
- Expanded private key is re-computed following RFC 8032
- Both are compared to the originally generated values
- Only verified keys are returned to the user

## Requirements

- Python 3.8+
- PyNaCl (Ed25519 cryptography library)

## Installation

```bash
pip install pynacl
```

Or:

```bash
pip install -r requirements.txt
```

## Usage

Generate a key with a specific hex prefix:

```bash
python meshcore_keygen.py AC123 --show-stats
```

Options:
- `PREFIX`: Hex string (case-insensitive, up to 8 chars recommended)
- `--show-stats`: Display generation statistics (tries, time, rate)
- `--threads N`: Number of CPU threads to use (default: auto-detect CPU count)

Examples:
```bash
# Use all available CPU cores
python meshcore_keygen.py AC123 --show-stats

# Limit to 8 threads
python meshcore_keygen.py AC123 --show-stats --threads 8

# Quick generation without stats
python meshcore_keygen.py AB
```

## Output

```
PUBLIC=<64-character hex public key>
PRIVATE=<128-character hex expanded private key>

Meshcore Serial CLI Command:
set prv.key <expanded_private_key>
```

The private key is the RFC 8032 expanded format: clamped scalar (32 bytes) concatenated with the hash prefix (32 bytes).

## Prefix Length Considerations

Prefix length affects generation time exponentially (16 possibilities per hex char):
- **1-2 chars**: Instant (<1 second)
- **3 chars**: ~1 second
- **4 chars**: ~15 seconds (65k attempts avg)
- **5 chars**: ~4 minutes (1M attempts avg)
- **6 chars**: ~1 hour (16M attempts avg)
- **7 chars**: ~16 hours (256M attempts avg)
- **8 chars**: ~10 days (4B attempts avg)

Actual times depend on CPU performance and core count. Recommended maximum is 6-7 characters for practical use. On a 9800x3D, finding a 6 character prefix took roughly 23 seconds in test, but can range lower or higher depending on luck. 

## Performance Optimization Details

The optimized implementation includes:

1. **Early Byte Filtering**: Before converting to hex string, the code checks if the first bytes match the prefix nibbles directly. This eliminates ~93.75% of candidates (for most prefixes) before expensive hex conversion.

2. **Fast Hex Conversion**: Uses pre-computed lookup tables instead of Python's built-in `.hex()` method, providing speedup for hex conversion.

3. **Reduced Shared State**: Uses simple `Value(c_bool)` instead of `Manager().dict()` to eliminate IPC overhead between processes.

4. **Large Batches**: 50,000 keys per worker iteration reduces synchronization frequency while keeping match detection latency reasonable.

5. **Infrequent Flag Checks**: Workers only check if another thread found a match every 100 iterations, reducing shared memory access overhead.



````
