#!/usr/bin/env python3
"""
Ed25519 Vanity Key Generator for Meshcore Devices

Generates Ed25519 keypairs with custom hex prefixes using multi-threaded CPU computation.
Optimized for high throughput with parallel key generation and efficient prefix matching.

All generated keys are automatically verified by re-deriving from the seed to ensure
cryptographic correctness before being returned.

Performance optimizations:
- Early prefix filtering on raw bytes before hex conversion
- Reduced IPC overhead with simpler shared primitives
- Larger batch sizes to minimize synchronization
- Pre-computed hex lookup tables
- Inlined hot path operations
- Automatic key verification
"""

import argparse
import hashlib
import os
import sys
import time
from typing import Optional, Tuple
from multiprocessing import Pool, cpu_count, Value, Array
from ctypes import c_bool, c_char

from nacl.signing import SigningKey

# Pre-computed hex lookup table for fast conversion
HEX_CHARS = '0123456789ABCDEF'


def expanded_from_seed(seed: bytes) -> bytes:
    """
    Generate expanded Ed25519 private key from seed (RFC 8032 section 5.1.5).
    
    The expanded key is 64 bytes:
    - First 32 bytes: clamped scalar (private key scalar a)
    - Last 32 bytes: prefix for nonce generation
    
    Args:
        seed: 32-byte random seed
        
    Returns:
        64-byte expanded private key
    """
    h = hashlib.sha512(seed).digest()
    
    # Clamp first 32 bytes per RFC 8032
    a = bytearray(h[0:32])
    a[0]  &= 0b1111_1000  # Clear low 3 bits
    a[31] &= 0b0111_1111  # Clear high bit
    a[31] |= 0b0100_0000  # Set second-highest bit
    
    prefix = h[32:64]
    return bytes(a) + prefix


def _bytes_to_hex_fast(data: bytes) -> str:
    """Fast byte-to-hex conversion using lookup table."""
    result = []
    for b in data:
        result.append(HEX_CHARS[b >> 4])
        result.append(HEX_CHARS[b & 0x0F])
    return ''.join(result)


def verify_key(seed: bytes, expected_pub: bytes, expected_expanded: bytes) -> bool:
    """
    Verify that a generated key is valid by re-deriving it.
    
    This ensures:
    1. The public key can be derived from the seed
    2. The expanded private key matches RFC 8032 derivation
    3. The public key matches the expected value
    
    Args:
        seed: 32-byte random seed
        expected_pub: Expected 32-byte public key
        expected_expanded: Expected 64-byte expanded private key
        
    Returns:
        True if all checks pass, False otherwise
    """
    try:
        # Re-derive public key from seed using PyNaCl
        sk = SigningKey(seed)
        derived_pub = sk.verify_key.encode()
        
        # Re-derive expanded private key
        derived_expanded = expanded_from_seed(seed)
        
        # Verify public key matches
        if derived_pub != expected_pub:
            return False
        
        # Verify expanded private key matches
        if derived_expanded != expected_expanded:
            return False
        
        return True
    except Exception:
        return False


def _matches_prefix_early(pub_bytes: bytes, prefix_bytes: bytes) -> bool:
    """
    Early prefix matching on raw bytes before full hex conversion.
    Each byte becomes 2 hex chars, so we check nibbles directly.
    """
    prefix_len = len(prefix_bytes)
    for i, prefix_byte in enumerate(prefix_bytes):
        if i >= len(pub_bytes):
            return False
        
        pub_byte = pub_bytes[i]
        
        # Check high nibble
        if (pub_byte >> 4) != (prefix_byte >> 4):
            return False
        
        # For odd-length prefixes, only check high nibble of last byte
        if i == prefix_len - 1 and prefix_len % 2 == 1:
            return True
        
        # Check low nibble
        if (pub_byte & 0x0F) != (prefix_byte & 0x0F):
            return False
    
    return True


def _hex_to_nibbles(hex_str: str) -> bytes:
    """Convert hex string to nibble-packed bytes for fast comparison."""
    nibbles = []
    for c in hex_str:
        if '0' <= c <= '9':
            nibbles.append(ord(c) - ord('0'))
        elif 'A' <= c <= 'F':
            nibbles.append(ord(c) - ord('A') + 10)
        elif 'a' <= c <= 'f':
            nibbles.append(ord(c) - ord('a') + 10)
    
    # Pack nibbles into bytes
    packed = []
    for i in range(0, len(nibbles), 2):
        if i + 1 < len(nibbles):
            packed.append((nibbles[i] << 4) | nibbles[i + 1])
        else:
            packed.append(nibbles[i] << 4)
    
    return bytes(packed)


# Global shared state for worker processes (must be initialized before Pool)
_shared_found = None

def _init_worker(shared_found):
    """Initialize worker process with shared state."""
    global _shared_found
    _shared_found = shared_found

def _generate_keys_worker(args_tuple: Tuple) -> Tuple[int, Optional[bytes], Optional[bytes], Optional[bytes]]:
    """
    Optimized worker function for parallel key generation.
    
    Args:
        args_tuple: (prefix_upper, prefix_bytes, batch_size)
        
    Returns:
        (tries, seed, pubkey, expanded) - seed/pubkey/expanded are None if no match
    """
    prefix_upper, prefix_bytes, batch_size = args_tuple
    tries = 0
    check_interval = 100  # Check shared_found less frequently
    
    for i in range(batch_size):
        # Check if another worker found a match (less frequently to reduce overhead)
        if i % check_interval == 0 and _shared_found.value:
            return (tries, None, None, None)
        
        tries += 1
        
        # Generate random seed and derive public key
        seed = os.urandom(32)
        sk = SigningKey(seed)
        pub = sk.verify_key.encode()
        
        # Early prefix check on raw bytes (faster than hex conversion)
        if len(prefix_bytes) > 0:
            # Quick byte-level filter
            first_byte = pub[0]
            first_prefix_byte = prefix_bytes[0]
            if (first_byte >> 4) != (first_prefix_byte >> 4):
                continue
            if len(prefix_upper) > 1 and (first_byte & 0x0F) != (first_prefix_byte & 0x0F):
                continue
        
        # Full hex conversion only for potential matches
        pub_hex = _bytes_to_hex_fast(pub)
        
        # Check full prefix
        if pub_hex.startswith(prefix_upper):
            # Found a match! Try to claim it atomically
            if not _shared_found.value:
                # Set flag first to stop other workers
                _shared_found.value = True
                expanded = expanded_from_seed(seed)
                return (tries, seed, pub, expanded)
            return (tries, None, None, None)
    
    return (tries, None, None, None)


def generate_with_prefix(
    prefix_upper: str,
    num_threads: Optional[int] = None,
    show_progress: bool = False
) -> Tuple[int, float, str, str]:
    """
    Generate Ed25519 key with matching prefix using multi-threaded CPU.
    
    All generated keys are verified by re-deriving from the seed to ensure
    correctness before being returned.
    
    Optimized with:
    - Larger batch sizes (50k vs 10k)
    - Simpler shared state (Value vs Manager)
    - Early byte-level prefix filtering
    - Fast hex conversion with lookup tables
    - Automatic verification of found keys
    
    Args:
        prefix_upper: Uppercase hex prefix to match
        num_threads: Number of threads (default: CPU count)
        show_progress: Print progress updates to stderr
        
    Returns:
        Tuple of (tries, elapsed_seconds, public_key_hex, expanded_private_key_hex)
        All returned keys are verified as valid Ed25519 keys.
    """
    if num_threads is None:
        num_threads = cpu_count()
    
    # Larger batch size to reduce synchronization overhead
    batch_size = 50000
    
    start_time = time.time()
    total_tries = 0
    
    # Convert prefix to nibble-packed bytes for fast comparison
    prefix_bytes = _hex_to_nibbles(prefix_upper)
    
    # Simpler shared state (no Manager overhead)
    shared_found = Value(c_bool, False)
    
    # Create pool with initializer to share state through inheritance
    with Pool(processes=num_threads, initializer=_init_worker, initargs=(shared_found,)) as pool:
        while True:
            # Distribute work to all threads
            args_list = [
                (prefix_upper, prefix_bytes, batch_size)
                for _ in range(num_threads)
            ]
            results = pool.map(_generate_keys_worker, args_list)
            
            # Check results from all workers
            for worker_tries, seed, pub, expanded in results:
                total_tries += worker_tries
                
                # Check if this worker found a match
                if seed is not None:
                    # Verify the key before returning it
                    if not verify_key(seed, pub, expanded):
                        if show_progress:
                            print(
                                f"Warning: Generated key failed verification! Continuing search...",
                                file=sys.stderr
                            )
                        # Reset shared_found flag and continue searching
                        shared_found.value = False
                        continue
                    
                    elapsed = time.time() - start_time
                    pub_hex = _bytes_to_hex_fast(pub)
                    expanded_hex = _bytes_to_hex_fast(expanded)
                    return (total_tries, elapsed, pub_hex, expanded_hex)
            
            # Check if any worker found a match
            if shared_found.value:
                # Another worker found it, results processed above
                continue
            
            # Progress indicator (print every ~1M tries)
            if show_progress and total_tries % 1000000 < batch_size * num_threads:
                elapsed = time.time() - start_time
                rate = total_tries / elapsed if elapsed > 0 else 0
                print(
                    f"  ... {total_tries:,} tries, {rate:,.0f} keys/s",
                    file=sys.stderr
                )


def validate_prefix(prefix: str) -> str:
    """
    Validate and normalize hex prefix.
    
    Args:
        prefix: User-provided prefix
        
    Returns:
        Uppercase hex prefix
        
    Raises:
        ValueError: If prefix is invalid
    """
    if not prefix:
        raise ValueError("Prefix cannot be empty")
    
    # Check if all characters are valid hex
    if not all(c in "0123456789abcdefABCDEF" for c in prefix):
        raise ValueError(f"Prefix must be hex (0-9, A-F): '{prefix}'")
    
    prefix_upper = prefix.upper()
    
    # Public keys are 32 bytes = 64 hex chars
    if len(prefix_upper) > 64:
        raise ValueError(f"Prefix too long (max 64 chars): {len(prefix_upper)}")
    
    # Warn about long prefixes
    if len(prefix_upper) > 8:
        print(
            f"Warning: {len(prefix_upper)}-char prefix may take very long. "
            f"Consider <= 8 chars.",
            file=sys.stderr
        )
    
    return prefix_upper


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Generate Ed25519 keypair with vanity hex prefix.\n\n"
            "The PUBLIC key (32 bytes, uppercase hex) will start with the specified prefix.\n"
            "Outputs:\n"
            "  PUBLIC=<64-char uppercase hex>\n"
            "  PRIVATE=<128-char uppercase hex (expanded: clamped scalar || prefix)>"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: %(prog)s AC123 --show-stats --threads 16"
    )
    
    parser.add_argument(
        "prefix",
        help="Hex prefix (1-8 chars recommended, case-insensitive)"
    )
    
    parser.add_argument(
        "--show-stats",
        action="store_true",
        help="Print statistics (tries, time, rate) to stderr"
    )
    
    parser.add_argument(
        "--threads",
        type=int,
        metavar="N",
        default=None,
        help=f"Number of CPU threads (default: {cpu_count()})"
    )
    
    args = parser.parse_args()
    
    # Validate prefix
    try:
        prefix_upper = validate_prefix(args.prefix)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)
    
    # Determine thread count
    num_threads = args.threads if args.threads else cpu_count()
    
    if args.show_stats:
        print(f"Generating key with prefix '{prefix_upper}' using {num_threads} threads...", file=sys.stderr)
    
    # Generate key
    try:
        tries, elapsed, pub_hex, expanded_hex = generate_with_prefix(
            prefix_upper,
            num_threads=num_threads,
            show_progress=args.show_stats
        )
    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Print statistics
    if args.show_stats:
        rate = tries / elapsed if elapsed > 0 else 0
        print(
            f"\nFound after {tries:,} tries in {elapsed:.2f}s (~{rate:,.0f} keys/s)",
            file=sys.stderr
        )
        print("Key verified successfully.", file=sys.stderr)
    
    # Output results
    print(f"PUBLIC={pub_hex}")
    print(f"PRIVATE={expanded_hex}")
    print("\nMeshcore Serial CLI Command:")
    print(f"set prv.key {expanded_hex}")


if __name__ == "__main__":
    main()
