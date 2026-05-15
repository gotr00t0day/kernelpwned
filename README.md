# KernelPWN - Linux Kernel Vulnerability Scanner

![Alt text](https://github.com/gotr00t0day/kernelpwned/blob/main/linux.png)

A lightweight, fast kernel vulnerability scanner written in C++ that automatically detects if your Linux kernel is vulnerable to known privilege escalation exploits.

## Overview

KernelPWN scans your current Linux kernel version and cross-references it against a database of known kernel vulnerabilities. It's designed for penetration testers, security researchers, and system administrators who need to quickly assess kernel vulnerability status.

## Features

- ✅ **Fast Detection** - C++ implementation provides near-instant vulnerability scanning
- ✅ **Multiple Exploits** - Checks for 4 major kernel vulnerabilities
- ✅ **PoC Links** - Direct GitHub links to proof-of-concept exploits
- ✅ **Color-Coded Output** - Easy-to-read terminal output with ANSI colors
- ✅ **Distribution Detection** - Identifies your Linux distribution
- ✅ **No Dependencies** - Single static binary, no external libraries required

## Vulnerabilities Detected

### 1. Dirty COW (CVE-2016-5195)
- **Affected Kernels:** 2.0.0 - 4.8.3
- **Type:** Race condition in copy-on-write mechanism
- **Impact:** Privilege escalation to root
- **PoC:** https://github.com/firefart/dirtycow

### 2. Dirty Pipe (CVE-2022-0847)
- **Affected Kernels:** 5.8.0 - 5.16.10
- **Type:** Write to arbitrary read-only files
- **Impact:** Privilege escalation to root
- **PoC:** https://github.com/Al1ex/CVE-2022-0847

### 3. GameOver(lay) (CVE-2023-32629)
- **Affected Kernels:** 6.2.0, 5.19.0, 5.4.0 (Ubuntu-specific)
- **Type:** Overlay filesystem vulnerability
- **Impact:** Privilege escalation to root
- **PoC:** https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629

### 4. CVE-2024-1086
- **Affected Kernels:** 3.15.0 - 6.8.0
- **Type:** Use-after-free in netfilter subsystem
- **Impact:** Privilege escalation to root
- **PoC:** https://github.com/Notselwyn/CVE-2024-1086

### 5. Copy Fail
- **Affected Kernels:** 4.14+ through 6.18.21, 6.19.11, and 7.0-rc1 
- **Type:** Logic flaw in the kernel crypto path: AF_ALG AEAD (algif_aead) + authencesn
- **Impact:** Privilege escalation to root
- **PoC:** https://xint.io/blog/copy-fail-linux-distributions

### 6. Dirty Frag
- **Affected Kernels:** 4.14+ through 6.18.21, 6.19.11, and 7.0-rc1 
- **Type:** Vulnerable kernel networking and memory-fragment handling components
- **Impact:** Privilege escalation to root
- **PoC:** https://github.com/V4bel/dirtyfrag

- ### 6. Fraqnesia
- **Affected Kernels:** 4.14+ through 6.18.21, 6.19.11, and 7.0-rc1 
- **Type:** Allows an unprivileged local attacker to gain root access by corrupting the kernel page cache of read-only files
- **Impact:** Privilege escalation to root
- **PoC:** https://github.com/v12-security/pocs/tree/main/fragnesia

## Requirements

- **Operating System:** Linux (any distribution)
- **Compiler:** g++ or clang++ with C++17 support
- **Build Tool:** GNU Make
- **Architecture:** x86_64, ARM64, or any Linux-supported architecture

## Installation

### Quick Build

```bash
# Navigate to the project directory
cd kernelpwned

# Build the project
make

# The executable will be at bin/kernelpwned
```

### System-Wide Installation

```bash
# Build and install to /usr/local/bin (requires sudo)
make
sudo make install

# Now you can run from anywhere
kernelpwned
```

### Uninstallation

```bash
sudo make uninstall
```

## Usage

### Basic Usage

```bash
# Run from build directory
./bin/kernelpwned

# Or if installed system-wide
kernelpwned
```

## License

This tool is provided for educational and security research purposes.
