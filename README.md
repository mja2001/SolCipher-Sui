# SolCipher-Sui
spork 🔐 | On-chain symmetric encryption for Sui. Simple, secure, and fun. Fork it, spork it, encrypt everything.
# spork 🥄🔐

**On-chain symmetric encryption for Sui.**  
Simple. Secure. A little ridiculous.

Encrypt secrets, messages, or just vibe — 100% on Sui, zero trust needed.

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Sui](https://img.shields.io/badge/blockchain-Sui-teal)](https://sui.io)

## Why spork?

- 🥄 It's a fork… but also a spoon (you're gonna use it every day)  
- 🔐 True on-chain symmetric encryption in pure Move  
- ⚡️ Blazing fast thanks to Sui’s parallel execution  
- 🛡️ Keys are owned Move objects — can't be copied, can't be lost  
- 🎯 Ideal for encrypted NFTs, private DeFi, secret messages, or pure chaos

## Quick Start

```bash
git clone https://github.com/yourusername/spork.git
cd spork

# Build
sui move build

# Test
sui move test

# Publish to Testnet
sui client publish --gas-budget 100000000
