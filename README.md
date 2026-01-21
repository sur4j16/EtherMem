# EtherMem - Volatility 3 Plugin

A forensic memory analysis plugin for Volatility 3 that detects and extracts Ethereum cryptocurrency transaction details from browser process memory.

##  Overview

This plugin scans Windows memory dumps to recover cryptocurrency transactions that occurred in web browsers. Currently tested with **MetaMask on Sepolia Ethereum testnet**. It's particularly useful for:

- **Digital forensics investigations** involving cryptocurrency theft or fraud
- **Incident response** to recover transaction evidence from compromised systems
- **Security research** into browser memory artifacts
- **Blockchain forensics** to correlate on-chain and off-chain data

##  Features

-  **MetaMask support**: Currently tested with MetaMask browser extension
-  **Sepolia testnet**: Verified functionality on Sepolia Ethereum testnet
-  **Complete transaction recovery**: Extracts sender, recipient, value, gas, and transaction hash
-  **Cross-process correlation**: Merges transaction fragments across browser subprocesses
-  **Smart deduplication**: Eliminates duplicate artifacts using hash-based merging
-  **Online verification**: Optional Etherscan integration to verify transactions on-chain
-  **Raw transaction parsing**: Extracts data from EIP-1559 signed transactions

**Note**: While the plugin includes patterns for multiple browsers and blockchains, it has only been tested with MetaMask on Sepolia testnet. Other configurations may work but are not yet verified.

## Requirements

### Volatility 3
```bash
# Install Volatility 3
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip install -r requirements.txt
```

##  Installation

1. Copy the plugin to your Volatility 3 plugins directory:
```bash
cp ethermem.py volatility3/volatility3/plugins/windows/
```

2. Verify installation:
```bash
python vol.py --help | grep ethermem
```

##  Usage

### Basic Scan
Scan all browser processes for cryptocurrency transactions:
```bash
python vol.py -f memdump.mem windows.ethermem
```

### Scan Specific Process
Target a specific browser process by PID:
```bash
python vol.py -f memdump.mem windows.ethermem --pid 1234
```

### Scan All Processes
Scan all processes, not just browsers:
```bash
python vol.py -f memdump.mem windows.ethermem --all_processes
```

### Online Verification
Verify transactions against Etherscan (requires internet):
```bash
python vol.py -f memdump.mem windows.ethermem --verify
```

### Adjust Memory Scan Limits
Set maximum VAD size to scan (in MB):
```bash
python vol.py -f memdump.mem windows.ethermem --max_size 200
```

##  Output Format

```
PID     Process       From Address                                To Address                                  Value (ETH)  Gas Limit  Gas Price (Gwei)  Chain ID  Tx Hash                                                            Verification
0x2ec   firefox.exe   0xc43581f4a991f9fb724ce50d153e156b07fcdc5c  0x126e07c2e78fe16794ccc8d48446fe76fea8fdb4  0.000100     31500      1.50             0xaa36a7  0xdf5efc2f3f3aa08297dd4ae79e228d9925e234370f4e5544535af36378927087  ✓ Confirmed (Block: 0x123456)
```

### Field Descriptions

| Field | Description |
|-------|-------------|
| **PID** | Process ID where transaction was found |
| **Process** | Process name (browser executable) |
| **From Address** | Ethereum address sending the transaction |
| **To Address** | Ethereum address receiving the transaction |
| **Value (ETH)** | Amount of ETH transferred |
| **Gas Limit** | Maximum gas units allocated |
| **Gas Price (Gwei)** | Gas price in Gwei |
| **Chain ID** | Blockchain network identifier |
| **Tx Hash** | Transaction hash (if available) |
| **Verification** | Online verification status (if --verify enabled) |

### Chain ID Reference

| Chain ID | Network | Testing Status |
|----------|---------|----------------|
| 0xaa36a7 | Sepolia Testnet |  Tested |
| 0x1 | Ethereum Mainnet |  Untested |
| 0x5 | Goerli Testnet |  Untested |
| 0x89 | Polygon |  Untested |
| 0xa86a | Avalanche |  Untested |
| 0x38 | Binance Smart Chain |  Untested |

## 🔬 How It Works

### Detection Strategy

1. **Pattern Matching**: Scans process Virtual Address Descriptors (VADs) for:
   - Ethereum addresses (0x + 40 hex chars)
   - JSON-RPC transaction objects
   - Transaction hashes in receipts
   - Raw signed transactions (EIP-1559)

2. **Data Extraction**: Parses memory for:
   - `eth_sendTransaction` RPC calls
   - Transaction receipts with hashes
   - Gas parameters and values
   - Chain identifiers

3. **Intelligent Correlation**: 
   - Matches transaction fragments using address pairs
   - Links orphan hashes to transaction objects
   - Merges partial data from multiple memory locations

4. **Cross-Process Merging**:
   - Collects data from all browser subprocesses
   - Merges fragments using transaction hash as primary key
   - Produces single complete record per transaction

### Memory Artifacts

The plugin targets these browser memory artifacts:
- **MetaMask extension state** (transaction history, pending txs)
- **Web3 provider buffers** (Infura, Alchemy responses)
- **Browser cache** (API responses, receipts)
- **JavaScript heap** (wallet objects, transaction queues)

##  Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--pid` | List[int] | None | Specific process IDs to scan |
| `--all_processes` | Bool | False | Scan all processes, not just browsers |
| `--max_size` | Int | 100 | Maximum VAD size in MB |
| `--verify` | Bool | False | Verify transactions online via Etherscan |

##  Testing

### Sample Test Case
```bash
# Tested scenario:
# 1. Open MetaMask browser extension
# 2. Send a test transaction on Sepolia testnet
# 3. Capture memory dump
# 4. Run plugin

python vol.py -f memdump.mem windows.ethermem --verify
```

### Testing Status
-  **Tested**: MetaMask + Sepolia testnet
-  **Untested**: Other wallets, browsers, and blockchain networks
-  **Contributions welcome**: Help expand testing coverage!

##  Forensic Considerations

### Evidence Integrity
- **Read-only analysis**: Plugin only reads memory, never modifies it
- **Artifact preservation**: All extracted data preserved in original form
- **Chain of custody**: Document plugin version and parameters used

### Legal/Privacy Notes
- Memory dumps may contain sensitive data (private keys, passwords)
- Follow proper evidence handling procedures
- Obtain appropriate legal authorization before analysis
- Consider data privacy regulations (GDPR, etc.)

##  Troubleshooting

### No Transactions Found
- Ensure memory dump contains browser processes
- Try `--all_processes` flag
- Increase `--max_size` if large browser processes
- Transaction may have been overwritten in memory

### Partial Transaction Data
- Some fields show "N/A" - this is normal for partial artifacts
- Browser memory is fragmented; complete recovery not always possible
- Different browser versions store data differently

### Verification Fails
- Check internet connectivity
- Etherscan API may be rate-limited
- Transaction might be on different network than expected
- Hash may be corrupted in memory

##  Technical Details

### Regex Patterns
- **Ethereum Address**: `0x[a-fA-F0-9]{40}`
- **Transaction Hash**: `0x[a-fA-F0-9]{64}`
- **EIP-1559 Raw Tx**: `0x02f[0-9a-fA-F]{100,600}`

### Conversion Functions
- **Wei to ETH**: `value / 10^18`
- **Wei to Gwei**: `value / 10^9`
- **Hex to Decimal**: Standard base-16 conversion

### Deduplication Algorithm
1. Index all transactions by hash (primary key)
2. Merge transactions with same hash but different fields
3. Match orphan transactions to known hashes via address correlation
4. Score matches: 2 points for both addresses, 1 for partial match
5. Output single merged record per unique transaction

---
