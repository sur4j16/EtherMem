import re
import logging
from typing import List, Dict, Set, Optional
from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class CryptoDetector(interfaces.plugins.PluginInterface):
    """Detects and extracts cryptocurrency transaction details from browser process memory"""
    
    _required_framework_version = (2, 0, 0)
    _version = (2, 2, 0)
    
    BROWSER_PROCESSES = [
        'firefox.exe', 'chrome.exe', 'msedge.exe', 
        'brave.exe', 'opera.exe', 'iexplore.exe'
    ]
    
    # Enhanced regex patterns
    PATTERNS = {
        'eth_address': re.compile(rb'0x[a-fA-F0-9]{40}'),
        'from_to': re.compile(rb'"(from|to)"\s*:\s*"(0x[a-fA-F0-9]{40})"'),
        'value': re.compile(rb'"value"\s*:\s*"(0x[a-fA-F0-9]+)"'),
        'gas': re.compile(rb'"(gas|gasLimit)"\s*:\s*"(0x[a-fA-F0-9]+)"'),
        'gas_price': re.compile(rb'"(gasPrice|maxFeePerGas|maxPriorityFeePerGas)"\s*:\s*"(0x[a-fA-F0-9]+)"'),
        'chain_id': re.compile(rb'"chainId"\s*:\s*"(0x[a-fA-F0-9]+)"'),
        'tx_hash_field': re.compile(rb'"transactionHash"\s*:\s*"(0x[a-fA-F0-9]{64})"'),
        'raw_tx': re.compile(rb'0x02f[0-9a-fA-F]{100,600}'),
        'sendtransaction': re.compile(rb'eth_sendTransaction|infura_simulateTransactions|eth_sendRawTransaction'),
    }

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name='kernel',
                description='Windows kernel',
                architectures=["Intel32", "Intel64"]
            ),
            requirements.ListRequirement(
                name='pid',
                description='Process IDs to include (all if empty)',
                element_type=int,
                optional=True
            ),
            requirements.BooleanRequirement(
                name='all_processes',
                description='Scan all processes, not just browsers',
                default=False,
                optional=True
            ),
            requirements.IntRequirement(
                name='max_size',
                description='Maximum VAD size to scan in MB',
                default=100,
                optional=True
            ),
            requirements.BooleanRequirement(
                name='verify',
                description='Verify transactions online via Etherscan (requires internet)',
                default=False,
                optional=True
            )
        ]

    def _is_browser_process(self, proc_name: str) -> bool:
        """Check if process is a known browser"""
        return any(browser.lower() in proc_name.lower() for browser in self.BROWSER_PROCESSES)
    
    def _check_internet_connection(self) -> bool:
        """Check if internet is available"""
        try:
            import urllib.request
            urllib.request.urlopen('https://www.google.com', timeout=3)
            return True
        except:
            return False
    
    def _get_chain_name(self, chain_id: str) -> str:
        """Convert chain ID to network name"""
        chain_map = {
            '0x1': 'mainnet',
            '0x5': 'goerli',
            '0xaa36a7': 'sepolia',
            '0x89': 'polygon',
            '0xa86a': 'avalanche',
            '0x38': 'bsc'
        }
        return chain_map.get(chain_id, 'mainnet')
    
    def _verify_transaction_online(self, tx_hash: str, chain_id: str = None) -> Dict:
        """Verify transaction on Etherscan"""
        try:
            import urllib.request
            import json
            
            network = self._get_chain_name(chain_id) if chain_id else 'mainnet'
            
            if network == 'mainnet':
                base_url = 'https://api.etherscan.io/api'
            elif network == 'sepolia':
                base_url = 'https://api-sepolia.etherscan.io/api'
            elif network == 'goerli':
                base_url = 'https://api-goerli.etherscan.io/api'
            else:
                base_url = 'https://api.etherscan.io/api'
            
            url = f"{base_url}?module=proxy&action=eth_getTransactionByHash&txhash={tx_hash}"
            
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0')
            
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                
                if data.get('result'):
                    result = data['result']
                    
                    if result:
                        return {
                            'verified': True,
                            'status': 'Confirmed',
                            'block': result.get('blockNumber', 'Unknown'),
                            'from': result.get('from', '').lower(),
                            'to': result.get('to', '').lower(),
                            'value': result.get('value', '0'),
                            'explorer_url': f"https://{network + '.' if network != 'mainnet' else ''}etherscan.io/tx/{tx_hash}"
                        }
                    else:
                        return {
                            'verified': False,
                            'status': 'Not Found',
                            'error': 'Transaction not found on blockchain'
                        }
                        
        except Exception as e:
            vollog.debug(f"Verification failed: {e}")
            return {
                'verified': False,
                'status': 'Verification Failed',
                'error': str(e)
            }
        
        return {'verified': False, 'status': 'Unknown'}

    def _hex_to_int(self, hex_str: str) -> int:
        """Convert hex string to integer"""
        try:
            return int(hex_str, 16)
        except:
            return 0

    def _hex_to_eth(self, hex_str: str) -> str:
        """Convert hex wei to ETH"""
        try:
            wei = int(hex_str, 16)
            if wei == 0:
                return None
            eth = wei / 1e18
            return f"{eth:.6f}"
        except:
            return None

    def _hex_to_gwei(self, hex_str: str) -> str:
        """Convert hex wei to Gwei"""
        try:
            wei = int(hex_str, 16)
            gwei = wei / 1e9
            return f"{gwei:.2f}"
        except:
            return None

    def _is_valid_address(self, addr: str) -> bool:
        """Check if address is valid (not all zeros, not multicall contract)"""
        if not addr or addr == '0x' + '0' * 40:
            return False
        if addr.lower() in ['0xca11bde05977b3631167028862be2a173976ca11']:
            return False
        return True

    def _keccak256(self, data: bytes) -> bytes:
        """Simple Keccak-256 implementation"""
        try:
            from eth_hash.auto import keccak
            return keccak(data)
        except ImportError:
            try:
                import hashlib
                return hashlib.sha3_256(data).digest()
            except:
                return None

    def _compute_tx_hash_from_raw(self, raw_tx_hex: str) -> Optional[str]:
        """Compute transaction hash from raw signed transaction"""
        try:
            if raw_tx_hex.startswith('0x'):
                raw_tx_hex = raw_tx_hex[2:]
            
            raw_bytes = bytes.fromhex(raw_tx_hex)
            hash_bytes = self._keccak256(raw_bytes)
            if hash_bytes:
                return '0x' + hash_bytes.hex()
        except Exception as e:
            vollog.debug(f"Error computing tx hash: {e}")
        return None

    def _parse_raw_transaction(self, raw_tx: str) -> Optional[Dict]:
        """Parse EIP-1559 raw transaction to extract details"""
        try:
            if not raw_tx.startswith('0x02'):
                return None
            
            raw_hex = raw_tx[2:]
            raw_bytes = bytes.fromhex(raw_hex)
            
            tx_info = {}
            
            tx_hash = self._compute_tx_hash_from_raw(raw_tx)
            if tx_hash:
                tx_info['tx_hash'] = tx_hash
            
            if len(raw_hex) > 100:
                for i in range(40, min(200, len(raw_hex) - 40), 2):
                    potential_addr = '0x' + raw_hex[i:i+40]
                    if self._is_valid_address(potential_addr):
                        tx_info['to'] = potential_addr.lower()
                        break
            
            return tx_info
        except Exception as e:
            vollog.debug(f"Error parsing raw tx: {e}")
        return None

    def _extract_all_data(self, data: bytes) -> tuple:
        """Extract all transaction-related data in one pass"""
        
        transactions = []
        observed_hashes = {}
        
        for match in self.PATTERNS['tx_hash_field'].finditer(data):
            tx_hash = match.group(1).decode('utf-8', errors='ignore').lower()
            
            start = max(0, match.start() - 1000)
            end = min(len(data), match.end() + 1000)
            context = data[start:end]
            
            nearby_addrs = set()
            for addr_match in self.PATTERNS['eth_address'].finditer(context):
                addr = addr_match.group().decode('utf-8', errors='ignore').lower()
                if self._is_valid_address(addr):
                    nearby_addrs.add(addr)
            
            if tx_hash not in observed_hashes:
                observed_hashes[tx_hash] = set()
            observed_hashes[tx_hash].update(nearby_addrs)
        
        for match in self.PATTERNS['raw_tx'].finditer(data):
            raw_tx = match.group().decode('utf-8', errors='ignore')
            
            parsed = self._parse_raw_transaction(raw_tx)
            if parsed and parsed.get('tx_hash'):
                tx_hash = parsed['tx_hash']
                
                start = max(0, match.start() - 2000)
                end = min(len(data), match.end() + 2000)
                context = data[start:end]
                
                nearby_addrs = set()
                for addr_match in self.PATTERNS['eth_address'].finditer(context):
                    addr = addr_match.group().decode('utf-8', errors='ignore').lower()
                    if self._is_valid_address(addr):
                        nearby_addrs.add(addr)
                
                if tx_hash not in observed_hashes:
                    observed_hashes[tx_hash] = set()
                observed_hashes[tx_hash].update(nearby_addrs)
        
        for match in self.PATTERNS['sendtransaction'].finditer(data):
            start = max(0, match.start() - 500)
            end = min(len(data), match.end() + 3000)
            chunk = data[start:end]
            
            tx_info = {
                'from': None,
                'to': None,
                'value': None,
                'gas': None,
                'gas_price': None,
                'chain_id': None,
                'tx_hash': None
            }
            
            # Extract from/to
            from_addr = None
            to_addr = None
            for ft_match in self.PATTERNS['from_to'].finditer(chunk):
                field = ft_match.group(1).decode('utf-8', errors='ignore')
                addr = ft_match.group(2).decode('utf-8', errors='ignore').lower()
                if not self._is_valid_address(addr):
                    continue
                if field == 'from' and not from_addr:
                    from_addr = addr
                elif field == 'to' and not to_addr:
                    to_addr = addr
            
            if not from_addr or not to_addr:
                continue
            
            tx_info['from'] = from_addr
            tx_info['to'] = to_addr
            
            # Extract value
            value_match = self.PATTERNS['value'].search(chunk)
            if value_match:
                value_eth = self._hex_to_eth(value_match.group(1).decode('utf-8'))
                if value_eth:
                    tx_info['value'] = value_eth
            
            # Extract gas
            gas_match = self.PATTERNS['gas'].search(chunk)
            if gas_match:
                gas_hex = gas_match.group(2).decode('utf-8')
                gas_int = self._hex_to_int(gas_hex)
                if gas_int > 0:
                    tx_info['gas'] = str(gas_int)
            
            # Extract gas price
            gas_price_match = self.PATTERNS['gas_price'].search(chunk)
            if gas_price_match:
                gwei = self._hex_to_gwei(gas_price_match.group(2).decode('utf-8'))
                if gwei:
                    tx_info['gas_price'] = gwei
            
            # Extract chain ID
            chain_match = self.PATTERNS['chain_id'].search(chunk)
            if chain_match:
                tx_info['chain_id'] = chain_match.group(1).decode('utf-8')
            
            # Require at least 3 fields
            field_count = sum([bool(v) for v in tx_info.values()])
            if field_count >= 3:
                transactions.append(tx_info)
        
        return transactions, observed_hashes

    def _merge_transactions(self, transactions: List[Dict], observed_hashes: Dict) -> List[Dict]:
        """
        Merge related transactions using tx_hash as primary key.
        This eliminates duplicates and creates complete transaction records.
        """
        tx_index = {}  # hash -> merged transaction
        orphan_txs = []  # transactions without hash yet
        
        for tx in transactions:
            if tx.get('tx_hash'):
                tx_hash = tx['tx_hash']
                if tx_hash not in tx_index:
                    tx_index[tx_hash] = tx.copy()
                else:
                    # Merge missing fields into existing entry
                    for key, value in tx.items():
                        if value and not tx_index[tx_hash].get(key):
                            tx_index[tx_hash][key] = value
            else:
                orphan_txs.append(tx)
        
        for tx in orphan_txs:
            from_addr = tx.get('from')
            to_addr = tx.get('to')
            
            if not from_addr or not to_addr:
                continue
            
            best_match = None
            best_score = 0
            
            for tx_hash, addrs in observed_hashes.items():
                score = 0
                if from_addr in addrs:
                    score += 1
                if to_addr in addrs:
                    score += 1
                
                if score == 2:
                    best_match = tx_hash
                    best_score = 2
                    break
                elif score > best_score:
                    best_score = score
                    best_match = tx_hash
            
            # If found a match with at least one address, merge it
            if best_match and best_score >= 1:
                if best_match not in tx_index:
                    tx['tx_hash'] = best_match
                    tx_index[best_match] = tx
                else:
                    # Merge fields into existing transaction
                    for key, value in tx.items():
                        if value and not tx_index[best_match].get(key):
                            tx_index[best_match][key] = value
            else:
                # Create standalone entry (no hash found)
                # Use from+to as temporary key
                temp_key = f"orphan_{from_addr}_{to_addr}"
                if temp_key not in tx_index:
                    tx_index[temp_key] = tx
        
        return list(tx_index.values())

    def _scan_process_vads(self, proc, proc_name: str, pid: int) -> tuple:
        """Scan process VADs and return transaction details (not yield)"""
        
        max_size_mb = self.config.get('max_size', 100)
        max_size_bytes = max_size_mb * 1024 * 1024
        
        try:
            proc_layer_name = proc.add_process_layer()
            if not proc_layer_name:
                return [], {}
        except Exception:
            return [], {}
        
        proc_layer = self.context.layers[proc_layer_name]
        
        all_transactions = []
        all_hashes = {}
        
        # Collect data from all VADs
        vads_scanned = 0
        for vad in proc.get_vad_root().traverse():
            try:
                start = vad.get_start()
                end = vad.get_end()
                size = end - start
                
                if size > max_size_bytes:
                    continue
                
                data = proc_layer.read(start, size, pad=True)
                
                transactions, observed_hashes = self._extract_all_data(data)
                all_transactions.extend(transactions)
                
                # Merge hash mappings
                for tx_hash, addrs in observed_hashes.items():
                    if tx_hash not in all_hashes:
                        all_hashes[tx_hash] = set()
                    all_hashes[tx_hash].update(addrs)
                
                vads_scanned += 1
                if vads_scanned > 500:
                    break
                    
            except Exception:
                continue
        
        return all_transactions, all_hashes

    def _generator(self, procs):
        """Generate results for detected crypto transactions"""
        
        all_processes = self.config.get('all_processes', False)
        verify_online = self.config.get('verify', False)
        
        vollog.info("Scanning for cryptocurrency transactions...")
        
        # Check internet once if verification is enabled
        internet_available = False
        if verify_online:
            vollog.info("Checking internet connectivity...")
            internet_available = self._check_internet_connection()
            if internet_available:
                vollog.info("Internet connected - will verify transactions online")
            else:
                vollog.info("No internet connection - showing offline results only")
        
        # Collect all transactions from all processes first
        global_transactions = []
        global_hashes = {}
        process_map = {}  # tx -> (pid, proc_name) for tracking origin
        
        for proc in procs:
            try:
                proc_name = proc.ImageFileName.cast(
                    "string", 
                    max_length=proc.ImageFileName.vol.count, 
                    errors='replace'
                )
            except Exception:
                continue
            
            if not all_processes and not self._is_browser_process(proc_name):
                continue
            
            pid = proc.UniqueProcessId
            vollog.info(f"Scanning: {proc_name} (PID: {pid})")
            
            try:
                transactions, hashes = self._scan_process_vads(proc, proc_name, pid)
                
                # Track which process each transaction came from
                for tx in transactions:
                    tx_key = (tx.get('from'), tx.get('to'), tx.get('value'))
                    if tx_key not in process_map:
                        process_map[tx_key] = []
                    process_map[tx_key].append((pid, proc_name))
                
                global_transactions.extend(transactions)
                
                # Merge hash mappings
                for tx_hash, addrs in hashes.items():
                    if tx_hash not in global_hashes:
                        global_hashes[tx_hash] = set()
                    global_hashes[tx_hash].update(addrs)
                    
            except Exception as e:
                vollog.warning(f"Error scanning PID {pid}: {str(e)}")
                continue
        
        # Now merge ALL transactions across ALL processes
        merged_txs = self._merge_transactions(global_transactions, global_hashes)
        
        if not merged_txs:
            vollog.info("No cryptocurrency transactions found")
            return
        
        vollog.info(f"Found {len(merged_txs)} unique transaction(s)")
        
        # Yield merged results
        for tx in merged_txs:
            # Find which process(es) this transaction came from
            tx_key = (tx.get('from'), tx.get('to'), tx.get('value'))
            pids_and_procs = process_map.get(tx_key, [(0, 'Unknown')])
            
            # Use the first process (they're all the same browser anyway)
            pid, proc_name = pids_and_procs[0]
            
            # Verify online if requested and hash exists
            verification_status = 'N/A'
            if verify_online and internet_available and tx.get('tx_hash'):
                vollog.info(f"Verifying transaction {tx['tx_hash'][:10]}...")
                verify_result = self._verify_transaction_online(tx['tx_hash'], tx.get('chain_id'))
                
                if verify_result['verified']:
                    verification_status = f"✓ Confirmed (Block: {verify_result['block']})"
                else:
                    verification_status = f"✗ {verify_result['status']}"
            
            yield (0, (
                format_hints.Hex(pid),
                proc_name,
                tx.get('from') or 'N/A',
                tx.get('to') or 'N/A',
                tx.get('value') or 'N/A',
                tx.get('gas') or 'N/A',
                tx.get('gas_price') or 'N/A',
                tx.get('chain_id') or 'N/A',
                tx.get('tx_hash') or 'N/A',
                verification_status
            ))

    def run(self):
        pids = self.config.get('pid', None)
        if pids:
            filter_func = pslist.PsList.create_pid_filter(pids)
        else:
            filter_func = pslist.PsList.create_pid_filter([])
        
        return renderers.TreeGrid(
            [
                ("PID", format_hints.Hex),
                ("Process", str),
                ("From Address", str),
                ("To Address", str),
                ("Value (ETH)", str),
                ("Gas Limit", str),
                ("Gas Price (Gwei)", str),
                ("Chain ID", str),
                ("Tx Hash", str),
                ("Verification", str)
            ],
            self._generator(
                pslist.PsList.list_processes(
                    context=self.context,
                    kernel_module_name=self.config['kernel'],
                    filter_func=filter_func
                )
            )
        )