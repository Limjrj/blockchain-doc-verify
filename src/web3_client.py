# src/web3_client.py
# -----------------------------------------------------------------------------
# Web3 client wrapper for project
#
# Responsibilities
# - Load env (RPC_URL, CHAIN_ID, PRIVATE_KEY, CONTRACT_ADDRESS, ABI_PATH)
# - Connect to the RPC and create a web3 instance
# - Load the contract ABI (from artifacts/DocumentVerification.abi.json by default)
#   and it's address (from .env or artifacts/contract_address.json)
# - Expose helpers to build/send signed transactions and wait for receipts
#
# Error handling
# - Clear, actionable RuntimeErro/SysExit messages for missing env, bad keys,
#   RPC connectivity, or missing artifacts
#
# Performance/Best practices
# - Reuse one Web3 instance and account object
# - Use EIP-1559 fee fields when available:; fall back to gasPrice otherwise
# - Estimate gas with a cap to avoid accidental runaway limits
#
# NOTE: this module intentionally does NOT compute digests or sign EIP-191
#       messages, it is done in specific scripts such as store_hash.py so
#       the signing logic lives near the use-site
# -----------------------------------------------------------------------------

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Dict, Any

from dotenv import load_dotenv
from eth_account import Account
from web3 import Web3
from web3.contract import Contract

# Default artifact locations (relative to project root)
ABI_DEFAULT_PATH = "artifacts/DocumentVerifcation.abi.json"
ADDR_JSON_DEFAULT_PATH = "artifacts/contract_address.json"

@dataclass
class Web3Client:
    """Thin wrapper around web3 + a bound contract instance"""
    w3: Web3
    chain_id: int
    account: Account
    contract: Contract

    # Constructors
    @staticmethod
    def from_env(
        *,
        abi_path: Optional[str] = None,
        contract_address: Optional[str] = None,
        address_json_path: str = ADDR_JSON_DEFAULT_PATH,
        request_timeout_sec: int = 30,
    ) -> "Web3Client":
        """
        Build a Web3Client from environment variables and artifacts.

        Env variables used:
            - RPC_URL (preferred) or SEPOLIA_RPC_URL
            - CHAIN_ID (e.g., 11155111 for Sepolia)
            - PRIVATE_KEY (preferred) or SEPOLIA_PRIVATE_KEY (0x-prefixed, 32 bytes)
            - CONTRACT_ADDRESS (optional; else read artifacts/contract_address.json)
            - ABI_PATH (optional; defaults to artifacts/DocumentVerification.abi.json)
        """
        load_dotenv()

        # RPC URL
        rpc_url = os.getenv("RPC_URL") or os.getenv("SEPOLIA_RPC_URL") or ""
        if not rpc_url:
            raise RuntimeError("Missing RPC_URL or SEPOLIA_RPC_URL in .env")
        
        # Chain ID
        chain_id_str = os.getenv("CHAIN_ID") or ""
        if not chain_id_str:
            raise RuntimeError("Missing CHAIN_ID in .env (e.g. 11155111 for Sepolia)")
        try:
            chain_id = int(chain_id_str)
        except ValueError as e:
            raise RuntimeError("CHAIN_ID must be an integer") from e
        
        # Private key (0x + 64 hex chars)
        priv = os.getenv("PRIVATE_KEY") or os.getenv("SEPOLIA_PRIVATE_KEY") or ""
        if not (priv.startswith("0x") and len(priv)>=66):
            raise RuntimeError("Missing/Invalid PRIVATE_KEY in .env (expected 0x-prefixed 32-bytes)")
        
        # Connect to RPC
        w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": request_timeout_sec}))
        if not w3.is_connected():
            raise RuntimeError(f"Failed to connect to RPC at {rpc_url}")
        
        # Load account
        account = Account.from_key(priv)

        # Load ABI (prefer explicit path; else .env, else default)
        abi_path = abi_path or os.getenv("ABI_PATH") or ABI_DEFAULT_PATH
        abi = _load_abi(abi_path)

        # Resolve contract address (explicit arg > .env > artifacts file)
        addr = contract_address or os.getenv("CONTRACT_ADDRESS") or ""
        if not addr:
            addr = _load_address_from_json(address_json_path) 
            checksum_addr = Web3.to_checksum_address(addr)

            # Bind contract
            contract = w3.eth.contract(address=checksum_addr, abi=abi)

            return Web3Client(w3=w3, chain_id=chain_id, account=account, contract=contract)
        
    # Transaction helpers
    def _base_tx(self) -> Dict[str, Any]:
        """
        Build a base transaction dict with chainId/from/none and reasonable fee fields.
        Uses EIP-1559 when supported; otherwise falls back to legacy gasPrice.
        """
        nonce = self.w3.eth.get_transaction_count(self.account.address)
        tx: Dict[str, Any] = {
            "chainid": self.chain_id,
            "from": self.account.address,
            "nonce": nonce,
        }
        # Prefer EIP-1559 if the node reports a base fee
        try:
            latest = self.w3.eth.get_block("latest")
            if "baseFeePerGas" in latest and latest["baseFeePerGas"] is not None:
                # Small priority fee, adjust if provider/network needs higher
                tx["maxPriorityFeePerGas"] = self.w3.to_wei(2, "gwei")
                tx["maxFeePerGas"] = int(latest["baseFeePerGas"]) + self.w3.to_wei(3, "gwei")
            else:
                tx["gasPrice"] = self.w3.eth.gas_price
        except Exception:
            # As a last resort, try legacy gasPrice
            tx["gasPrice"] = self.w3.eth.gas_price
        return tx
    
    def send_fn_tx(self, fn) -> str:
        """
        Sign and broadcast a transaction for a given contract function
        E.g.:
            fn = self.contract.functions.register(doc_hash, subject, uri_hint)
            tx_hash = client.send_fn_tx(fn)
            receipt = client.wait(tx_hash)
        """
        tx = fn.build_transaction(self._base_tx())

        # Attempt gas estimation with a safety cap
        try:
            estimated = self.w3.eth.estimate_gas(tx)
            tx["gas"] = min(int(estimated*1.2), 2_000_000) # 20% headroom, capped at 2mil
        except Exception:
            tx["gas"] = 500_000 # Conservative fallback

        signed = self.account.sign_transaction(tx)
        raw = signed.rawTransaction
        tx_hash = self.w3.eth.send_raw_transaction(raw)
        return tx_hash.hex()
    
    def wait(self, tx_hash: str, timeout: int=180):
        """
        Wait for a receipt (raises on timeout)
        """
        return self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout, poll_latency=1.0)
    
    # Read-only helpers (optional, for QOL)
    def call_is_registered(self, doc_hash: bytes) -> bool:
        """
        Convenience wrapper for contract.isRegistered(bytes32)
        """
        return bool(self.contract.functions.isRegistered(doc_hash).call())
    
    def call_get_record(self, doc_hash: bytes) -> Dict[str, Any]:
        """
        Returns the Record struct as a python dict:
            {"issuer": str, "subject": str, "issuedAt": int, "revoked": bool}
        """
        r = self.contract.functions.get(doc_hash).call()
        return{
            "issuer": r[0],
            "subject": r[1],
            "issuedAt": int(r[2]),
            "revoked": bool(r[3])
        }
    
# Internal helpers
def _load_abi(abi_path: str):
    """
    Loads the ABI. Accepts either:
        - a file containing the ABI array
        - a full Hardhat artifact JSON
    """
    p = Path(abi_path)
    if not p.exists():
        raise RuntimeError(f"ABI file not found at {abi_path}, did you run 'npx hardhat compile' and/or write artifacts?")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise RuntimeError(f"ABI file at {abi_path} is not valid JSON") from e
    
    # If file is a dict with "abi", use that; otherwise assume it's ABI array itself
    if isinstance(data, dict) and "abi" in data:
        return data["abi"]
    if isinstance(data, list):
        return data
    raise RuntimeError(f"ABI at {abi_path} did not look like an ABI array or a Hardhat artifact with 'abi' key")

def _load_address_from_json(address_json_path: str) -> str:
    """
    Reads artifacts/contract_address.json written by deploy script
    Expects: {"address": "0x...", "chainId": 11155111}
    """
    p = Path(address_json_path)
    if not p.exists():
        raise RuntimeError(
            f"Contract address not provided and {address_json_path} not found.\n"
            f"Set CONTRACT_ADRESS in .env or create {address_json_path} with {{\"address\":\"0x...\"}}."
        )
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise RuntimeError(f"{address_json_path} is not valid JSON") from e
    
    addr = data.get("address", "")
    if not addr:
        raise RuntimeError(f"{address_json_path} missing 'address' field")
    return addr