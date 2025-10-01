# scripts/deploy_contract.py
# Deploys DocumentVerification to the chain in .env, then writes:
#  - artifacts/DocumentVerification.abi.json
#  - artifacts/contract_address.json
#
# Env required:
#   RPC_URL, CHAIN_ID, PRIVATE_KEY
#
# Reads ABI/bytecode from:
#   artifacts/contracts/DocumentVerification.sol/DocumentVerification.json
#
# Usage:
#   python scripts/deploy_contract.py
#   python scripts/deploy_contract.py --grant 0xIssuer1 --grant 0xIssuer2

import json, os, sys
from pathlib import Path
from typing import List
from dotenv import load_dotenv
from web3 import Web3
from eth_account import Account

HARDHAT_ARTIFACT = "artifacts/contracts/DocumentVerification.sol/DocumentVerification.json"
ABI_OUT = "artifacts/DocumentVerification.abi.json"
ADDR_OUT = "artifacts/contract_address.json"
ISSUER_ROLE = Web3.keccak(text="ISSUER_ROLE")  # must match contract

def load_env():
    load_dotenv()
    rpc = os.getenv("RPC_URL") or os.getenv("SEPOLIA_RPC_URL") or ""
    cid = os.getenv("CHAIN_ID") or ""
    pk  = os.getenv("PRIVATE_KEY") or os.getenv("SEPOLIA_PRIVATE_KEY") or ""
    if not rpc: sys.exit("Missing RPC_URL in .env")
    try:
        chain_id = int(cid)
    except Exception:
        sys.exit("CHAIN_ID must be an integer (e.g., 11155111 for Sepolia, 31337 for Hardhat)")
    if not (pk.startswith("0x") and len(pk) >= 66):
        sys.exit("PRIVATE_KEY missing/invalid (0x + 64 hex)")
    return rpc, chain_id, pk

def read_hardhat_artifact():
    p = Path(HARDHAT_ARTIFACT)
    if not p.exists():
        sys.exit(f"Artifact not found at {HARDHAT_ARTIFACT}. Run `npx hardhat compile` first.")
    data = json.loads(p.read_text(encoding="utf-8"))
    abi = data.get("abi")
    bytecode = data.get("bytecode")
    if not abi or not bytecode:
        sys.exit("Artifact missing abi/bytecode")
    return abi, bytecode

def write_outputs(abi, address, chain_id):
    Path("artifacts").mkdir(exist_ok=True)
    Path(ABI_OUT).write_text(json.dumps(abi, indent=2), encoding="utf-8")
    Path(ADDR_OUT).write_text(json.dumps({"address": address, "chainId": chain_id}, indent=2), encoding="utf-8")
    print(f"✔ Wrote {ABI_OUT}")
    print(f"✔ Wrote {ADDR_OUT}")

def grant_issuers(w3: Web3, contract, admin_acct: Account, chain_id: int, issuers: List[str]):
    if not issuers: return
    nonce = w3.eth.get_transaction_count(admin_acct.address)
    for addr in issuers:
        addr = Web3.to_checksum_address(addr)
        tx = contract.functions.grantRole(ISSUER_ROLE, addr).build_transaction({
            "chainId": chain_id,
            "from": admin_acct.address,
            "nonce": nonce,
        })
        nonce += 1
        # EIP-1559 if available
        latest = w3.eth.get_block("latest")
        if "baseFeePerGas" in latest and latest["baseFeePerGas"] is not None:
            tx["maxPriorityFeePerGas"] = w3.to_wei(2, "gwei")
            tx["maxFeePerGas"] = int(latest["baseFeePerGas"]) + w3.to_wei(3, "gwei")
        else:
            tx["gasPrice"] = w3.eth.gas_price
        try:
            tx["gas"] = min(300_000, w3.eth.estimate_gas(tx))
        except Exception:
            tx["gas"] = 300_000
        signed = admin_acct.sign_transaction(tx)
        h = w3.eth.send_raw_transaction(signed.raw_transaction)
        r = w3.eth.wait_for_transaction_receipt(h)
        print(f"Granted ISSUER_ROLE to {addr} in {h.hex()} (status={r.status})")

def main():
    # parse simple --grant flags
    issuers: List[str] = []
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--grant" and i + 1 < len(args):
            issuers.append(args[i+1]); i += 2
        else:
            print("Usage: python scripts/deploy_contract.py [--grant 0xAddress] ...")
            sys.exit(1)

    rpc, chain_id, pk = load_env()
    abi, bytecode = read_hardhat_artifact()
    w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 30}))
    if not w3.is_connected():
        sys.exit(f"Failed to connect to {rpc}")

    admin = Account.from_key(pk)
    print("Admin:", admin.address)
    print("Chain:", chain_id)

    factory = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx = factory.constructor(admin.address).build_transaction({
        "chainId": chain_id,
        "from": admin.address,
        "nonce": w3.eth.get_transaction_count(admin.address),
    })
    latest = w3.eth.get_block("latest")
    if "baseFeePerGas" in latest and latest["baseFeePerGas"] is not None:
        tx["maxPriorityFeePerGas"] = w3.to_wei(2, "gwei")
        tx["maxFeePerGas"] = int(latest["baseFeePerGas"]) + w3.to_wei(3, "gwei")
    else:
        tx["gasPrice"] = w3.eth.gas_price
    try:
        tx["gas"] = min(3_000_000, w3.eth.estimate_gas(tx))
    except Exception:
        tx["gas"] = 3_000_000

    signed = admin.sign_transaction(tx)
    h = w3.eth.send_raw_transaction(signed.raw_transaction)
    print("Deploy tx:", h.hex())
    rcpt = w3.eth.wait_for_transaction_receipt(h)
    if rcpt.status != 1:
        sys.exit(f"Deployment failed: {rcpt}")
    address = rcpt.contractAddress
    print("Deployed at:", address)

    contract = w3.eth.contract(address=address, abi=abi)
    grant_issuers(w3, contract, admin, chain_id, issuers)

    write_outputs(abi, address, chain_id)
    print("✅ Done.")

if __name__ == "__main__":
    main()
