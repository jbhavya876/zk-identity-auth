# ZK Registration System

A **privacy-preserving identity and authentication protocol** built on Ethereum using **zk-SNARKs (Groth16)**. Users can prove they are registered members of a group without revealing *who* they are, using a Poseidon-hashed commitment stored in a Merkle tree.

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Usage](#usage)
  - [1. Compile the Circuit](#1-compile-the-circuit)
  - [2. Trusted Setup (Powers of Tau)](#2-trusted-setup-powers-of-tau)
  - [3. Generate Witness & Proof](#3-generate-witness--proof)
  - [4. Deploy & Test Contracts](#4-deploy--test-contracts)
  - [5. Run the Frontend](#5-run-the-frontend)
- [Key Concepts](#key-concepts)
- [Security Considerations](#security-considerations)
- [Future Improvements](#future-improvements)

---

## Overview

This project demonstrates a complete ZK-based user registration and authentication flow:

1. A user generates a secret identity (nullifier + trapdoor).
2. Their **commitment** (a Poseidon hash of the secrets) is inserted into an on-chain Merkle tree.
3. To authenticate, the user generates a **Groth16 zk-SNARK proof** entirely in-browser, proving they know the secrets behind a commitment in the tree — **without revealing the commitment or secrets**.
4. The smart contract verifies the proof on-chain and prevents replay attacks using a **nullifier hash**.

---

## How It Works

```
User (Browser / CLI)
│
│  1. User enters a secret PIN
│
▼
Derive:  nullifier = secret × 123
         trapdoor  = secret × 456
│
│  (Secrets NEVER leave the client)
▼
commitment = Poseidon(nullifier, trapdoor)
│
│  2. Build Merkle proof path (simulated / fetched from indexer)
▼
Circom Circuit: RegistrationAuth(levels=20)
  ├── Identity template   → verifies commitment derivation
  └── MerkleTreeChecker   → proves commitment is in the tree
│
│  3. snarkjs.groth16.fullProve() — runs WASM witness gen + Groth16
▼
Groth16 Proof  { pA, pB, pC }
Public signals { nullifierHash, merkleRoot }
│
│  4. Submit to smart contract
▼
ZkRegistration.authenticate(pA, pB, pC, nullifierHash, merkleRoot)
  ├── Check merkleRoot == currentRoot
  ├── Check nullifierHash not already spent
  ├── Groth16Verifier.verifyProof() → on-chain pairing check
  └── Mark nullifierHash as spent  ✅ Access granted
```

---

## Architecture

```
zkp-registration/
│
├── circuits/                 ← Circom ZK circuits
│   ├── identity.circom       ← Standalone identity circuit (commitment + nullifier hash)
│   └── registration.circom   ← Full auth circuit (identity + Merkle proof)
│
├── contracts/                ← Solidity smart contracts
│   ├── Verifier.sol          ← Auto-generated Groth16 verifier (snarkjs export)
│   └── Registration.sol      ← Business logic: root management, auth, replay protection
│
├── frontend/                 ← Vite + React client-side prover UI
│   └── src/
│       ├── main.jsx          ← React entry point
│       └── App.jsx           ← ZK proof generation UI
│
├── test/
│   └── registration.test.js  ← Hardhat integration test (proof → on-chain verification)
│
├── generate_input.js         ← CLI: generate input.json for witness computation
├── client_prover.js          ← CLI: generate proof off-chain (Node.js / ESM)
├── hardhat.config.js         ← Hardhat configuration
└── package.json              ← Root package (snarkjs, circomlib, hardhat)
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| ZK Circuit | [Circom 2.1.5](https://docs.circom.io/) |
| ZK Proving | [snarkjs](https://github.com/iden3/snarkjs) (Groth16) |
| Hash Function | [Poseidon](https://eprint.iacr.org/2019/458.pdf) (ZK-friendly) |
| Smart Contracts | Solidity 0.8.20 |
| Contract Dev | [Hardhat](https://hardhat.org/) |
| Frontend | [Vite](https://vitejs.dev/) + [React 19](https://react.dev/) |
| Frontend ZK | snarkjs (browser WASM) |

---

## Prerequisites

- **Node.js** ≥ 18
- **npm** ≥ 9
- **Circom** compiler (`circom` CLI) — [Install guide](https://docs.circom.io/getting-started/installation/)
- **snarkjs** (installed automatically via npm)

---

## Setup

```bash
# Clone the repository
git clone <repo-url>
cd zkp-registration

# Install root dependencies (circomlib, snarkjs, hardhat)
npm install

# Install frontend dependencies
cd frontend && npm install && cd ..
```

---

## Usage

### 1. Compile the Circuit

```bash
# Compiles registration.circom → WASM witness generator + R1CS constraint system
circom circuits/registration.circom \
  --r1cs --wasm --sym \
  -o build/
```

This produces:
- `build/registration.r1cs` — constraint system
- `build/registration_js/registration.wasm` — witness generator (used in browser and CLI)

---

### 2. Trusted Setup (Powers of Tau)

The `.ptau` and `.zkey` files are pre-committed in the repo for development. **For production**, run a proper ceremony:

```bash
# Phase 1: Universal SRS (already committed as pot14_final.ptau)
snarkjs powersoftau new bn128 14 pot14_0000.ptau
snarkjs powersoftau contribute pot14_0000.ptau pot14_0001.ptau --name="Contributor 1"
snarkjs powersoftau prepare phase2 pot14_0001.ptau pot14_final.ptau

# Phase 2: Circuit-specific setup
snarkjs groth16 setup build/registration.r1cs pot14_final.ptau registration_0000.zkey
snarkjs zkey contribute registration_0000.zkey registration_final.zkey --name="Contributor 1"
snarkjs zkey export verificationkey registration_final.zkey verification_key.json

# Export the Solidity verifier
snarkjs zkey export solidityverifier registration_final.zkey contracts/Verifier.sol
```

---

### 3. Generate Witness & Proof

```bash
# Step A: Generate the circuit input JSON
node generate_input.js
# → writes input.json

# Step B: Compute witness
node build/registration_js/generate_witness.js \
  build/registration_js/registration.wasm \
  input.json witness.wtns

# Step C: Generate Groth16 proof
snarkjs groth16 prove registration_final.zkey witness.wtns proof.json public.json

# Step D: Verify proof off-chain
snarkjs groth16 verify verification_key.json public.json proof.json

# Step E (optional): Generate proof entirely in Node.js
node client_prover.js
```

---

### 4. Deploy & Test Contracts

```bash
# Run the Hardhat integration test (deploys contracts + submits proof)
npx hardhat test
```

The test in `test/registration.test.js`:
1. Reads `proof.json` and `public.json` generated in step 3.
2. Deploys `Groth16Verifier` and `ZkRegistration` to the local Hardhat network.
3. Calls `authenticate()` with the proof and asserts it succeeds.
4. Attempts a replay attack and asserts it is rejected.

---

### 5. Run the Frontend

The frontend lets users generate a ZK proof in-browser by entering a secret PIN.

**Required**: Copy the WASM and zkey files to the frontend's `public/` directory first:

```bash
cp build/registration_js/registration.wasm frontend/public/
cp registration_final.zkey frontend/public/
```

Then start the dev server:

```bash
cd frontend
npm run dev
# → http://localhost:5173
```

The UI:
1. Accepts a numeric secret PIN.
2. Derives `nullifier` and `trapdoor` from it.
3. Builds the Merkle path locally (simulated empty tree in dev).
4. Generates a Groth16 proof using the WASM circuit in-browser.
5. Displays the nullifier hash, Merkle root, and full proof JSON.

---

## Key Concepts

### Commitment
```
commitment = Poseidon(nullifier, trapdoor)
```
A one-way binding to the user's identity. Safe to store publicly on-chain.

### Nullifier Hash
```
nullifierHash = Poseidon(nullifier)
```
Revealed publicly during authentication. Prevents the same identity from authenticating twice (**replay protection**) without revealing *which* commitment was used.

### Merkle Proof
A path from the commitment (leaf) to the Merkle root, proving membership without revealing which leaf. The Circom `MerkleTreeChecker` template recursively hashes path elements using Poseidon.

### Groth16 (zk-SNARK)
A succinct, non-interactive proof system. Produces a small constant-size proof (~200 bytes) regardless of circuit complexity. Requires a circuit-specific trusted setup.

---

## Security Considerations

| Risk | Mitigation |
|---|---|
| Replay attacks | `usedNullifiers` mapping prevents proof reuse |
| Merkle root staleness | `authenticate()` enforces `_merkleRoot == currentRoot` |
| Weak KDF in frontend | Demo only — use a proper KDF (e.g., PBKDF2, Argon2) in production |
| Trusted setup | Use a multi-party ceremony for production `zkey` |
| Centralised root update | `updateRoot()` is unrestricted — add access control in production |
| Secret exposure | Secrets never leave the client; only `nullifierHash` and `root` are public |

---

## Future Improvements

- **Incremental Merkle Trees**: Gas-efficient on-chain insertion using a Solidity Poseidon library.
- **MPC Trusted Setup**: Phase 2 ceremony with multiple independent contributors.
- **Relayer Infrastructure**: Gasless authentication by submitting proofs through a relayer.
- **Indexer Integration**: Fetch live Merkle tree state from an on-chain indexer rather than simulating.
- **Proper KDF**: Replace the linear secret derivation in the frontend with Argon2id or PBKDF2.
- **Access Control on `updateRoot`**: Restrict root updates to an authorised operator or on-chain Merkle logic contract.
