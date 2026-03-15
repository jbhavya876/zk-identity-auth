// CLI script that generates a Groth16 ZK proof entirely in Node.js (no browser).
// Simulates the user as leaf 0 in an empty 20-level Poseidon Merkle tree,
// then formats the proof for direct submission to the ZkRegistration smart contract.
import * as snarkjs from "snarkjs";
import { buildPoseidon } from "circomlibjs";

async function generateClientProof() {
    console.log("1. Initializing Cryptography (Poseidon Hash)...");
    const poseidon = await buildPoseidon();

    // DEVELOPMENT ONLY — use securely random BigInts in production
    const nullifier = 12345n;
    const trapdoor  = 67890n;

    // commitment = Poseidon(nullifier, trapdoor) — the Merkle leaf
    const commitment = poseidon([nullifier, trapdoor]);

    console.log("2. Fetching Merkle Tree State...");
    // Simulate an empty 20-level tree; in production, fetch real path from an indexer
    let pathElements = [];
    let pathIndices  = [];
    let currentLevelHash = commitment;
    const zeroHash = poseidon.F.e(0);

    for (let i = 0; i < 20; i++) {
        pathElements.push(poseidon.F.toObject(zeroHash).toString());
        pathIndices.push(0);
        currentLevelHash = poseidon([currentLevelHash, zeroHash]);
    }

    const root = poseidon.F.toObject(currentLevelHash).toString();

    const input = {
        root,
        nullifier: nullifier.toString(),
        trapdoor:  trapdoor.toString(),
        pathElements,
        pathIndices
    };

    console.log("3. Generating Zero-Knowledge Proof Dynamically...");
    const wasmPath = "./build/registration_js/registration.wasm";
    const zkeyPath = "./registration_final.zkey";

    // fullProve computes the witness and generates the Groth16 proof in one call
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);

    console.log("4. Formatting Proof for EVM Calldata...");
    const pA = [proof.pi_a[0], proof.pi_a[1]];
    // EVM requires G2 point sub-arrays to be reversed compared to snarkjs output
    const pB = [
        [proof.pi_b[0][1], proof.pi_b[0][0]],
        [proof.pi_b[1][1], proof.pi_b[1][0]]
    ];
    const pC = [proof.pi_c[0], proof.pi_c[1]];

    console.log("\n✅ SUCCESS: Client-Side Proof Generated!");
    console.log("--------------------------------------------------");
    console.log("Nullifier Hash (Public):", publicSignals[0]);
    console.log("Merkle Root (Public):   ", publicSignals[1]);
    console.log("--------------------------------------------------");
    console.log("Ready to submit `pA`, `pB`, and `pC` to the smart contract!");

    return { pA, pB, pC, publicSignals };
}

generateClientProof()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });