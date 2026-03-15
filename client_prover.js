import * as snarkjs from "snarkjs";
import { buildPoseidon } from "circomlibjs";

async function generateClientProof() {
    console.log("1. Initializing Cryptography (Poseidon Hash)...");
    const poseidon = await buildPoseidon();

    // 1. The User's Secrets (These stay on the device!)
    const nullifier = 12345n;
    const trapdoor = 67890n;

    // Calculate the user's commitment
    const commitment = poseidon([nullifier, trapdoor]);

    console.log("2. Fetching Merkle Tree State...");
    // 2. Reconstruct the Merkle Tree path locally
    // In a real dApp, you would fetch the leaves from the blockchain or an indexer.
    // Here, we simulate the same empty 20-level tree we used in testing.
    let pathElements = [];
    let pathIndices = [];
    let currentLevelHash = commitment;
    const zeroHash = poseidon.F.e(0);

    for (let i = 0; i < 20; i++) {
        pathElements.push(poseidon.F.toObject(zeroHash).toString());
        pathIndices.push(0);
        currentLevelHash = poseidon([currentLevelHash, zeroHash]);
    }

    const root = poseidon.F.toObject(currentLevelHash).toString();

    const input = {
        root: root,
        nullifier: nullifier.toString(),
        trapdoor: trapdoor.toString(),
        pathElements: pathElements,
        pathIndices: pathIndices
    };

    console.log("3. Generating Zero-Knowledge Proof Dynamically...");
    // 3. Point to the WASM and ZKEY files hosted on your "frontend"
    const wasmPath = "./build/registration_js/registration.wasm";
    const zkeyPath = "./registration_final.zkey";

    // This single function calculates the witness AND generates the proof
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);

    console.log("4. Formatting Proof for EVM Calldata...");
    // 4. Format the output so Ethers.js can send it straight to Solidity
    const pA = [proof.pi_a[0], proof.pi_a[1]];
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

// Execute the function
generateClientProof()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });