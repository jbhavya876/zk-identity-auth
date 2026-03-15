// Generates input.json for the RegistrationAuth(20) circuit.
// Simulates the user as leaf 0 in an empty 20-level Poseidon Merkle tree.
const { buildPoseidon } = require("circomlibjs");
const fs = require("fs");

async function run() {
    const poseidon = await buildPoseidon();

    // DEVELOPMENT ONLY — use securely random BigInts in production
    const nullifier = 12345n;
    const trapdoor  = 67890n;

    // commitment = Poseidon(nullifier, trapdoor) — this becomes the Merkle leaf
    const commitmentF = poseidon([nullifier, trapdoor]);

    // Build Merkle path for leaf at index 0; all siblings are Poseidon(0) (empty subtrees)
    let pathElements = [];
    let pathIndices  = [];
    let currentLevelHash = commitmentF;
    const zeroHash = poseidon.F.e(0);

    for (let i = 0; i < 20; i++) {
        pathElements.push(poseidon.F.toObject(zeroHash).toString());
        pathIndices.push(0); // 0 = left child at every level
        currentLevelHash = poseidon([currentLevelHash, zeroHash]);
    }

    const root = poseidon.F.toObject(currentLevelHash);

    // Write circuit input as decimal strings (required by snarkjs witness generator)
    const input = {
        root:         root.toString(),
        nullifier:    nullifier.toString(),
        trapdoor:     trapdoor.toString(),
        pathElements: pathElements,
        pathIndices:  pathIndices
    };

    fs.writeFileSync("input.json", JSON.stringify(input, null, 2));
    console.log("input.json generated successfully!");
    console.log("Expected Root:", root.toString());
}

run();