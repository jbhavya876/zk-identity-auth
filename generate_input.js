const { buildPoseidon } = require("circomlibjs");
const fs = require("fs");

async function run() {
    const poseidon = await buildPoseidon();

    // 1. Generate random secrets (Keep these safe in a real app!)
    const nullifier = 12345n; 
    const trapdoor = 67890n;  

    // 2. Calculate Commitment
    const commitmentF = poseidon([nullifier, trapdoor]);

    // 3. Simulate a 20-level Merkle tree (Index 0, all siblings are 0)
    let pathElements = [];
    let pathIndices = [];
    let currentLevelHash = commitmentF;
    const zeroHash = poseidon.F.e(0);

    for (let i = 0; i < 20; i++) {
        pathElements.push(poseidon.F.toObject(zeroHash).toString());
        pathIndices.push(0); // 0 means sibling is on the right
        
        // Hash current level with the zero sibling
        currentLevelHash = poseidon([currentLevelHash, zeroHash]);
    }

    const root = poseidon.F.toObject(currentLevelHash);

    // 4. Create the input object
    const input = {
        root: root.toString(),
        nullifier: nullifier.toString(),
        trapdoor: trapdoor.toString(),
        pathElements: pathElements,
        pathIndices: pathIndices
    };

    fs.writeFileSync("input.json", JSON.stringify(input, null, 2));
    console.log("input.json generated successfully!");
    console.log("Expected Root:", root.toString());
}

run();