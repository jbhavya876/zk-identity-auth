pragma circom 2.1.5;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/switcher.circom";

// 1. Your previous Identity logic
template Identity() {
    signal input nullifier;
    signal input trapdoor;
    signal output commitment;
    signal output nullifierHash;

    component commitmentHasher = Poseidon(2);
    commitmentHasher.inputs[0] <== nullifier;
    commitmentHasher.inputs[1] <== trapdoor;
    commitment <== commitmentHasher.out;

    component nullifierHasher = Poseidon(1);
    nullifierHasher.inputs[0] <== nullifier;
    nullifierHash <== nullifierHasher.out;
}

// 2. The new Merkle Tree logic
template MerkleTreeChecker(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels]; // 0 for left, 1 for right
    signal output root;

    component hashers[levels];
    component switchers[levels];

    signal currentHash[levels + 1];
    currentHash[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        switchers[i] = Switcher();
        switchers[i].L <== currentHash[i];
        switchers[i].R <== pathElements[i];
        switchers[i].sel <== pathIndices[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== switchers[i].outL;
        hashers[i].inputs[1] <== switchers[i].outR;

        currentHash[i + 1] <== hashers[i].out;
    }

    root <== currentHash[levels];
}

// 3. The Master Template tying it all together
template RegistrationAuth(levels) {
    // Public Inputs (What the smart contract knows)
    signal input root;

    // Private Inputs (What ONLY the user knows)
    signal input nullifier;
    signal input trapdoor;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    // Public Outputs
    signal output nullifierHash;

    // Get the commitment and nullifier hash
    component id = Identity();
    id.nullifier <== nullifier;
    id.trapdoor <== trapdoor;
    nullifierHash <== id.nullifierHash;

    // Check if the commitment is in the tree
    component merkle = MerkleTreeChecker(levels);
    merkle.leaf <== id.commitment;
    for (var i = 0; i < levels; i++) {
        merkle.pathElements[i] <== pathElements[i];
        merkle.pathIndices[i] <== pathIndices[i];
    }

    // THE MOST IMPORTANT LINE: 
    // Constrain the mathematically calculated root to exactly match the public input root.
    // If they don't match, the proof fails entirely.
    root === merkle.root; 
}

// Instantiate with a tree of 20 levels (Capacity for ~1 million users)
// We explicitly declare 'root' as a public input. Outputs are public by default.
component main {public [root]} = RegistrationAuth(20);