pragma circom 2.1.5;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/switcher.circom";

// Derives commitment and nullifierHash from the user's secret nullifier + trapdoor.
template Identity() {
    signal input nullifier;
    signal input trapdoor;
    signal output commitment;
    signal output nullifierHash;

    // commitment = Poseidon(nullifier, trapdoor) — the public Merkle leaf
    component commitmentHasher = Poseidon(2);
    commitmentHasher.inputs[0] <== nullifier;
    commitmentHasher.inputs[1] <== trapdoor;
    commitment <== commitmentHasher.out;

    // nullifierHash = Poseidon(nullifier) — revealed on-chain to prevent replay attacks
    component nullifierHasher = Poseidon(1);
    nullifierHasher.inputs[0] <== nullifier;
    nullifierHash <== nullifierHasher.out;
}

// Verifies a Merkle inclusion proof: proves `leaf` is a member of the tree with the given `root`.
template MerkleTreeChecker(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels]; // 0 = left child, 1 = right child

    signal output root;

    component hashers[levels];
    component switchers[levels];

    signal currentHash[levels + 1];
    currentHash[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        // Switcher orders (current, sibling) correctly based on the path direction
        switchers[i] = Switcher();
        switchers[i].L <== currentHash[i];
        switchers[i].R <== pathElements[i];
        switchers[i].sel <== pathIndices[i];

        // Hash the ordered pair to move one level up the tree
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== switchers[i].outL;
        hashers[i].inputs[1] <== switchers[i].outR;

        currentHash[i + 1] <== hashers[i].out;
    }

    root <== currentHash[levels];
}

// Master authentication circuit: proves the prover knows secrets behind a commitment in the Merkle tree.
template RegistrationAuth(levels) {
    // Public: the current on-chain Merkle root the proof targets
    signal input root;

    // Private: user's secrets — never revealed to the verifier
    signal input nullifier;
    signal input trapdoor;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    // Public output: used on-chain as a one-time spending tag (replay protection)
    signal output nullifierHash;

    // Derive commitment = Poseidon(nullifier, trapdoor) and nullifierHash = Poseidon(nullifier)
    component id = Identity();
    id.nullifier <== nullifier;
    id.trapdoor <== trapdoor;
    nullifierHash <== id.nullifierHash;

    // Verify the commitment is a valid leaf in the Merkle tree
    component merkle = MerkleTreeChecker(levels);
    merkle.leaf <== id.commitment;
    for (var i = 0; i < levels; i++) {
        merkle.pathElements[i] <== pathElements[i];
        merkle.pathIndices[i] <== pathIndices[i];
    }

    // Critical constraint: computed root must match the public input root or the proof fails
    root === merkle.root;
}

// Instantiate with depth 20 (supports ~1M users); root is explicitly declared public
component main {public [root]} = RegistrationAuth(20);