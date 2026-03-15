pragma circom 2.1.5;

// Poseidon is a ZK-friendly hash function with far fewer constraints than SHA-256
include "../node_modules/circomlib/circuits/poseidon.circom";

// Standalone identity circuit — also embedded as a template inside registration.circom
template Identity() {
    // Private inputs: the user's secrets, never revealed
    signal input nullifier;
    signal input trapdoor;

    // Public outputs: commitment is the Merkle leaf; nullifierHash is the replay-attack tag
    signal output commitment;
    signal output nullifierHash;

    // commitment = Poseidon(nullifier, trapdoor)
    component commitmentHasher = Poseidon(2);
    commitmentHasher.inputs[0] <== nullifier;
    commitmentHasher.inputs[1] <== trapdoor;
    commitment <== commitmentHasher.out;

    // nullifierHash = Poseidon(nullifier) — revealed on auth to mark the proof as spent
    component nullifierHasher = Poseidon(1);
    nullifierHasher.inputs[0] <== nullifier;
    nullifierHash <== nullifierHasher.out;
}

// Standalone instantiation for compiling/testing this circuit independently
component main = Identity();