pragma circom 2.1.5;

// Import the Poseidon hash template from circomlib
include "../node_modules/circomlib/circuits/poseidon.circom";

template Identity() {
    // 1. Private Inputs (The User's Secrets)
    signal input nullifier;
    signal input trapdoor;

    // 2. Public Outputs
    signal output commitment;
    signal output nullifierHash;

    // 3. Generate the Commitment: Poseidon(nullifier, trapdoor)
    component commitmentHasher = Poseidon(2);
    commitmentHasher.inputs[0] <== nullifier;
    commitmentHasher.inputs[1] <== trapdoor;
    commitment <== commitmentHasher.out;

    // 4. Generate the Nullifier Hash: Poseidon(nullifier)
    // This will be exposed publicly when authenticating to prove the user
    // owns the commitment without revealing the commitment itself.
    component nullifierHasher = Poseidon(1);
    nullifierHasher.inputs[0] <== nullifier;
    nullifierHash <== nullifierHasher.out;
}

// Instantiate the component so we can compile it
component main = Identity();