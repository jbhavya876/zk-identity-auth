// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal interface for the snarkjs-generated Groth16Verifier contract
interface IVerifier {
    function verifyProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[2] calldata _pubSignals
    ) external view returns (bool);
}

// ZK-SNARK based anonymous authentication — proves Merkle membership without revealing identity
contract ZkRegistration {
    IVerifier public verifier;

    // The Merkle root representing the current registered user set
    uint256 public currentRoot;

    // Tracks spent nullifier hashes to block proof replay attacks
    mapping(uint256 => bool) public usedNullifiers;

    event UserRegistered(uint256 commitment);
    event UserAuthenticated(uint256 nullifierHash);

    constructor(address _verifierAddress, uint256 _initialRoot) {
        verifier = IVerifier(_verifierAddress);
        currentRoot = _initialRoot;
    }

    // Updates the Merkle root after a new commitment is inserted.
    // TODO: Restrict to an authorised operator or use on-chain Merkle insertion in production.
    function updateRoot(uint256 _newRoot) external {
        currentRoot = _newRoot;
    }

    // Authenticates a user by verifying their Groth16 ZK proof on-chain.
    function authenticate(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint256 _nullifierHash,
        uint256 _merkleRoot
    ) external {
        // Reject proofs generated against a stale Merkle root
        require(_merkleRoot == currentRoot, "Invalid Merkle Root");

        // Reject replay: each nullifier can only be spent once
        require(!usedNullifiers[_nullifierHash], "Proof already used!");

        // Order must match Circom's public signal output: [nullifierHash, merkleRoot]
        uint[2] memory pubSignals = [_nullifierHash, _merkleRoot];

        // Delegate cryptographic verification to the snarkjs Groth16 verifier (BN254 pairings)
        require(
            verifier.verifyProof(_pA, _pB, _pC, pubSignals),
            "Invalid Zero Knowledge Proof"
        );

        // Mark nullifier as spent — proof cannot be replayed after this point
        usedNullifiers[_nullifierHash] = true;

        emit UserAuthenticated(_nullifierHash);
    }
}