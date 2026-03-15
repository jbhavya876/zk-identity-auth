// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Interface to interact with the automatically generated snarkjs Verifier
interface IVerifier {
    function verifyProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[2] calldata _pubSignals
    ) external view returns (bool);
}

contract ZkRegistration {
    IVerifier public verifier;
    
    // The current valid state of the Merkle Tree
    uint256 public currentRoot;
    
    // Anti-replay mechanism: Track which proofs have already been used
    mapping(uint256 => bool) public usedNullifiers;

    event UserRegistered(uint256 commitment);
    event UserAuthenticated(uint256 nullifierHash);

    constructor(address _verifierAddress, uint256 _initialRoot) {
        verifier = IVerifier(_verifierAddress);
        currentRoot = _initialRoot;
    }

    // In a full production app, you calculate the new Merkle root on-chain here 
    // using a Poseidon smart contract, or off-chain via a relayer. 
    // For this module, we will allow updating the root directly to test the ZK verification.
    function updateRoot(uint256 _newRoot) external {
        currentRoot = _newRoot;
    }

    // The core authentication function
    function authenticate(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint256 _nullifierHash,
        uint256 _merkleRoot
    ) external {
        // 1. Check that the user is proving against the correct tree state
        require(_merkleRoot == currentRoot, "Invalid Merkle Root");
        
        // 2. Prevent replay attacks (Nullifier check)
        require(!usedNullifiers[_nullifierHash], "Proof already used!");

        // 3. Assemble the public signals array. 
        // IMPORTANT: We must match the exact order outputted by Circom.
        uint[2] memory pubSignals = [_nullifierHash, _merkleRoot];

        // 4. Verify the Groth16 proof using the snarkjs contract
        require(
            verifier.verifyProof(_pA, _pB, _pC, pubSignals),
            "Invalid Zero Knowledge Proof"
        );

        // 5. Mark the nullifier as spent so this exact proof can never be used again
        usedNullifiers[_nullifierHash] = true;
        
        emit UserAuthenticated(_nullifierHash);
    }
}