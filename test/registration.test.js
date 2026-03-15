import { expect } from "chai";
import hre from "hardhat";
import fs from "fs";

const { ethers } = hre;

// Integration test: deploys both contracts, submits a real Groth16 proof, and checks replay protection.
// Requires proof.json and public.json to be generated first (see README).
describe("ZkRegistration On-Chain Verification", function () {
    it("Should verify the proof and authenticate the user", async function () {
        // Read the pre-generated proof and public signals from disk
        const proof = JSON.parse(fs.readFileSync("proof.json", "utf8"));
        const publicSignals = JSON.parse(fs.readFileSync("public.json", "utf8"));

        const nullifierHash = publicSignals[0];
        const merkleRoot    = publicSignals[1];

        // Deploy the snarkjs-generated Groth16 verifier (BN254 pairing checks)
        const Verifier  = await ethers.getContractFactory("Groth16Verifier");
        const verifier  = await Verifier.deploy();
        await verifier.waitForDeployment();

        // Deploy our registration contract, initialised with the proof's Merkle root
        const Registration = await ethers.getContractFactory("ZkRegistration");
        const registration = await Registration.deploy(verifier.target, merkleRoot);
        await registration.waitForDeployment();

        // Format proof: pA and pC are straightforward; pB sub-arrays must be reversed for the EVM ABI
        const pA = [proof.pi_a[0], proof.pi_a[1]];
        const pB = [
            [proof.pi_b[0][1], proof.pi_b[0][0]],
            [proof.pi_b[1][1], proof.pi_b[1][0]]
        ];
        const pC = [proof.pi_c[0], proof.pi_c[1]];

        console.log("Submitting proof to local EVM...");
        const authTx = await registration.authenticate(pA, pB, pC, nullifierHash, merkleRoot);
        await authTx.wait();

        // Assert the nullifier was marked as spent after successful authentication
        const isUsed = await registration.usedNullifiers(nullifierHash);
        expect(isUsed).to.be.true;
        console.log("Proof Verified! Nullifier marked as spent to prevent replay attacks.");

        // Re-submitting the same proof must revert — confirming replay protection works
        await expect(
            registration.authenticate(pA, pB, pC, nullifierHash, merkleRoot)
        ).to.be.revertedWith("Proof already used!");
        console.log("Replay attack successfully blocked.");
    });
});