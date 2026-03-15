import { expect } from "chai";
import hre from "hardhat";
import fs from "fs";

const { ethers } = hre;

describe("ZkRegistration On-Chain Verification", function () {
    it("Should verify the proof and authenticate the user", async function () {
        // 1. Read our generated cryptographic files
        const proof = JSON.parse(fs.readFileSync("proof.json", "utf8"));
        const publicSignals = JSON.parse(fs.readFileSync("public.json", "utf8"));
        
        const nullifierHash = publicSignals[0];
        const merkleRoot = publicSignals[1];

        // 2. Deploy the snarkjs Verifier contract
        const Verifier = await ethers.getContractFactory("Groth16Verifier");
        const verifier = await Verifier.deploy();
        await verifier.waitForDeployment();

        // 3. Deploy our Custom Registration contract
        const Registration = await ethers.getContractFactory("ZkRegistration");
        const registration = await Registration.deploy(verifier.target, merkleRoot);
        await registration.waitForDeployment();

        // 4. Format the Proof for Solidity
        const pA = [proof.pi_a[0], proof.pi_a[1]];
        // EVM requires the elements of the B arrays to be reversed!
        const pB = [
            [proof.pi_b[0][1], proof.pi_b[0][0]], 
            [proof.pi_b[1][1], proof.pi_b[1][0]]
        ];
        const pC = [proof.pi_c[0], proof.pi_c[1]];

        // 5. Execute the on-chain authentication
        console.log("Submitting proof to local EVM...");
        
        const authTx = await registration.authenticate(
            pA, 
            pB, 
            pC, 
            nullifierHash, 
            merkleRoot
        );
        
        await authTx.wait();

        // 6. Assertions
        const isUsed = await registration.usedNullifiers(nullifierHash);
        expect(isUsed).to.be.true;

        console.log("Proof Verified! Nullifier marked as spent to prevent replay attacks.");

        // 7. Test Replay Attack Prevention
        await expect(
            registration.authenticate(pA, pB, pC, nullifierHash, merkleRoot)
        ).to.be.revertedWith("Proof already used!");
        
        console.log("Replay attack successfully blocked.");
    });
});