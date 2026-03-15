import { useState } from 'react';
import * as snarkjs from 'snarkjs';
import { buildPoseidon } from 'circomlibjs';

function App() {
  const [secret, setSecret] = useState('');
  const [status, setStatus] = useState('Idle');
  const [proofData, setProofData] = useState(null);

  const generateProof = async () => {
    try {
      setStatus('Initializing Cryptography...');
      const poseidon = await buildPoseidon();

      // 1. Derive secrets from the user's input
      // In a real app, you'd use a robust KDF. Here we split a number.
      const nullifier = BigInt(secret) * 123n; 
      const trapdoor = BigInt(secret) * 456n;

      const commitment = poseidon([nullifier, trapdoor]);

      setStatus('Fetching Merkle Tree State...');
      // 2. Simulate the 20-level Merkle tree
      let pathElements = [];
      let pathIndices = [];
      let currentLevelHash = commitment;
      const zeroHash = poseidon.F.e(0);

      for (let i = 0; i < 20; i++) {
        pathElements.push(poseidon.F.toObject(zeroHash).toString());
        pathIndices.push(0);
        currentLevelHash = poseidon([currentLevelHash, zeroHash]);
      }

      const root = poseidon.F.toObject(currentLevelHash).toString();

      const input = {
        root: root,
        nullifier: nullifier.toString(),
        trapdoor: trapdoor.toString(),
        pathElements: pathElements,
        pathIndices: pathIndices
      };

      setStatus('Generating Zero-Knowledge Proof (This may take a moment)...');
      
      // 3. Download the assets and prove!
      // Notice we use URLs here, not file paths.
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input, 
        "/registration.wasm", 
        "/registration_final.zkey"
      );

      setStatus('Proof Generated Successfully!');
      setProofData({ proof, publicSignals });

    } catch (error) {
      console.error(error);
      setStatus('Error generating proof. Check console.');
    }
  };

  return (
    <div style={{ padding: '40px', fontFamily: 'system-ui', maxWidth: '600px', margin: '0 auto' }}>
      <h1>ZK Registration UI</h1>
      
      <div style={{ marginBottom: '20px' }}>
        <label style={{ display: 'block', marginBottom: '8px' }}>Enter Secret PIN (Numbers only):</label>
        <input 
          type="number" 
          value={secret} 
          onChange={(e) => setSecret(e.target.value)} 
          placeholder="e.g. 12345"
          style={{ padding: '10px', width: '100%', fontSize: '16px' }}
        />
      </div>

      <button 
        onClick={generateProof} 
        disabled={!secret || status.includes('Generating')}
        style={{ padding: '10px 20px', fontSize: '16px', cursor: 'pointer', backgroundColor: '#007bff', color: 'white', border: 'none', borderRadius: '4px' }}
      >
        Authenticate Anonymously
      </button>

      <div style={{ marginTop: '20px', padding: '15px', backgroundColor: '#f4f4f4', borderRadius: '4px' }}>
        <strong>Status:</strong> {status}
      </div>

      {proofData && (
        <div style={{ marginTop: '20px' }}>
          <h3>Cryptographic Output:</h3>
          <p><strong>Nullifier Hash:</strong> {proofData.publicSignals[0].slice(0, 15)}...</p>
          <p><strong>Merkle Root:</strong> {proofData.publicSignals[1].slice(0, 15)}...</p>
          <textarea 
            readOnly 
            value={JSON.stringify(proofData.proof, null, 2)} 
            style={{ width: '100%', height: '200px', fontFamily: 'monospace', marginTop: '10px' }} 
          />
        </div>
      )}
    </div>
  );
}

export default App;