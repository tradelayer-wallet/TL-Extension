import React, { useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { setSeedPhrase } from '../store/store';
import { generateMnemonic, derivePrivateKey, signMessage } from '../lib/walletUtils';

const SignMessage = () => {
  const [message, setMessage] = useState('Hello, world!');
  const dispatch = useDispatch();
  const seedPhrase = useSelector((state) => state.seedPhrase); // Get seed phrase from Redux

  const handleSignMessage = () => {
    // Check if seedPhrase exists
    if (!seedPhrase) {
      alert('Please generate a seed phrase first!');
      return;
    }

    // Derive private key from the seed phrase
    const privateKey = derivePrivateKey(seedPhrase);
    console.log('Derived Private Key:', privateKey);

    // Sign the message using the derived private key
    const signature = signMessage(privateKey, message);
    console.log('Message Signature:', signature);
    alert(`Message Signed: ${signature}`);
  };

  return (
    <div>
      <h2>Step 2: Sign a Message</h2>
      
      {/* Input to change the message to be signed */}
      <input
        type="text"
        value={message}
        onChange={(e) => setMessage(e.target.value)}
        placeholder="Enter message to sign"
      />
      
      <button onClick={handleSignMessage}>Sign Message</button>

      <p>Message: {message}</p>
    </div>
  );
};

export default SignMessage;
