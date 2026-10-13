import React, { useRef } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { setMessageToSign, setSignRequest, setStep, setTxToSign } from '../store/store';
import { checkPasswordMatch, signMessage, signTransaction } from '../lib/walletUtils';

const SignTransaction = () => {
  const dispatch = useDispatch();
  const passwordRef = useRef('');
  const address = useSelector((state) => state.address);
  const messageToSign = useSelector((state) => state.message);
  const network = useSelector((state) => state.network);
  const requestId = useSelector((state) => state.id);
  const requestOrigin = useSelector((state) => state.requestOrigin);
  const txToSign = useSelector((state) => state.tx);

  const checkPassword = async (password) => {
    try {
      return await checkPasswordMatch(password, network, address);
    } catch {
      return false;
    }
  };

  const reject = async (reason = 'User rejected the signing request.') => {
    if (requestId) {
      await chrome.runtime.sendMessage({
        method: 'rejectPendingRequest',
        payload: { requestId, reason },
      });
    }
    dispatch(setSignRequest(false));
    dispatch(setMessageToSign(null));
    dispatch(setTxToSign(null));
    dispatch(setStep(7));
  };

  const sign = async () => {
    const password = passwordRef.current.value || '';
    passwordRef.current.value = '';

    if (!password) {
      alert('Please enter a password');
      return;
    }

    const valid = await checkPassword(password);
    if (!valid) {
      alert('Invalid password');
      return;
    }

    try {
      if (messageToSign) {
        const signedMessage = await signMessage(messageToSign, password, network);
        await chrome.runtime.sendMessage({
          method: 'signMessageResponse',
          payload: {
            requestId,
            signedMessage,
          },
        });
      } else if (txToSign) {
        const signedTx = await signTransaction(txToSign, password, network);
        await chrome.runtime.sendMessage({
          method: 'signTxResponse',
          payload: {
            requestId,
            signedTx,
          },
        });
      }

      dispatch(setSignRequest(false));
      dispatch(setMessageToSign(null));
      dispatch(setTxToSign(null));
      dispatch(setStep(14));
    } catch (error) {
      console.error('Error signing request:', error);
      alert('There was an error signing the request.');
    }
  };

  return (
    <div>
      <h2>{messageToSign ? 'Sign Message' : 'Review Legacy Transaction'}</h2>

      {requestOrigin && <p><strong>Origin:</strong> {requestOrigin}</p>}
      {network && <p><strong>Network:</strong> {network}</p>}

      {messageToSign && (
        <div>
          <h3>Message</h3>
          <pre className="tx-box" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
            {messageToSign}
          </pre>
        </div>
      )}

      {!messageToSign && txToSign && (
        <div>
          <h3>Transaction Payload</h3>
          <pre className="tx-box" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
            {JSON.stringify(txToSign, null, 2)}
          </pre>
        </div>
      )}

      <div>
        <label htmlFor="password">Enter Password to Approve:</label>
        <input
          type="password"
          id="password"
          ref={passwordRef}
          placeholder="Enter password"
        />
      </div>

      <button onClick={sign}>Approve</button>
      <button onClick={() => reject()}>Reject</button>
    </div>
  );
};

export default SignTransaction;
