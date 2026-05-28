import React, { useEffect, useRef, useState } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { setPSBTToSign, setSignRequest, setStep } from '../store/store';
import { checkPasswordMatch, signInputsInPsbt, summarizePsbtForDisplay } from '../lib/walletUtils';

const formatLtc = (sats) => (typeof sats === 'number' ? (sats / 1e8).toFixed(8) : 'unknown');

const SignPSBT = () => {
  const dispatch = useDispatch();
  const passwordRef = useRef('');
  const psbtPayload = useSelector((state) => state.psbt);
  const network = useSelector((state) => state.network);
  const sellerFlag = useSelector((state) => state.signPSBT);
  const requestId = useSelector((state) => state.id);
  const requestOrigin = useSelector((state) => state.requestOrigin);
  const address = useSelector((state) => state.address);
  const [summary, setSummary] = useState(null);

  useEffect(() => {
    let cancelled = false;

    const loadSummary = async () => {
      if (!psbtPayload?.psbtHex) {
        setSummary(null);
        return;
      }

      const result = await chrome.storage.local.get(['addresses']);
      const ownAddresses = (result.addresses || [])
        .map((item) => item.address)
        .filter(Boolean);

      if (address) {
        ownAddresses.push(address);
      }

      try {
        const nextSummary = summarizePsbtForDisplay(
          psbtPayload.psbtHex,
          network,
          Array.from(new Set(ownAddresses))
        );
        if (!cancelled) {
          setSummary(nextSummary);
        }
      } catch (error) {
        console.error('Failed to summarize PSBT:', error);
        if (!cancelled) {
          setSummary(null);
        }
      }
    };

    loadSummary();
    return () => {
      cancelled = true;
    };
  }, [address, network, psbtPayload]);

  const reject = async (reason = 'User rejected the PSBT signing request.') => {
    if (requestId) {
      await chrome.runtime.sendMessage({
        method: 'rejectPendingRequest',
        payload: { requestId, reason },
      });
    }

    dispatch(setSignRequest(false));
    dispatch(setPSBTToSign(null, null));
    dispatch(setStep(7));
  };

  const sign = async () => {
    const password = passwordRef.current.value || '';
    passwordRef.current.value = '';

    if (!password) {
      alert('Please enter a password');
      return;
    }

    const validPassword = await checkPasswordMatch(password, network, address);
    if (!validPassword) {
      alert('Invalid password');
      return;
    }

    try {
      if (!psbtPayload?.psbtHex) {
        throw new Error('No PSBT loaded.');
      }

      const signedPSBT = await signInputsInPsbt(
        psbtPayload.psbtHex,
        network,
        password,
        sellerFlag,
        psbtPayload.redeemScript
      );

      if (!signedPSBT || !signedPSBT.success) {
        throw new Error('PSBT signing failed: ' + (signedPSBT?.error || 'unknown error'));
      }

      await chrome.runtime.sendMessage({
        method: 'signTxResponse',
        payload: {
          requestId,
          signedTx: {
            success: true,
            data: {
              psbtHex: signedPSBT.data.rawTx,
              isValid: true,
              isFinished: !sellerFlag,
              rawTx: signedPSBT.data.rawTx,
              txid: signedPSBT.data.txid,
            },
          },
        },
      });

      dispatch(setStep(14));
    } catch (error) {
      console.error('Error signing PSBT:', error);
      alert('Failed to sign the PSBT: ' + error.message);
    }
  };

  return (
    <div>
      <h2>Sign PSBT</h2>
      {requestOrigin && <p><strong>Origin:</strong> {requestOrigin}</p>}
      {network && <p><strong>Network:</strong> {network}</p>}
      <p><strong>Role:</strong> {sellerFlag ? 'Partial signer' : 'Final signer'}</p>

      {summary && (
        <div>
          <h3>Spend Summary</h3>
          <p><strong>Inputs:</strong> {summary.inputCount}</p>
          <p><strong>Outputs:</strong> {summary.outputCount}</p>
          <p><strong>Total In:</strong> {formatLtc(summary.totalInputSats)} {summary.network}</p>
          <p><strong>Total Out:</strong> {formatLtc(summary.totalOutputSats)} {summary.network}</p>
          <p><strong>Estimated Fee:</strong> {formatLtc(summary.feeSats)} {summary.network}</p>
          {summary.outputs.map((output) => (
            <div key={output.index} style={{ marginBottom: '12px' }}>
              <strong>Output {output.index}</strong>
              <div>Amount: {formatLtc(output.valueSats)} {summary.network}</div>
              <div>
                Destination: {output.address || (output.isOpReturn ? 'OP_RETURN' : 'Non-standard output')}
              </div>
              {output.isChange && <div>Tagged as change output.</div>}
              {output.opReturnText && <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{output.opReturnText}</pre>}
            </div>
          ))}
        </div>
      )}

      {psbtPayload?.redeemScript && (
        <div>
          <h3>Witness Script</h3>
          <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontSize: '10px' }}>
            {psbtPayload.redeemScript}
          </pre>
        </div>
      )}

      <div>
        <label htmlFor="password">Enter Password to Sign:</label>
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

export default SignPSBT;
