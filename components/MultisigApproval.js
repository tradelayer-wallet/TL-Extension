import React from 'react';
import { useSelector } from 'react-redux';
import { addMultisigAddress } from '../lib/walletUtils';

const MultisigApproval = () => {
  const approvalRequest = useSelector((state) => state.approvalRequest);

  const reject = async () => {
    if (!approvalRequest?.requestId) return;
    await chrome.runtime.sendMessage({
      method: 'rejectPendingRequest',
      payload: {
        requestId: approvalRequest.requestId,
        reason: 'User rejected multisig request.',
      },
    });
  };

  const approve = async () => {
    if (!approvalRequest?.requestId) return;

    try {
      const result = addMultisigAddress(
        approvalRequest.m,
        approvalRequest.pubkeys,
        approvalRequest.network
      );

      await chrome.runtime.sendMessage({
        method: 'addMultisigResponse',
        payload: {
          requestId: approvalRequest.requestId,
          result,
        },
      });
    } catch (error) {
      await chrome.runtime.sendMessage({
        method: 'rejectPendingRequest',
        payload: {
          requestId: approvalRequest.requestId,
          reason: error.message || 'Failed to create multisig address.',
        },
      });
    }
  };

  if (!approvalRequest) {
    return <p>No multisig request loaded.</p>;
  }

  return (
    <div className="balance-container">
      <h2>Create Multisig</h2>
      <p><strong>Origin:</strong> {approvalRequest.origin}</p>
      <p><strong>Network:</strong> {approvalRequest.network}</p>
      <p><strong>Threshold:</strong> {approvalRequest.m} of {approvalRequest.pubkeys?.length || 0}</p>
      <div className="wallet-address-display" style={{ display: 'block' }}>
        {approvalRequest.pubkeys?.map((pubkey) => (
          <pre key={pubkey} style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontSize: '10px' }}>
            {pubkey}
          </pre>
        ))}
      </div>
      <div className="buttons-container">
        <button onClick={approve}>Approve</button>
        <button onClick={reject}>Reject</button>
      </div>
    </div>
  );
};

export default MultisigApproval;
