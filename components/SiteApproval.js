import React from 'react';
import { useSelector } from 'react-redux';

const SiteApproval = () => {
  const approvalRequest = useSelector((state) => state.approvalRequest);

  const respond = async (approved) => {
    if (!approvalRequest?.requestId) return;
    await chrome.runtime.sendMessage({
      method: 'approvalDecision',
      payload: {
        requestId: approvalRequest.requestId,
        approved,
      },
    });
  };

  if (!approvalRequest) {
    return <p>No approval request loaded.</p>;
  }

  return (
    <div className="balance-container">
      <h2>Connect Site</h2>
      <p><strong>Origin:</strong> {approvalRequest.origin}</p>
      <p><strong>Network:</strong> {approvalRequest.network || 'LTC'}</p>
      <p>
        Approving this site lets it request your wallet address and public key for the selected
        network. Spending still requires a separate signing approval.
      </p>
      <div className="buttons-container">
        <button onClick={() => respond(true)}>Approve</button>
        <button onClick={() => respond(false)}>Reject</button>
      </div>
    </div>
  );
};

export default SiteApproval;
