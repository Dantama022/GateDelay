const { ethers } = require('ethers');
// Note: gnosis-safe-sdk is mentioned in requirements but not in package.json.
// We will implement the logic using ethers.js as the primary library.

/**
 * MULTISIG SERVICE
 * Handles management of multi-signature wallets, signature collection, and transaction processing.
 */

// In-memory store for pending transactions (In production, this would be in MongoDB)
const pendingTransactions = new Map();

// Replay protection: store used nonces with timestamps
const usedNonces = new Map();
const NONCE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const MAX_TIMESTAMP_DRIFT_MS = 5 * 60 * 1000; // 5 minutes

// Mock Multi-sig Wallets Configuration
const MULTISIG_WALLETS = {
  'MARKET_OPS': {
    address: '0x1234567890123456789012345678901234567890',
    owners: [
      '0xOwner1...',
      '0xOwner2...',
      '0xOwner3...'
    ],
    threshold: 2,
    scheme: 'ECDSA'
  },
  'TREASURY': {
    address: '0x0987654321098765432109876543210987654321',
    owners: [
      '0xAdmin1...',
      '0xAdmin2...',
      '0xAdmin3...',
      '0xAdmin4...',
      '0xAdmin5...'
    ],
    threshold: 3,
    scheme: 'BLS'
  }
};

/**
 * Get multisig wallet details
 * @param {string} walletId 
 * @returns {object}
 */
function getWallet(walletId) {
  const wallet = MULTISIG_WALLETS[walletId];
  if (!wallet) throw new Error('Multisig wallet not found');
  return wallet;
}

/**
 * Verify replay protection (nonce, timestamp, signature)
 * @param {string} nonce 
 * @param {number} timestamp 
 * @param {string} signature 
 * @param {string} signer 
 * @param {object} payload 
 * @returns {object} { valid: boolean, error?: string, recoveredSigner?: string }
 */
function verifyReplayProtection(nonce, timestamp, signature, signer, payload) {
  if (!nonce || typeof nonce !== 'string') {
    return { valid: false, error: 'Missing or invalid nonce' };
  }

  if (usedNonces.has(nonce)) {
    return { valid: false, error: 'Nonce already used (replay detected)' };
  }

  if (!timestamp || typeof timestamp !== 'number') {
    return { valid: false, error: 'Missing or invalid timestamp' };
  }

  const now = Date.now();
  if (Math.abs(now - timestamp) > MAX_TIMESTAMP_DRIFT_MS) {
    return {
      valid: false,
      error: `Timestamp drift exceeds ${MAX_TIMESTAMP_DRIFT_MS}ms`
    };
  }

  if (!signature || typeof signature !== 'string') {
    return { valid: false, error: 'Missing or invalid signature' };
  }

  if (!signer || typeof signer !== 'string') {
    return { valid: false, error: 'Missing or invalid signer' };
  }

  // Create deterministic message from payload, nonce, and timestamp
  const sortedPayload = Object.keys(payload)
    .sort()
    .reduce((acc, key) => {
      acc[key] = payload[key];
      return acc;
    }, {});

  const message = JSON.stringify({
    payload: sortedPayload,
    nonce,
    timestamp
  });

  let recoveredSigner;
  try {
    recoveredSigner = ethers.verifyMessage(message, signature);
  } catch {
    return { valid: false, error: 'Invalid signature format' };
  }

  if (ethers.getAddress(recoveredSigner) !== ethers.getAddress(signer)) {
    return { valid: false, error: 'Signature signer mismatch' };
  }

  // Mark nonce as used
  usedNonces.set(nonce, timestamp);

  return { valid: true, recoveredSigner };
}

/**
 * Cleanup expired nonces (call periodically)
 */
function cleanupExpiredNonces() {
  const now = Date.now();
  for (const [nonce, ts] of usedNonces.entries()) {
    if (now - ts > NONCE_TTL_MS) {
      usedNonces.delete(nonce);
    }
  }
}

// Run cleanup every hour
setInterval(cleanupExpiredNonces, 60 * 60 * 1000);

/**
 * Propose a new multi-sig transaction
 * @param {string} walletId 
 * @param {object} txData 
 * @param {string} proposer 
 * @param {string} nonce - Unique nonce for replay protection
 * @param {number} timestamp - Unix timestamp in milliseconds
 * @param {string} signature - EIP-191 signature of the proposal payload
 * @returns {string} transactionId
 */
async function proposeTransaction(walletId, txData, proposer, nonce, timestamp, signature) {
  const wallet = getWallet(walletId);
  
  if (!wallet.owners.includes(proposer)) {
    throw new Error('Proposer is not an owner of this multisig');
  }

  // Verify replay protection
  const payload = { walletId, txData, proposer };
  const replayResult = verifyReplayProtection(nonce, timestamp, signature, proposer, payload);
  if (!replayResult.valid) {
    throw new Error(`Replay protection failed: ${replayResult.error}`);
  }

  const txId = ethers.id(JSON.stringify(txData) + Date.now());
  
  pendingTransactions.set(txId, {
    id: txId,
    walletId,
    data: txData,
    proposer,
    signatures: [],
    status: 'Pending',
    createdAt: new Date().toISOString(),
    nonce, // Store nonce for reference
    timestamp // Store timestamp for reference
  });

  return txId;
}

/**
 * Collect signature for a pending transaction
 * @param {string} txId 
 * @param {string} owner 
 * @param {string} signature 
 * @param {string} nonce - Unique nonce for replay protection
 * @param {number} timestamp - Unix timestamp in milliseconds
 * @param {string} signSignature - EIP-191 signature of the sign payload
 */
async function collectSignature(txId, owner, signature, nonce, timestamp, signSignature) {
  const tx = pendingTransactions.get(txId);
  if (!tx) throw new Error('Transaction not found');
  
  const wallet = getWallet(tx.walletId);
  if (!wallet.owners.includes(owner)) {
    throw new Error('Signer is not an owner of this multisig');
  }

  // Verify replay protection for signature collection
  const payload = { txId, owner, signature };
  const replayResult = verifyReplayProtection(nonce, timestamp, signSignature, owner, payload);
  if (!replayResult.valid) {
    throw new Error(`Replay protection failed: ${replayResult.error}`);
  }

  // Verify the transaction signature itself (simplified for mock)
  // In production: ethers.verifyMessage(txId, signature) === owner
  
  if (tx.signatures.find(s => s.owner === owner)) {
    throw new Error('Owner has already signed this transaction');
  }

  tx.signatures.push({ owner, signature, timestamp: new Date().toISOString() });

  // Update status if threshold reached
  if (tx.signatures.length >= wallet.threshold) {
    tx.status = 'Ready';
  }

  return tx;
}

/**
 * Process/Execute a multi-sig transaction
 * @param {string} txId 
 * @param {string} executor 
 * @param {string} nonce 
 * @param {number} timestamp 
 * @param {string} signature 
 */
async function processTransaction(txId, executor, nonce, timestamp, signature) {
  const tx = pendingTransactions.get(txId);
  if (!tx) throw new Error('Transaction not found');
  
  const wallet = getWallet(tx.walletId);

  // Verify replay protection for execution
  const payload = { txId, executor };
  const replayResult = verifyReplayProtection(nonce, timestamp, signature, executor, payload);
  if (!replayResult.valid) {
    throw new Error(`Replay protection failed: ${replayResult.error}`);
  }

  if (tx.signatures.length < wallet.threshold) {
    throw new Error(`Insufficient signatures. Required: ${wallet.threshold}, Current: ${tx.signatures.length}`);
  }

  // Verify executor is an owner
  if (!wallet.owners.includes(executor)) {
    throw new Error('Executor is not an owner of this multisig');
  }

  console.log(`Executing multisig transaction ${txId} for wallet ${tx.walletId}...`);
  
  // Logic to broadcast to blockchain would go here
  tx.status = 'Executed';
  tx.executedAt = new Date().toISOString();
  tx.txHash = '0x' + Math.random().toString(16).slice(2, 66);
  tx.executedBy = executor;

  return tx;
}

/**
 * Track status of a transaction
 * @param {string} txId 
 */
function getTransactionStatus(txId) {
  const tx = pendingTransactions.get(txId);
  if (!tx) throw new Error('Transaction not found');
  return tx;
}

module.exports = {
  getWallet,
  proposeTransaction,
  collectSignature,
  processTransaction,
  getTransactionStatus,
  verifyReplayProtection,
  cleanupExpiredNonces
};
