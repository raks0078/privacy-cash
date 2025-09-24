import { 
  Connection, 
  Keypair, 
  PublicKey, 
  SystemProgram,
  AddressLookupTableProgram,
  Transaction,
  sendAndConfirmTransaction,
  ComputeBudgetProgram,
  VersionedTransaction,
  TransactionMessage
} from '@solana/web3.js';
import * as anchor from "@coral-xyz/anchor";

// Global ALT for test session (created once, used everywhere)
let globalTestALT: PublicKey | null = null;

/**
 * Create a global test ALT that will be reused for all tests in the session
 */
export async function createGlobalTestALT(
  connection: Connection,
  payer: Keypair,
  addresses: PublicKey[]
): Promise<PublicKey> {
  if (globalTestALT) {
    return globalTestALT;
  }

  try {
    // Create the lookup table with a recent slot
    const recentSlot = await connection.getSlot('confirmed');
    
    let [lookupTableInst, lookupTableAddress] = AddressLookupTableProgram.createLookupTable({
      authority: payer.publicKey,
      payer: payer.publicKey,
      recentSlot: recentSlot,
    });

    const createALTTx = new Transaction().add(lookupTableInst);
    
    try {
      await sendAndConfirmTransaction(connection, createALTTx, [payer]);
    } catch (error: any) {
      const isSlotTooOld = 
        error.message?.includes('not a recent slot') ||
        error.transactionLogs?.some((log: string) => log.includes('not a recent slot'));
      
      if (isSlotTooOld) {
        const newerSlot = await connection.getSlot('finalized');
        
        [lookupTableInst, lookupTableAddress] = AddressLookupTableProgram.createLookupTable({
          authority: payer.publicKey,
          payer: payer.publicKey,
          recentSlot: newerSlot,
        });
        
        const retryCreateALTTx = new Transaction().add(lookupTableInst);
        await sendAndConfirmTransaction(connection, retryCreateALTTx, [payer]);
      } else {
        throw error;
      }
    }
    
    // Wait a moment for the ALT to be available
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Add addresses to the lookup table in chunks
    const chunkSize = 20;
    const addressChunks = [];
    for (let i = 0; i < addresses.length; i += chunkSize) {
      addressChunks.push(addresses.slice(i, i + chunkSize));
    }

    for (let i = 0; i < addressChunks.length; i++) {
      const chunk = addressChunks[i];
      
      const extendInstruction = AddressLookupTableProgram.extendLookupTable({
        payer: payer.publicKey,
        authority: payer.publicKey,
        lookupTable: lookupTableAddress,
        addresses: chunk,
      });
      
      const extendTx = new Transaction().add(extendInstruction);
      await sendAndConfirmTransaction(connection, extendTx, [payer]);
      
      // Small delay between chunks
      if (i < addressChunks.length - 1) {
        await new Promise(resolve => setTimeout(resolve, 500));
      }
    }
    
    // Wait for all address additions to be confirmed
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Verify the ALT was created successfully
    const altAccount = await connection.getAddressLookupTable(lookupTableAddress);
    if (!altAccount.value) {
      throw new Error('Failed to create ALT');
    }
    
    globalTestALT = lookupTableAddress;
    return lookupTableAddress;
    
  } catch (error) {
    throw error;
  }
}

/**
 * Get all protocol addresses for the test ALT
 */
export function getTestProtocolAddresses(
  programId: PublicKey,
  authority: PublicKey,
  treeAccount: PublicKey,
  treeTokenAccount: PublicKey,
  feeRecipient: PublicKey
): PublicKey[] {
  return [
    // Program and system accounts
    programId,
    SystemProgram.programId,
    ComputeBudgetProgram.programId,
    
    // All important system variables and programs
    anchor.web3.SYSVAR_RENT_PUBKEY,
    anchor.web3.SYSVAR_CLOCK_PUBKEY,
    anchor.web3.SYSVAR_EPOCH_SCHEDULE_PUBKEY,
    anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
    anchor.web3.SYSVAR_RECENT_BLOCKHASHES_PUBKEY,
    anchor.web3.SYSVAR_SLOT_HASHES_PUBKEY,
    anchor.web3.SYSVAR_SLOT_HISTORY_PUBKEY,
    anchor.web3.SYSVAR_STAKE_HISTORY_PUBKEY,
    
    // Token program (even though we might not use it, include for safety)
    new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'),
    
    // Associated Token Program
    new PublicKey('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'),
    
    // Main accounts
    authority,
    treeAccount,
    treeTokenAccount,
    
    // Transaction-specific accounts
    feeRecipient,
  ];
}

/**
 * Create a versioned transaction using an existing ALT
 */
export async function createVersionedTransactionWithALT(
  connection: Connection,
  payer: PublicKey,
  instructions: anchor.web3.TransactionInstruction[],
  altAddress: PublicKey
): Promise<VersionedTransaction> {
  try {
    // Get the ALT account
    const lookupTableAccount = await connection.getAddressLookupTable(altAddress);
    if (!lookupTableAccount.value) {
      throw new Error(`ALT not found: ${altAddress.toString()}`);
    }
    
    // Get recent blockhash
    const recentBlockhash = await connection.getLatestBlockhash();
    
    // Create the message
    const messageV0 = new anchor.web3.TransactionMessage({
      payerKey: payer,
      recentBlockhash: recentBlockhash.blockhash,
      instructions: instructions,
    }).compileToV0Message([lookupTableAccount.value]);
    
    // Create versioned transaction
    const versionedTx = new VersionedTransaction(messageV0);
    
    return versionedTx;
    
  } catch (error) {
    throw error;
  }
}

/**
 * Send and confirm a versioned transaction
 */
export async function sendAndConfirmVersionedTransaction(
  connection: Connection,
  transaction: VersionedTransaction,
  signers: Keypair[]
): Promise<string> {
  // Sign the transaction
  transaction.sign(signers);
  
  // Send and confirm the transaction
  const signature = await connection.sendTransaction(transaction, {
    skipPreflight: false,
    preflightCommitment: 'confirmed',
  });
  
  // Get latest blockhash for confirmation
  const latestBlockHash = await connection.getLatestBlockhash();
  
  // Confirm the transaction
  await connection.confirmTransaction({
    blockhash: latestBlockHash.blockhash,
    lastValidBlockHeight: latestBlockHash.lastValidBlockHeight,
    signature: signature,
  });
  
  return signature;
}

/**
 * Get the current global test ALT (throws if not created)
 */
export function getGlobalTestALT(): PublicKey {
  if (!globalTestALT) {
    throw new Error('Global test ALT not created. Call createGlobalTestALT() first in before() hook');
  }
  return globalTestALT;
}

/**
 * Clear the global test ALT (useful for test cleanup)
 */
export function clearGlobalTestALT(): void {
  globalTestALT = null;
  console.log('Global test ALT cleared');
} 