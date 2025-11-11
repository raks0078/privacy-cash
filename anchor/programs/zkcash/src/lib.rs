use anchor_lang::prelude::*;
use light_hasher::Poseidon;
use anchor_lang::solana_program::sysvar::rent::Rent;
use ark_ff::PrimeField;
use ark_bn254::Fr;

declare_id!("9fhQBbumKEFuXtMBDw8AaQyAjCorLGJQiS3skWZdQyQD");

pub mod merkle_tree;
pub mod utils;
pub mod groth16;
pub mod errors;

use merkle_tree::MerkleTree;

// Constants
const MERKLE_TREE_HEIGHT: u8 = 26;

#[cfg(any(feature = "localnet", test))]
pub const ADMIN_PUBKEY: Option<Pubkey> = None;

#[cfg(not(any(feature = "localnet", test)))]
pub const ADMIN_PUBKEY: Option<Pubkey> = Some(pubkey!("AWexibGxNFKTa1b5R5MN4PJr9HWnWRwf8EW9g8cLx3dM"));

#[program]
pub mod zkcash {
    use crate::utils::{verify_proof, VERIFYING_KEY};

    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        if let Some(admin_key) = ADMIN_PUBKEY {
            require!(ctx.accounts.authority.key().eq(&admin_key), ErrorCode::Unauthorized);
        }
        
        let tree_account = &mut ctx.accounts.tree_account.load_init()?;
        tree_account.authority = ctx.accounts.authority.key();
        tree_account.next_index = 0;
        tree_account.root_index = 0;
        tree_account.bump = ctx.bumps.tree_account;
        tree_account.max_deposit_amount = 1_000_000_000_000; // 1000 SOL default limit
        tree_account.height = MERKLE_TREE_HEIGHT; // Hardcoded height
        tree_account.root_history_size = 100; // Hardcoded root history size

        MerkleTree::initialize::<Poseidon>(tree_account)?;
        
        let token_account = &mut ctx.accounts.tree_token_account;
        token_account.authority = ctx.accounts.authority.key();
        token_account.bump = ctx.bumps.tree_token_account;
        
        // Initialize global config
        let global_config = &mut ctx.accounts.global_config;
        global_config.authority = ctx.accounts.authority.key();
        global_config.deposit_fee_rate = 0; // 0% - Free deposits
        global_config.withdrawal_fee_rate = 100; // 1% (100 basis points)
        global_config.fee_error_margin = 500; // 5% (500 basis points)
        global_config.bump = ctx.bumps.global_config;
        
        msg!("Sparse Merkle Tree initialized successfully with height: {}, root history size: {}, deposit limit: {} lamports, \
            deposit fee rate: {}, withdrawal fee rate: {}, fee error margin: {}",
            MERKLE_TREE_HEIGHT, 100, tree_account.max_deposit_amount, global_config.deposit_fee_rate, global_config.withdrawal_fee_rate, global_config.fee_error_margin);
        Ok(())
    }

    // Other contract methods omitted for brevity...
}