// Copyright (c) Elliot Technologies, Inc.
// SPDX-License-Identifier: BUSL-1.1

use anyhow::Result;
use num::BigUint;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::Witness;
use serde::Deserialize;

use crate::bigint::bigint::{BigIntTarget, SignTarget};
use crate::bigint::biguint::{BigUintTarget, CircuitBuilderBiguint};
use crate::bigint::comparison::CircuitBuilderBiguintSubtractiveComparison;
use crate::bool_utils::CircuitBuilderBoolUtils;
use crate::eddsa::gadgets::base_field::QuinticExtensionTarget;
use crate::eddsa::schnorr::hash_to_quintic_extension_circuit;
use crate::liquidation::{get_available_collateral, get_shares_usdc_value};
use crate::tx_interface::{Apply, TxHash, Verify};
use crate::types::config::{BIG_U96_LIMBS, Builder, F};
use crate::types::constants::*;
use crate::types::tx_state::TxState;
use crate::types::tx_type::TxTypeTargets;
use crate::utils::CircuitBuilderUtils;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct L2MintSharesTx {
    #[serde(rename = "ai", default)]
    pub account_index: i64,

    #[serde(rename = "ki", default)]
    pub api_key_index: u8,

    #[serde(rename = "p", default)]
    pub public_pool_index: i64,

    #[serde(rename = "s", default)]
    pub share_amount: i64,
}

#[derive(Debug)]
pub struct L2MintSharesTxTarget {
    pub account_index: Target,
    pub api_key_index: Target,
    pub public_pool_index: Target,
    pub share_amount: Target,

    // Helper
    is_operator: BoolTarget,
    usdc_amount: Target,
    new_total_shares: Target,
    new_entry_usdc: Target,
    collateral_to_mint_shares: BigUintTarget,

    // Output
    success: BoolTarget,
}

impl L2MintSharesTxTarget {
    pub fn new(builder: &mut Builder) -> Self {
        L2MintSharesTxTarget {
            account_index: builder.add_virtual_target(),
            api_key_index: builder.add_virtual_target(),
            public_pool_index: builder.add_virtual_target(),
            share_amount: builder.add_virtual_target(),

            // Helper
            is_operator: builder._false(),
            usdc_amount: builder.zero(),
            new_total_shares: builder.zero(),
            new_entry_usdc: builder.zero(),
            collateral_to_mint_shares: builder.zero_biguint(),

            // Output
            success: BoolTarget::default(),
        }
    }
}

impl TxHash for L2MintSharesTxTarget {
    fn hash(
        &self,
        builder: &mut Builder,
        tx_nonce: Target,
        tx_expired_at: Target,
        chain_id: u32,
    ) -> QuinticExtensionTarget {
        let elements = [
            builder.constant(F::from_canonical_u32(chain_id)),
            builder.constant(F::from_canonical_u8(TX_TYPE_L2_MINT_SHARES)),
            tx_nonce,
            tx_expired_at,
            self.account_index,
            self.api_key_index,
            self.public_pool_index,
            self.share_amount,
        ];

        hash_to_quintic_extension_circuit(builder, &elements)
    }
}

impl Verify for L2MintSharesTxTarget {
    fn verify(&mut self, builder: &mut Builder, tx_type: &TxTypeTargets, tx_state: &TxState) {
        let is_enabled = tx_type.is_l2_mint_shares;
        self.success = is_enabled;

        builder.conditional_assert_eq(
            is_enabled,
            self.account_index,
            tx_state.accounts[OWNER_ACCOUNT_ID].account_index,
        );
        builder.conditional_assert_eq(
            is_enabled,
            self.api_key_index,
            tx_state.api_key.api_key_index,
        );
        builder.conditional_assert_eq(
            is_enabled,
            self.public_pool_index,
            tx_state.accounts[SUB_ACCOUNT_ID].account_index,
        );

        let big_shares_amount = builder.target_to_biguint(self.share_amount);
        builder.range_check_biguint(
            &big_shares_amount,
            MAX_POOL_SHARES_TO_MINT_OR_BURN_USDC_BITS,
        );
        builder.conditional_assert_not_zero(is_enabled, self.share_amount);

        let public_pool_account_type = builder.constant_from_u8(PUBLIC_POOL_ACCOUNT_TYPE);
        let insurance_fund_account_type = builder.constant_from_u8(INSURANCE_FUND_ACCOUNT_TYPE);
        let is_public_pool_account_type = builder.is_equal(
            tx_state.accounts[SUB_ACCOUNT_ID].account_type,
            public_pool_account_type,
        );
        let is_insurance_fund_account_type = builder.is_equal(
            tx_state.accounts[SUB_ACCOUNT_ID].account_type,
            insurance_fund_account_type,
        );
        let is_valid_account_type =
            builder.or(is_public_pool_account_type, is_insurance_fund_account_type);
        builder.conditional_assert_true(is_enabled, is_valid_account_type);

        let active_public_pool = builder.constant_from_u8(ACTIVE_PUBLIC_POOL);
        let is_active_public_pool = builder.is_equal(
            tx_state.accounts[SUB_ACCOUNT_ID].public_pool_info.status,
            active_public_pool,
        );
        builder.conditional_assert_true(is_enabled, is_active_public_pool);

        self.new_total_shares = builder.add(
            tx_state.accounts[SUB_ACCOUNT_ID]
                .public_pool_info
                .total_shares,
            self.share_amount,
        );
        let big_new_total_shares = builder.target_to_biguint(self.new_total_shares);
        builder.range_check_biguint(&big_new_total_shares, MAX_POOL_SHARES_BITS);

        let available_collateral_to_mint_shares = get_available_collateral(
            builder,
            &tx_state.risk_infos[OWNER_ACCOUNT_ID].cross_risk_parameters,
        );

        self.usdc_amount = get_shares_usdc_value(
            builder,
            &tx_state.risk_infos[SUB_ACCOUNT_ID].cross_risk_parameters,
            &tx_state.accounts[SUB_ACCOUNT_ID],
            self.share_amount,
        );
        self.new_entry_usdc = builder.add(tx_state.public_pool_share.entry_usdc, self.usdc_amount);
        builder.register_range_check(self.new_entry_usdc, MAX_POOL_ENTRY_USDC_BITS);
        let usdc_to_collateral_multiplier =
            builder.constant_biguint(&BigUint::from(USDC_TO_COLLATERAL_MULTIPLIER));

        let big_usdc_amount = builder.target_to_biguint(self.usdc_amount);
        self.collateral_to_mint_shares = builder.mul_biguint_non_carry(
            &big_usdc_amount,
            &usdc_to_collateral_multiplier,
            BIG_U96_LIMBS,
        );
        builder.conditional_assert_lte_biguint(
            is_enabled,
            &self.collateral_to_mint_shares,
            &available_collateral_to_mint_shares,
        );

        self.is_operator = builder.is_equal(
            tx_state.accounts[OWNER_ACCOUNT_ID].account_index,
            tx_state.accounts[SUB_ACCOUNT_ID].master_account_index,
        );

        // If minter is not the operator, then check if the minimum share rate is still
        // going to be satisfied for the pool operator
        {
            // If operator shares drops below the minimum operator share rate, fail the transaction
            let big_min_operator_share_rate = builder.target_to_biguint(
                tx_state.accounts[SUB_ACCOUNT_ID]
                    .public_pool_info
                    .min_operator_share_rate,
            );
            let big_operator_shares = builder.target_to_biguint(
                tx_state.accounts[SUB_ACCOUNT_ID]
                    .public_pool_info
                    .operator_shares,
            );
            let big_share_tick = builder.constant_biguint(&BigUint::from(SHARE_TICK));
            let lhs = builder.mul_biguint(&big_new_total_shares, &big_min_operator_share_rate);
            let rhs = builder.mul_biguint(&big_operator_shares, &big_share_tick);
            let not_operator_and_enabled = builder.and_not(is_enabled, self.is_operator);
            builder.conditional_assert_lte_biguint(not_operator_and_enabled, &lhs, &rhs);
        }
    }
}

impl Apply for L2MintSharesTxTarget {
    fn apply(&mut self, builder: &mut Builder, tx_state: &mut TxState) -> BoolTarget {
        let zero = builder.zero();
        let one = builder.one();
        let neg_one = builder.neg_one();

        let is_big_collateral_amount_zero =
            builder.is_zero_biguint(&self.collateral_to_mint_shares);
        let add_sign = builder.select(is_big_collateral_amount_zero, zero, one);
        let sub_sign = builder.select(is_big_collateral_amount_zero, zero, neg_one);

        // Collateral deltas
        tx_state.accounts[OWNER_ACCOUNT_ID].apply_collateral_delta(
            builder,
            self.success,
            BigIntTarget {
                abs: self.collateral_to_mint_shares.clone(),
                sign: SignTarget::new_unsafe(sub_sign),
            },
        );
        tx_state.accounts[SUB_ACCOUNT_ID].apply_collateral_delta(
            builder,
            self.success,
            BigIntTarget {
                abs: self.collateral_to_mint_shares.clone(),
                sign: SignTarget::new_unsafe(add_sign),
            },
        );

        // Public pool total share
        tx_state.accounts[SUB_ACCOUNT_ID]
            .public_pool_info
            .total_shares = builder.select(
            self.success,
            self.new_total_shares,
            tx_state.accounts[SUB_ACCOUNT_ID]
                .public_pool_info
                .total_shares,
        );

        // Set pool shares - not operator
        {
            let is_success_and_not_operator = builder.and_not(self.success, self.is_operator);

            let new_share_amount =
                builder.add(tx_state.public_pool_share.share_amount, self.share_amount);
            tx_state.public_pool_share.entry_usdc = builder.select(
                is_success_and_not_operator,
                self.new_entry_usdc,
                tx_state.public_pool_share.entry_usdc,
            );
            tx_state.public_pool_share.share_amount = builder.select(
                is_success_and_not_operator,
                new_share_amount,
                tx_state.public_pool_share.share_amount,
            );
            tx_state.apply_pool_share_delta_flag = builder.or(
                is_success_and_not_operator,
                tx_state.apply_pool_share_delta_flag,
            );
        }
        // Set pool shares - is operator
        {
            let is_success_and_operator = builder.and(self.success, self.is_operator);
            let new_operator_shares_for_operator = builder.add(
                tx_state.accounts[SUB_ACCOUNT_ID]
                    .public_pool_info
                    .operator_shares,
                self.share_amount,
            );
            tx_state.accounts[SUB_ACCOUNT_ID]
                .public_pool_info
                .operator_shares = builder.select(
                is_success_and_operator,
                new_operator_shares_for_operator,
                tx_state.accounts[SUB_ACCOUNT_ID]
                    .public_pool_info
                    .operator_shares,
            );
        }

        self.success
    }
}

pub trait L2MintSharesTxTargetWitness<F: PrimeField64> {
    fn set_l2_mint_shares_tx_target(
        &mut self,
        a: &L2MintSharesTxTarget,
        b: &L2MintSharesTx,
    ) -> Result<()>;
}

impl<T: Witness<F>, F: PrimeField64> L2MintSharesTxTargetWitness<F> for T {
    fn set_l2_mint_shares_tx_target(
        &mut self,
        a: &L2MintSharesTxTarget,
        b: &L2MintSharesTx,
    ) -> Result<()> {
        self.set_target(a.account_index, F::from_canonical_i64(b.account_index))?;
        self.set_target(a.api_key_index, F::from_canonical_u8(b.api_key_index))?;
        self.set_target(
            a.public_pool_index,
            F::from_canonical_i64(b.public_pool_index),
        )?;
        self.set_target(a.share_amount, F::from_canonical_i64(b.share_amount))?;
        Ok(())
    }
}
