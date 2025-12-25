// Copyright (c) Elliot Technologies, Inc.
// SPDX-License-Identifier: BUSL-1.1

use anyhow::Result;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::Witness;
use serde::Deserialize;

use crate::bigint::bigint::{BigIntTarget, CircuitBuilderBigInt, SignTarget};
use crate::bigint::biguint::{BigUintTarget, CircuitBuilderBiguint};
use crate::bigint::comparison::CircuitBuilderBiguintSubtractiveComparison;
use crate::bool_utils::CircuitBuilderBoolUtils;
use crate::comparison::CircuitBuilderSubtractiveComparison;
use crate::eddsa::gadgets::base_field::QuinticExtensionTarget;
use crate::eddsa::schnorr::hash_to_quintic_extension_circuit;
use crate::liquidation::get_available_collateral;
use crate::tx_interface::{Apply, TxHash, Verify};
use crate::types::config::{BIG_U96_LIMBS, Builder, F};
use crate::types::constants::*;
use crate::types::public_pool::{PublicPoolInfoTarget, select_public_pool_info_target};
use crate::types::tx_state::TxState;
use crate::types::tx_type::TxTypeTargets;
use crate::uint::u32::gadgets::arithmetic_u32::CircuitBuilderU32;
use crate::utils::CircuitBuilderUtils;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct L2CreatePublicPoolTx {
    #[serde(rename = "ai")]
    pub account_index: i64, // 48 bits

    #[serde(rename = "ki")]
    pub api_key_index: u8,

    #[serde(rename = "o")]
    pub operator_fee: i64,

    #[serde(rename = "i")]
    pub initial_total_shares: i64,

    #[serde(rename = "m")]
    pub min_operator_share_rate: i64,
}

#[derive(Debug, Clone)]
pub struct L2CreatePublicPoolTxTarget {
    pub account_index: Target, // 48 bits
    pub api_key_index: Target, // 8 bits
    pub operator_fee: Target,
    pub initial_total_shares: Target,
    pub min_operator_share_rate: Target,

    // helper
    pub account_type: Target,
    pub collateral_delta: BigUintTarget,

    // output
    pub success: BoolTarget,
}

impl L2CreatePublicPoolTxTarget {
    pub fn new(builder: &mut Builder) -> Self {
        L2CreatePublicPoolTxTarget {
            account_index: builder.add_virtual_target(),
            api_key_index: builder.add_virtual_target(),
            operator_fee: builder.add_virtual_target(),
            initial_total_shares: builder.add_virtual_target(),
            min_operator_share_rate: builder.add_virtual_target(),
            account_type: builder.zero(),
            collateral_delta: builder.zero_biguint(),

            // output
            success: BoolTarget::default(),
        }
    }
}

impl TxHash for L2CreatePublicPoolTxTarget {
    fn hash(
        &self,
        builder: &mut Builder,
        tx_nonce: Target,
        tx_expired_at: Target,
        chain_id: u32,
    ) -> QuinticExtensionTarget {
        let elements = [
            builder.constant(F::from_canonical_u32(chain_id)),
            builder.constant(F::from_canonical_u8(TX_TYPE_L2_CREATE_PUBLIC_POOL)),
            tx_nonce,
            tx_expired_at,
            self.account_index,
            self.api_key_index,
            self.operator_fee,
            self.initial_total_shares,
            self.min_operator_share_rate,
        ];

        hash_to_quintic_extension_circuit(builder, &elements)
    }
}

impl Verify for L2CreatePublicPoolTxTarget {
    fn verify(&mut self, builder: &mut Builder, tx_type: &TxTypeTargets, tx_state: &TxState) {
        let is_enabled = tx_type.is_l2_create_public_pool;
        self.success = is_enabled;

        builder.conditional_assert_eq(
            is_enabled,
            self.account_index,
            tx_state.accounts[MASTER_ACCOUNT_ID].account_index,
        );
        builder.conditional_assert_eq(
            is_enabled,
            self.api_key_index,
            tx_state.api_key.api_key_index,
        );

        let fee_tick = builder.constant(F::from_canonical_u64(FEE_TICK));
        builder.register_range_check(self.operator_fee, 24);
        builder.conditional_assert_lte(is_enabled, self.operator_fee, fee_tick, FEE_BITS);

        builder.conditional_assert_not_zero(is_enabled, self.initial_total_shares);
        let max_initial_total_shares = builder.constant_u64(MAX_INITIAL_TOTAL_SHARES);
        builder.register_range_check(self.initial_total_shares, INITIAL_TOTAL_SHARES_BITS);
        builder.conditional_assert_lte(
            is_enabled,
            self.initial_total_shares,
            max_initial_total_shares,
            INITIAL_TOTAL_SHARES_BITS,
        );

        let share_tick = builder.constant(F::from_canonical_u64(SHARE_TICK));
        builder.register_range_check(self.min_operator_share_rate, SHARE_RATE_BITS);
        builder.conditional_assert_lte(
            is_enabled,
            self.min_operator_share_rate,
            share_tick,
            SHARE_RATE_BITS,
        );

        // Ensure the sender account is a master account
        let max_master_account_index = builder.constant_i64(MAX_MASTER_ACCOUNT_INDEX);
        builder.conditional_assert_lte(
            is_enabled,
            self.account_index,
            max_master_account_index,
            ACCOUNT_INDEX_BITS,
        );

        let min_sub_account_index = builder.constant_i64(MIN_SUB_ACCOUNT_INDEX);
        builder.conditional_assert_lte(
            is_enabled,
            min_sub_account_index,
            tx_state.accounts[SUB_ACCOUNT_ID].account_index,
            ACCOUNT_INDEX_BITS,
        );

        // Verify that given sub-account is empty before
        let is_new_account = tx_state.is_new_account[SUB_ACCOUNT_ID];
        builder.conditional_assert_true(is_enabled, is_new_account);

        // nil account index is reserved and always should be empty
        let nil_account_index = builder.constant_i64(NIL_ACCOUNT_INDEX);
        builder.conditional_assert_not_eq(
            is_enabled,
            tx_state.accounts[SUB_ACCOUNT_ID].account_index,
            nil_account_index,
        );

        let insurance_fund_operator_account_index =
            builder.constant_usize(INSURANCE_FUND_OPERATOR_ACCOUNT_INDEX);
        let is_insurance_fund_operator_account = builder.is_equal(
            tx_state.accounts[MASTER_ACCOUNT_ID].account_index,
            insurance_fund_operator_account_index,
        );

        let public_pool_account_type =
            builder.constant(F::from_canonical_u8(PUBLIC_POOL_ACCOUNT_TYPE));
        let insurance_fund_account_type =
            builder.constant(F::from_canonical_u8(INSURANCE_FUND_ACCOUNT_TYPE));
        self.account_type = builder.select(
            is_insurance_fund_operator_account,
            insurance_fund_account_type,
            public_pool_account_type,
        );

        let initial_pool_share_value = builder.constant_u64(INITIAL_POOL_SHARE_VALUE);
        let pool_usdc_value = builder.mul(self.initial_total_shares, initial_pool_share_value);
        let pool_usdc_value_big = builder.target_to_biguint(pool_usdc_value);
        let usdc_to_collateral_multiplier = builder.constant_u32(USDC_TO_COLLATERAL_MULTIPLIER);
        self.collateral_delta = builder.mul_biguint_non_carry(
            &pool_usdc_value_big,
            &BigUintTarget::from(usdc_to_collateral_multiplier),
            BIG_U96_LIMBS,
        );
        let available_collateral_to_transfer =
            get_available_collateral(builder, &tx_state.risk_infos[0].cross_risk_parameters);
        builder.conditional_assert_lte_biguint(
            is_enabled,
            &self.collateral_delta,
            &available_collateral_to_transfer,
        );
    }
}

impl Apply for L2CreatePublicPoolTxTarget {
    fn apply(&mut self, builder: &mut Builder, tx_state: &mut TxState) -> BoolTarget {
        tx_state.accounts[SUB_ACCOUNT_ID].account_type = builder.select(
            self.success,
            self.account_type,
            tx_state.accounts[SUB_ACCOUNT_ID].account_type,
        );
        tx_state.accounts[SUB_ACCOUNT_ID].l1_address = builder.select_biguint(
            self.success,
            &tx_state.accounts[MASTER_ACCOUNT_ID].l1_address,
            &tx_state.accounts[SUB_ACCOUNT_ID].l1_address,
        );
        tx_state.accounts[SUB_ACCOUNT_ID].master_account_index = builder.select(
            self.success,
            self.account_index,
            tx_state.accounts[SUB_ACCOUNT_ID].master_account_index,
        );

        let zero = builder.zero();
        let one = builder.one();
        let neg_one = builder.neg_one();

        let is_big_collateral_amount_zero = builder.is_zero_biguint(&self.collateral_delta);
        let add_sign = builder.select(is_big_collateral_amount_zero, zero, one);
        let sub_sign = builder.select(is_big_collateral_amount_zero, zero, neg_one);

        let account_collateral_after = builder.add_bigint_non_carry(
            &tx_state.accounts[MASTER_ACCOUNT_ID].collateral,
            &BigIntTarget {
                abs: self.collateral_delta.clone(),
                sign: SignTarget::new_unsafe(sub_sign),
            },
            BIG_U96_LIMBS,
        );
        let pool_collateral_after = &BigIntTarget {
            abs: self.collateral_delta.clone(),
            sign: SignTarget::new_unsafe(add_sign),
        };

        tx_state.accounts[MASTER_ACCOUNT_ID].collateral = builder.select_bigint(
            self.success,
            &account_collateral_after,
            &tx_state.accounts[MASTER_ACCOUNT_ID].collateral,
        );
        tx_state.accounts[SUB_ACCOUNT_ID].collateral = builder.select_bigint(
            self.success,
            pool_collateral_after,
            &tx_state.accounts[SUB_ACCOUNT_ID].collateral,
        );

        let active_public_pool = builder.constant_from_u8(ACTIVE_PUBLIC_POOL);
        let public_pool_info = &PublicPoolInfoTarget {
            status: active_public_pool,
            operator_fee: self.operator_fee,
            min_operator_share_rate: self.min_operator_share_rate,
            total_shares: self.initial_total_shares,
            operator_shares: self.initial_total_shares,
        };
        tx_state.accounts[SUB_ACCOUNT_ID].public_pool_info = select_public_pool_info_target(
            builder,
            self.success,
            public_pool_info,
            &tx_state.accounts[SUB_ACCOUNT_ID].public_pool_info,
        );

        self.success
    }
}

pub trait L2CreatePublicPoolTxTargetWitness<F: PrimeField64> {
    fn set_l2_create_public_pool_tx_target(
        &mut self,
        a: &L2CreatePublicPoolTxTarget,
        b: &L2CreatePublicPoolTx,
    ) -> Result<()>;
}

impl<T: Witness<F>, F: PrimeField64> L2CreatePublicPoolTxTargetWitness<F> for T {
    fn set_l2_create_public_pool_tx_target(
        &mut self,
        a: &L2CreatePublicPoolTxTarget,
        b: &L2CreatePublicPoolTx,
    ) -> Result<()> {
        self.set_target(a.account_index, F::from_canonical_i64(b.account_index))?;
        self.set_target(a.api_key_index, F::from_canonical_u8(b.api_key_index))?;
        self.set_target(a.operator_fee, F::from_canonical_i64(b.operator_fee))?;
        self.set_target(
            a.initial_total_shares,
            F::from_canonical_i64(b.initial_total_shares),
        )?;
        self.set_target(
            a.min_operator_share_rate,
            F::from_canonical_i64(b.min_operator_share_rate),
        )?;

        Ok(())
    }
}
