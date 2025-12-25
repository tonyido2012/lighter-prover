// Copyright (c) Elliot Technologies, Inc.
// SPDX-License-Identifier: BUSL-1.1

use num::BigUint;
use plonky2::iop::target::{BoolTarget, Target};

use super::account::AccountTarget;
use super::account_position::{AccountPositionTarget, get_position_unrealized_pnl};
use super::config::{BIG_U96_LIMBS, Builder};
use super::constants::{
    BANKRUPTCY, ISOLATED_MARGIN, MARGIN_FRACTION_MULTIPLIER, POSITION_LIST_SIZE,
    USDC_TO_COLLATERAL_MULTIPLIER,
};
use super::market_details::{MarketDetailsTarget, select_market_details};
use crate::bigint::big_u16::{CircuitBuilderBigIntU16, CircuitBuilderBiguint16};
use crate::bigint::bigint::{BigIntTarget, CircuitBuilderBigInt, SignTarget};
use crate::bigint::biguint::{BigUintTarget, CircuitBuilderBiguint};
use crate::bigint::comparison::CircuitBuilderBiguintSubtractiveComparison;
use crate::signed::signed_target::CircuitBuilderSigned;
use crate::types::constants::MARKET_STATUS_EXPIRED;
use crate::uint::u32::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target};
use crate::utils::CircuitBuilderUtils;

#[derive(Debug, Clone, Default)]
pub struct RiskInfoTarget {
    // Risk parameters for the cross margin, includes all cross positions
    pub cross_risk_parameters: RiskParametersTarget,
    // If current market is isolated, this will be the risk parameters for the isolated market, otherwise it will be the same as cross_risk_parameters
    pub current_risk_parameters: RiskParametersTarget,
}

#[derive(Debug, Clone, Default)]
pub struct RiskParametersTarget {
    pub collateral: BigIntTarget,              // 96 bits
    pub collateral_with_funding: BigIntTarget, // 96 bits
    pub total_account_value: BigIntTarget,     // 96 bits
    pub initial_margin_requirement: BigUintTarget,
    pub maintenance_margin_requirement: BigUintTarget,
    pub close_out_margin_requirement: BigUintTarget,
}

impl RiskInfoTarget {
    pub fn new(
        builder: &mut Builder,
        account: &AccountTarget,
        position: &AccountPositionTarget,
        current_market_details: &MarketDetailsTarget,
        all_market_details: &[MarketDetailsTarget; POSITION_LIST_SIZE],
    ) -> Self {
        let usdc_to_collateral_multiplier =
            BigUintTarget::from(builder.constant_u32(USDC_TO_COLLATERAL_MULTIPLIER));
        let isolated_margin_mode = builder.constant_usize(ISOLATED_MARGIN);

        let is_isolated_position = builder.is_equal(position.margin_mode, isolated_margin_mode);

        let (position_base_notional_values, cross_position_base_notional_value) =
            account.get_cross_position_base_notional_values(builder, all_market_details);

        let (isolated_position_notional, isolated_position_base_notinal_value) = {
            let zero = builder.zero();
            let one = builder.one();
            let (isolated_position_notional, isolated_positive_tpv_sum, isolated_negative_tpv_sum) =
                position_base_notional(builder, position, current_market_details);
            let is_positive_tpv_sum_zero = builder.is_zero(isolated_positive_tpv_sum);
            let add_sign = builder.select(is_positive_tpv_sum_zero, zero, one);
            let big_positive_tpv_sum = BigIntTarget {
                abs: builder.target_to_biguint(isolated_positive_tpv_sum),
                sign: SignTarget::new_unsafe(add_sign),
            };

            let is_negative_tpv_sum_zero = builder.is_zero(isolated_negative_tpv_sum);
            let add_sign = builder.select(is_negative_tpv_sum_zero, zero, one);
            let big_negative_tpv_sum = BigIntTarget {
                abs: builder.target_to_biguint(isolated_negative_tpv_sum),
                sign: SignTarget::new_unsafe(add_sign),
            };
            (
                builder.target_to_biguint(isolated_position_notional),
                builder.sub_bigint_non_carry(
                    &big_positive_tpv_sum,
                    &big_negative_tpv_sum,
                    BIG_U96_LIMBS,
                ),
            )
        };

        let cross_position_notional_value = builder.mul_bigint_with_biguint_non_carry(
            &cross_position_base_notional_value,
            &usdc_to_collateral_multiplier,
            BIG_U96_LIMBS,
        );

        let isolated_position_notional_value = builder.mul_bigint_with_biguint_non_carry(
            &isolated_position_base_notinal_value,
            &usdc_to_collateral_multiplier,
            BIG_U96_LIMBS,
        );

        let cross_funding = account.get_cross_unrealized_funding(builder, all_market_details);
        let isolated_funding =
            position_unrealized_funding(builder, position, current_market_details);

        let cross_collateral = account.collateral.clone();
        let cross_collateral_with_funding =
            builder.add_bigint_non_carry(&cross_collateral, &cross_funding, BIG_U96_LIMBS);
        let cross_total_account_value = builder.add_bigint_non_carry(
            &cross_collateral_with_funding,
            &cross_position_notional_value,
            BIG_U96_LIMBS,
        );

        let isolated_collateral = position.allocated_margin.clone();
        let isolated_collateral_with_funding =
            builder.add_bigint_non_carry(&isolated_collateral, &isolated_funding, BIG_U96_LIMBS);
        let isolated_total_account_value = builder.add_bigint_non_carry(
            &isolated_collateral_with_funding,
            &isolated_position_notional_value,
            BIG_U96_LIMBS,
        );

        let cross_initial_margin_requirement = account.get_initial_margin_requirement(
            builder,
            &position_base_notional_values,
            all_market_details,
        );

        let cross_maintenance_margin_requirement = account.get_maintenance_margin_requirement(
            builder,
            &position_base_notional_values,
            all_market_details,
        );

        let cross_close_out_margin_requirement = account.get_close_out_margin_requirement(
            builder,
            &position_base_notional_values,
            all_market_details,
        );

        let cross_risk_parameters = RiskParametersTarget {
            collateral: cross_collateral,
            total_account_value: cross_total_account_value,
            collateral_with_funding: cross_collateral_with_funding,
            initial_margin_requirement: cross_initial_margin_requirement,
            maintenance_margin_requirement: cross_maintenance_margin_requirement,
            close_out_margin_requirement: cross_close_out_margin_requirement,
        };

        let (
            isolated_initial_margin_requirement,
            isolated_maintenance_margin_requirement,
            isolated_close_out_margin_requirement,
        ) = position_margin_requirements(
            builder,
            position,
            &isolated_position_notional,
            current_market_details,
        );
        let isolated_risk_parameters = RiskParametersTarget {
            collateral: isolated_collateral,
            total_account_value: isolated_total_account_value,
            collateral_with_funding: isolated_collateral_with_funding,
            initial_margin_requirement: isolated_initial_margin_requirement,
            maintenance_margin_requirement: isolated_maintenance_margin_requirement,
            close_out_margin_requirement: isolated_close_out_margin_requirement,
        };

        let current_risk_parameters = RiskParametersTarget::select(
            builder,
            is_isolated_position,
            &isolated_risk_parameters,
            &cross_risk_parameters,
        );

        RiskInfoTarget {
            cross_risk_parameters,
            current_risk_parameters,
        }
    }
}

impl RiskParametersTarget {
    pub fn get_health(&self, builder: &mut Builder) -> Target {
        let neg_one = builder.neg_one();

        let is_tav_negative = builder.is_equal(self.total_account_value.sign.target, neg_one);

        let initial_margin_gt = builder.is_lt_biguint(
            &self.total_account_value.abs,
            &self.initial_margin_requirement,
        );
        let maintenance_margin_gt = builder.is_lt_biguint(
            &self.total_account_value.abs,
            &self.maintenance_margin_requirement,
        );
        let close_out_margin_gt = builder.is_lt_biguint(
            &self.total_account_value.abs,
            &self.close_out_margin_requirement,
        );

        let positive_tav_result = builder.add_many([
            initial_margin_gt.target,
            maintenance_margin_gt.target,
            close_out_margin_gt.target,
        ]);

        // If total account value is negative, health status is BANKRUPTCY
        // Otherwise, positive_tav_result could be 0 to 3 i.e. HEALTHY to FULL_LIQUIDATION
        let bancruptcy = builder.constant_from_u8(BANKRUPTCY);
        builder.select(is_tav_negative, bancruptcy, positive_tav_result)
    }

    pub fn is_healthy(&self, builder: &mut Builder) -> BoolTarget {
        let neg_one = builder.neg_one();
        let tav_is_not_negative =
            builder.is_not_equal(self.total_account_value.sign.target, neg_one);
        let abs_tav_gte_initial_margin = builder.is_gte_biguint(
            &self.total_account_value.abs,
            &self.initial_margin_requirement,
        );
        builder.and(tav_is_not_negative, abs_tav_gte_initial_margin)
    }

    /// Returns true if health < PRE_LIQUIDATION
    pub fn is_not_in_liquidation(&self, builder: &mut Builder) -> BoolTarget {
        let neg_one = builder.neg_one();
        let tav_is_not_negative =
            builder.is_not_equal(self.total_account_value.sign.target, neg_one);
        let abs_tav_gte_maintenance_margin = builder.is_gte_biguint(
            &self.total_account_value.abs,
            &self.maintenance_margin_requirement,
        );
        builder.and(tav_is_not_negative, abs_tav_gte_maintenance_margin)
    }

    fn is_health_improved(&self, builder: &mut Builder, new: &Self) -> BoolTarget {
        let left_side = builder.mul_bigint_with_biguint_non_carry(
            &self.total_account_value,
            &new.maintenance_margin_requirement,
            self.total_account_value.abs.limbs.len()
                + new.maintenance_margin_requirement.limbs.len(),
        );
        let right_side = builder.mul_bigint_with_biguint_non_carry(
            &new.total_account_value,
            &self.maintenance_margin_requirement,
            new.total_account_value.abs.limbs.len()
                + self.maintenance_margin_requirement.limbs.len(),
        );

        builder.is_lte_bigint(&left_side, &right_side)
    }

    pub fn is_valid_risk_change(&self, builder: &mut Builder, new: &Self) -> BoolTarget {
        // 1. If new account collateral is not within [-2^96, 2^96], return false
        // 2. If the account is below initial margin requirement, health should improve
        // 3. If the account is above initial margin, it should stay above initial margin requirement

        let is_healthy_before = self.is_healthy(builder);
        let is_health_improved = self.is_health_improved(builder, new);
        let cond_1 = builder.or(is_healthy_before, is_health_improved);

        let is_not_healthy_before = builder.not(is_healthy_before);
        let is_healthy_after = new.is_healthy(builder);
        let cond_2 = builder.or(is_not_healthy_before, is_healthy_after);

        builder.and(cond_1, cond_2)
    }

    pub fn is_in_liquidation(&self, builder: &mut Builder) -> BoolTarget {
        let neg_one = builder.neg_one();
        let is_tav_negative = builder.is_equal(self.total_account_value.sign.target, neg_one);
        let is_tav_abs_less_than_mmr = builder.is_lt_biguint(
            &self.total_account_value.abs,
            &self.maintenance_margin_requirement,
        );
        builder.or(is_tav_negative, is_tav_abs_less_than_mmr)
    }

    pub fn update(
        &self,
        builder: &mut Builder,
        collateral_delta: &BigIntTarget,
        old_position: &AccountPositionTarget,
        new_position: &AccountPositionTarget,
        market_details: &MarketDetailsTarget,
        is_enabled: BoolTarget,
    ) -> Self {
        let zero_bigint = builder.zero_bigint();
        let empty_position = AccountPositionTarget::empty(builder);
        let empty_market = MarketDetailsTarget::empty(builder);

        // Prevent overflow when inactive
        let collateral_delta = builder.select_bigint(is_enabled, collateral_delta, &zero_bigint);
        let old_position = AccountPositionTarget::select_position(
            builder,
            is_enabled,
            old_position,
            &empty_position,
        );
        let new_position = AccountPositionTarget::select_position(
            builder,
            is_enabled,
            new_position,
            &empty_position,
        );
        let market_details =
            select_market_details(builder, is_enabled, market_details, &empty_market);

        // Apply collateral delta
        let collateral =
            builder.add_bigint_non_carry(&self.collateral, &collateral_delta, BIG_U96_LIMBS);
        let collateral_with_funding = builder.add_bigint_non_carry(
            &self.collateral_with_funding,
            &collateral_delta,
            BIG_U96_LIMBS,
        );

        // Apply total account value delta
        let mut total_account_value = builder.add_bigint_non_carry(
            &self.total_account_value,
            &collateral_delta,
            BIG_U96_LIMBS,
        );

        // Update position value changes to the total account value
        let old_position_abs = builder.biguint_u16_to_target(&old_position.position.abs);
        let old_notional = get_position_unrealized_pnl(
            builder,
            &market_details,
            old_position_abs,
            old_position.position.sign,
            old_position.entry_quote,
        );
        let new_position_abs = builder.biguint_u16_to_target(&new_position.position.abs);
        let new_notional = get_position_unrealized_pnl(
            builder,
            &market_details,
            new_position_abs,
            new_position.position.sign,
            new_position.entry_quote,
        );

        let notional_diff = builder.sub_signed(new_notional, old_notional);
        let notional_diff_big = builder.signed_target_to_bigint(notional_diff);

        let usdc_to_collateral_multiplier =
            builder.constant_biguint(&BigUint::from(USDC_TO_COLLATERAL_MULTIPLIER));
        let total_account_value_delta = builder.mul_bigint_with_biguint_non_carry(
            &notional_diff_big,
            &usdc_to_collateral_multiplier,
            BIG_U96_LIMBS,
        );

        total_account_value = builder.add_bigint_non_carry(
            &total_account_value,
            &total_account_value_delta,
            BIG_U96_LIMBS,
        );

        // Update margin requirements for the position change
        let margin_fraction_multiplier = builder.constant_u64(MARGIN_FRACTION_MULTIPLIER as u64);
        let normalized_position_notional_multiplier = builder.mul_many([
            market_details.mark_price,       // 32 bits
            market_details.quote_multiplier, // 14 bits
            margin_fraction_multiplier,      // 7 bits
        ]);
        let normalized_position_notional_multiplier =
            builder.target_to_biguint(normalized_position_notional_multiplier);
        let old_position_abs_big = builder.target_to_biguint(old_position_abs);
        let new_position_abs_big = builder.target_to_biguint(new_position_abs);
        let old_normalized_position_notional_value = builder.mul_biguint_non_carry(
            &old_position_abs_big,
            &normalized_position_notional_multiplier,
            BIG_U96_LIMBS,
        );
        let new_normalized_position_notional_value = builder.mul_biguint_non_carry(
            &new_position_abs_big,
            &normalized_position_notional_multiplier,
            BIG_U96_LIMBS,
        );

        // Update initial margin requirement
        let new_position_initial_margin_fraction = new_position.get_initial_margin_fraction(
            builder,
            market_details.default_initial_margin_fraction,
            market_details.min_initial_margin_fraction,
        );
        let new_position_initial_margin_fraction_big =
            builder.target_to_biguint_single_limb_unsafe(new_position_initial_margin_fraction);
        let old_position_initial_margin_fraction = old_position.get_initial_margin_fraction(
            builder,
            market_details.default_initial_margin_fraction,
            market_details.min_initial_margin_fraction,
        );
        let old_position_initial_margin_fraction_big =
            builder.target_to_biguint_single_limb_unsafe(old_position_initial_margin_fraction);
        let initial_margin_requirement_add = builder.mul_biguint_non_carry(
            &new_position_initial_margin_fraction_big,
            &new_normalized_position_notional_value,
            BIG_U96_LIMBS,
        );
        let initial_margin_requirement_sub = builder.mul_biguint_non_carry(
            &old_position_initial_margin_fraction_big,
            &old_normalized_position_notional_value,
            BIG_U96_LIMBS,
        );
        let initial_margin_requirement = builder.add_biguint_non_carry(
            &self.initial_margin_requirement,
            &initial_margin_requirement_add,
            BIG_U96_LIMBS,
        );
        let (initial_margin_requirement, sub_success) =
            builder.try_sub_biguint(&initial_margin_requirement, &initial_margin_requirement_sub);
        builder.conditional_assert_zero(is_enabled, sub_success.0);

        // Update maintenance margin requirement
        let maintenance_margin_fraction_big = builder
            .target_to_biguint_single_limb_unsafe(market_details.maintenance_margin_fraction);
        let maintenance_margin_requirement_add = builder.mul_biguint_non_carry(
            &new_normalized_position_notional_value,
            &maintenance_margin_fraction_big,
            BIG_U96_LIMBS,
        );
        let maintenance_margin_requirement_sub = builder.mul_biguint_non_carry(
            &old_normalized_position_notional_value,
            &maintenance_margin_fraction_big,
            BIG_U96_LIMBS,
        );
        let maintenance_margin_requirement = builder.add_biguint_non_carry(
            &self.maintenance_margin_requirement,
            &maintenance_margin_requirement_add,
            BIG_U96_LIMBS,
        );
        let (maintenance_margin_requirement, sub_success) = builder.try_sub_biguint(
            &maintenance_margin_requirement,
            &maintenance_margin_requirement_sub,
        );
        builder.conditional_assert_zero(is_enabled, sub_success.0);

        // Update close out margin requirement
        let close_out_margin_fraction_big =
            builder.target_to_biguint_single_limb_unsafe(market_details.close_out_margin_fraction);
        let close_out_margin_requirement_add = builder.mul_biguint_non_carry(
            &new_normalized_position_notional_value,
            &close_out_margin_fraction_big,
            BIG_U96_LIMBS,
        );
        let close_out_margin_requirement_sub = builder.mul_biguint_non_carry(
            &old_normalized_position_notional_value,
            &close_out_margin_fraction_big,
            BIG_U96_LIMBS,
        );
        let close_out_margin_requirement = builder.add_biguint_non_carry(
            &self.close_out_margin_requirement,
            &close_out_margin_requirement_add,
            BIG_U96_LIMBS,
        );
        let (close_out_margin_requirement, sub_success) = builder.try_sub_biguint(
            &close_out_margin_requirement,
            &close_out_margin_requirement_sub,
        );
        builder.conditional_assert_zero(is_enabled, sub_success.0);

        Self {
            collateral,
            total_account_value,
            initial_margin_requirement,
            maintenance_margin_requirement,
            close_out_margin_requirement,
            collateral_with_funding,
        }
    }

    pub fn select(builder: &mut Builder, flag: BoolTarget, a: &Self, b: &Self) -> Self {
        let collateral = builder.select_bigint(flag, &a.collateral, &b.collateral);
        let collateral_with_funding =
            builder.select_bigint(flag, &a.collateral_with_funding, &b.collateral_with_funding);
        let total_account_value =
            builder.select_bigint(flag, &a.total_account_value, &b.total_account_value);
        let initial_margin_requirement = builder.select_biguint(
            flag,
            &a.initial_margin_requirement,
            &b.initial_margin_requirement,
        );
        let maintenance_margin_requirement = builder.select_biguint(
            flag,
            &a.maintenance_margin_requirement,
            &b.maintenance_margin_requirement,
        );
        let close_out_margin_requirement = builder.select_biguint(
            flag,
            &a.close_out_margin_requirement,
            &b.close_out_margin_requirement,
        );

        Self {
            collateral,
            collateral_with_funding,
            total_account_value,
            initial_margin_requirement,
            maintenance_margin_requirement,
            close_out_margin_requirement,
        }
    }
}

pub fn position_base_notional(
    builder: &mut Builder,
    position: &AccountPositionTarget,
    market_details: &MarketDetailsTarget,
) -> (Target, Target, Target) {
    let one = builder.one();

    // Compute the position notional value as Target, then convert it to BigInt
    let mark_price_times_quote_multiplier =
        builder.mul(market_details.quote_multiplier, market_details.mark_price);
    let abs_position = builder.biguint_u16_to_target(&position.position.abs);
    let abs_position_notional = builder.mul(abs_position, mark_price_times_quote_multiplier);
    let position_is_positive = builder.is_equal(position.position.sign.target, one);
    let positive_tpv_component = builder.select(
        position_is_positive,
        abs_position_notional,
        position.entry_quote,
    );
    let negative_tpv_component = builder.select(
        position_is_positive,
        position.entry_quote,
        abs_position_notional,
    );

    // Expired market -> no margin requirement
    let expired_market_status = builder.constant_u64(MARKET_STATUS_EXPIRED as u64);
    let is_market_not_expired = builder.is_not_equal(market_details.status, expired_market_status);
    (
        builder.mul_bool(is_market_not_expired, abs_position_notional),
        positive_tpv_component,
        negative_tpv_component,
    )
}

pub fn position_unrealized_funding(
    builder: &mut Builder,
    position: &AccountPositionTarget,
    market_details: &MarketDetailsTarget,
) -> BigIntTarget {
    let last_funding_rate_ps = builder.bigint_u16_to_bigint(&position.last_funding_rate_prefix_sum);
    let market_funding_rate_ps =
        builder.bigint_u16_to_bigint(&market_details.funding_rate_prefix_sum);
    let position = builder.bigint_u16_to_bigint(&position.position);

    let quote_multiplier = BigUintTarget::from(U32Target(market_details.quote_multiplier));

    let abs_position_times_quote_multiplier =
        builder.mul_biguint_non_carry(&position.abs, &quote_multiplier, BIG_U96_LIMBS);

    let funding_rate_ps_diff = builder.sub_bigint(&last_funding_rate_ps, &market_funding_rate_ps);

    BigIntTarget {
        abs: builder.mul_biguint_non_carry(
            &abs_position_times_quote_multiplier,
            &funding_rate_ps_diff.abs,
            BIG_U96_LIMBS,
        ),
        sign: SignTarget::new_unsafe(
            builder.mul(position.sign.target, funding_rate_ps_diff.sign.target),
        ),
    }
}

pub fn position_margin_requirements(
    builder: &mut Builder,
    position: &AccountPositionTarget,
    position_notional_value: &BigUintTarget,
    market_details: &MarketDetailsTarget,
) -> (BigUintTarget, BigUintTarget, BigUintTarget) {
    let margin_fraction_multiplier =
        builder.constant_biguint(&BigUint::from(MARGIN_FRACTION_MULTIPLIER));

    let initial_margin_fraction = BigUintTarget {
        // Set a single limb from initial margin fraction
        limbs: vec![U32Target(position.get_initial_margin_fraction(
            builder,
            market_details.default_initial_margin_fraction,
            market_details.min_initial_margin_fraction,
        ))],
    };
    let position_times_initial_margin = builder.mul_biguint_non_carry(
        position_notional_value,
        &initial_margin_fraction,
        BIG_U96_LIMBS,
    );
    let initial_margin_requirement = builder.mul_biguint_non_carry(
        &position_times_initial_margin,
        &margin_fraction_multiplier,
        BIG_U96_LIMBS,
    );

    let maintenance_margin_fraction = BigUintTarget {
        // Set a single limb from initial margin fraction
        limbs: vec![U32Target(market_details.maintenance_margin_fraction)],
    };
    let position_times_maintenance_margin = builder.mul_biguint_non_carry(
        position_notional_value,
        &maintenance_margin_fraction,
        BIG_U96_LIMBS,
    );
    let maintenance_margin_requirement = builder.mul_biguint_non_carry(
        &position_times_maintenance_margin,
        &margin_fraction_multiplier,
        BIG_U96_LIMBS,
    );

    let close_out_margin_fraction = BigUintTarget {
        // Set a single limb from initial margin fraction
        limbs: vec![U32Target(market_details.close_out_margin_fraction)],
    };
    let position_times_close_out_margin = builder.mul_biguint_non_carry(
        position_notional_value,
        &close_out_margin_fraction,
        BIG_U96_LIMBS,
    );
    let close_out_margin_requirement = builder.mul_biguint_non_carry(
        &position_times_close_out_margin,
        &margin_fraction_multiplier,
        BIG_U96_LIMBS,
    );

    (
        initial_margin_requirement,
        maintenance_margin_requirement,
        close_out_margin_requirement,
    )
}
