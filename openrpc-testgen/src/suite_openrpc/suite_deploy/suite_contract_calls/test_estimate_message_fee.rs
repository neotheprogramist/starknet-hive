use crate::assert_result;
use crate::utils::v7::accounts::account::ConnectedAccount;
use crate::utils::v7::providers::provider::Provider;
use crate::{
    utils::v7::endpoints::{errors::OpenRpcTestGenError, utils::get_selector_from_name},
    RunnableTrait,
};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{BlockId, BlockTag, MsgFromL1, PriceUnit};

const BLOB_GAS_PRICE: Felt = Felt::from_hex_unchecked("0x28");
const GAS_PRICE: Felt = Felt::from_hex_unchecked("0x1e");

#[derive(Clone, Debug)]
pub struct TestCase {}

impl RunnableTrait for TestCase {
    type Input = super::TestSuiteContractCalls;

    async fn run(test_input: &Self::Input) -> Result<Self, OpenRpcTestGenError> {
        let estimate = test_input
            .random_paymaster_account
            .provider()
            .estimate_message_fee(
                MsgFromL1 {
                    from_address: String::from("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
                    to_address: test_input.deployed_contract_address,
                    entry_point_selector: get_selector_from_name("deposit")?,
                    payload: vec![(1_u32).into(), (10_u32).into()],
                },
                BlockId::Tag(BlockTag::Pending),
            )
            .await;

        let result = estimate.is_ok();

        assert_result!(result);

        let estimate = estimate?;

        let expected_price_unit = PriceUnit::Wei;
        assert_result!(
            estimate.unit == expected_price_unit,
            format!(
                "Estimate fee unit expected: {:?}, actual: {:?}",
                expected_price_unit, estimate.unit
            )
        );

        assert_result!(
            estimate.data_gas_price == BLOB_GAS_PRICE,
            format!(
                "Estimate data gas price expected: {:?}, actual: {:?}",
                BLOB_GAS_PRICE, estimate.data_gas_price
            )
        );

        assert_result!(
            estimate.gas_price == GAS_PRICE,
            format!(
                "Estimate fee data gas price expected: {:?}, actual: {:?}",
                GAS_PRICE, estimate.gas_price
            )
        );

        let data_fee = estimate.data_gas_consumed * estimate.data_gas_price;

        let fee = estimate.gas_consumed * estimate.gas_price;

        let overall_fee = data_fee + fee;

        assert_result!(
            overall_fee == estimate.overall_fee,
            format!(
                "Estimate fee overall fee expected: {:?}, actual: {:?}",
                overall_fee, estimate.overall_fee
            )
        );

        Ok(Self {})
    }
}
