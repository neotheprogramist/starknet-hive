use std::sync::Arc;

use super::v7::{
    accounts::{
        account::{
            Account, ConnectedAccount, DeclarationV2, DeclarationV3, ExecutionEncoder, ExecutionV1,
            ExecutionV3, RawDeclarationV2, RawDeclarationV3, RawExecutionV1, RawExecutionV3,
        },
        call::Call,
        creation::{
            create::{create_account, AccountType},
            helpers::get_chain_id,
        },
        deployment::{
            deploy::{deploy_account, DeployAccountVersion},
            structs::{ValidatedWaitParams, WaitForTx},
        },
        single_owner::{ExecutionEncoding, SingleOwnerAccount},
    },
    endpoints::{
        errors::OpenRpcTestGenError,
        utils::{get_selector_from_name, wait_for_sent_transaction},
    },
    providers::{
        jsonrpc::{HttpTransport, JsonRpcClient},
        provider::{Provider, ProviderError},
    },
    signers::{key_pair::SigningKey, local_wallet::LocalWallet},
};
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{BlockId, BlockTag, ContractClass};
use std::fmt::Debug;
use url::Url;

const STRK: Felt =
    Felt::from_hex_unchecked("0x4718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D");

#[derive(Debug)]
pub struct StarkneHive {
    pub account: SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
}

impl StarkneHive {
    pub async fn new(
        node_url: Url,
        paymaster_account_address: Felt,
        paymaster_private_key: Felt,
        account_class_hash: Felt,
    ) -> Result<Self, OpenRpcTestGenError> {
        let provider = JsonRpcClient::new(HttpTransport::new(node_url.clone()));
        let chain_id = get_chain_id(&provider).await?;
        let paymaster_private_key = SigningKey::from_secret_scalar(paymaster_private_key);

        let mut paymaster_account = SingleOwnerAccount::new(
            provider.clone(),
            LocalWallet::from(paymaster_private_key),
            paymaster_account_address,
            chain_id,
            ExecutionEncoding::New,
        );
        paymaster_account.set_block_id(BlockId::Tag(BlockTag::Pending));

        let account_data = create_account(
            &provider,
            AccountType::Oz,
            Option::None,
            Some(account_class_hash),
        )
        .await?;

        let transfer_amount = Felt::from_hex("0xfffffffffffffff")?;

        let transfer_execution = paymaster_account
            .execute_v3(vec![Call {
                to: STRK,
                selector: get_selector_from_name("transfer")?,
                calldata: vec![account_data.address, transfer_amount, Felt::ZERO],
            }])
            .send()
            .await?;

        wait_for_sent_transaction(transfer_execution.transaction_hash, &paymaster_account).await?;

        let wait_config = WaitForTx {
            wait: true,
            wait_params: ValidatedWaitParams::default(),
        };

        let deployment_hash = deploy_account(
            &provider,
            chain_id,
            wait_config,
            account_data,
            DeployAccountVersion::V3,
        )
        .await?;

        wait_for_sent_transaction(deployment_hash, &paymaster_account).await?;

        let account = SingleOwnerAccount::new(
            provider.clone(),
            LocalWallet::from(account_data.signing_key),
            account_data.address,
            chain_id,
            ExecutionEncoding::New,
        );
        Ok(Self { account })
    }
}

impl ExecutionEncoder for StarkneHive {
    fn encode_calls(&self, calls: &[Call]) -> Vec<Felt> {
        self.account.encode_calls(calls)
    }
}

impl Account for StarkneHive {
    type SignError =
        <SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet> as Account>::SignError;

    fn address(&self) -> Felt {
        self.account.address()
    }

    fn chain_id(&self) -> Felt {
        self.account.chain_id()
    }

    fn is_signer_interactive(&self) -> bool {
        self.account.is_signer_interactive()
    }

    async fn sign_execution_v1(
        &self,
        execution: &RawExecutionV1,
        query_only: bool,
    ) -> Result<Vec<Felt>, Self::SignError> {
        self.account.sign_execution_v1(execution, query_only).await
    }

    async fn sign_execution_v3(
        &self,
        execution: &RawExecutionV3,
        query_only: bool,
    ) -> Result<Vec<Felt>, Self::SignError> {
        self.account.sign_execution_v3(execution, query_only).await
    }

    async fn sign_declaration_v2(
        &self,
        declaration: &RawDeclarationV2,
        query_only: bool,
    ) -> Result<Vec<Felt>, Self::SignError> {
        self.account
            .sign_declaration_v2(declaration, query_only)
            .await
    }

    async fn sign_declaration_v3(
        &self,
        declaration: &RawDeclarationV3,
        query_only: bool,
    ) -> Result<Vec<Felt>, Self::SignError> {
        self.account
            .sign_declaration_v3(declaration, query_only)
            .await
    }

    fn execute_v1(&self, calls: Vec<Call>) -> ExecutionV1<Self> {
        ExecutionV1::new(calls.clone(), self)
    }

    fn execute_v3(&self, calls: Vec<Call>) -> ExecutionV3<Self> {
        ExecutionV3::new(calls.clone(), self)
    }

    fn declare_v2(
        &self,
        contract_class: Arc<ContractClass<Felt>>,
        compiled_class_hash: Felt,
    ) -> DeclarationV2<Self> {
        DeclarationV2::new(contract_class, compiled_class_hash, self)
    }

    fn declare_v3(
        &self,
        contract_class: ContractClass<Felt>,
        compiled_class_hash: Felt,
    ) -> DeclarationV3<Self>
    where
        Self: Debug,
    {
        DeclarationV3::new(contract_class, compiled_class_hash, self)
    }
}

impl ConnectedAccount for StarkneHive {
    type Provider = JsonRpcClient<HttpTransport>;

    fn provider(&self) -> &Self::Provider {
        self.account.provider()
    }

    fn block_id(&self) -> BlockId<Felt> {
        BlockId::Tag(BlockTag::Pending)
    }

    async fn get_nonce(&self) -> Result<Felt, ProviderError> {
        self.provider()
            .get_nonce(self.block_id(), self.address())
            .await
    }
}
