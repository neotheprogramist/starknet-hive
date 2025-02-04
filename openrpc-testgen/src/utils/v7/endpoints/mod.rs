pub mod declare_contract;
pub mod deploy_contract;
pub mod endpoints_functions;
pub mod errors;
pub mod utils;

use colored::*;
use endpoints_functions::{
    add_declare_transaction_v2, add_declare_transaction_v3, add_invoke_transaction_v1,
    add_invoke_transaction_v3, block_number, call, chain_id, estimate_message_fee,
    get_block_transaction_count, get_block_with_tx_hashes, get_block_with_txs, get_class,
    get_class_at, get_class_hash_at, get_state_update, get_storage_at,
    get_transaction_by_block_id_and_index, get_transaction_by_hash_deploy_acc,
    get_transaction_by_hash_invoke, get_transaction_by_hash_non_existent_tx,
    get_transaction_receipt, get_transaction_status_succeeded, invoke_contract_v1,
    invoke_contract_v3,
};
use errors::OpenRpcTestGenError;
use starknet_types_core::felt::Felt;
use starknet_types_rpc::{
    v0_7_1::{
        AddInvokeTransactionResult, BlockWithTxHashes, BlockWithTxs, ContractClass,
        DeployAccountTxnV3, InvokeTxnV1, StateUpdate, Txn, TxnStatus,
    },
    FeeEstimate, InvokeTxnReceipt,
};

use tracing::{error, info};
use url::Url;

pub struct Rpc {
    pub url: Url,
}

impl Rpc {
    #[allow(clippy::result_large_err)]
    pub fn new(url: Url) -> Result<Self, OpenRpcTestGenError> {
        Ok(Self { url })
    }
    pub fn set_url(&mut self, new_url: Url) {
        self.url = new_url;
    }
}

pub trait RpcEndpoints {
    // #[allow(clippy::too_many_arguments)]
    // fn invoke_contract_erc20_transfer(
    //     &self,
    //     sierra_path: &str,
    //     casm_path: &str,
    //     account_class_hash: Option<Felt>,
    //     account_address: Option<Felt>,
    //     private_key: Option<Felt>,
    //     erc20_strk_contract_address: Option<Felt>,
    //     erc20_eth_contract_address: Option<Felt>,
    //     amount_per_test: Option<Felt>,
    // ) -> impl std::future::Future<Output = Result<Felt, OpenRpcTestGenError>>;

    #[allow(clippy::too_many_arguments)]
    fn add_declare_transaction_v2(
        &self,
        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> impl std::future::Future<Output = Result<Felt, OpenRpcTestGenError>> + Send;

    #[allow(clippy::too_many_arguments)]
    fn add_declare_transaction_v3(
        &self,
        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> impl std::future::Future<Output = Result<Felt, OpenRpcTestGenError>> + Send;

    #[allow(clippy::too_many_arguments)]
    fn add_invoke_transaction_v1(
        &self,
        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> impl std::future::Future<Output = Result<AddInvokeTransactionResult<Felt>, OpenRpcTestGenError>>;

    #[allow(clippy::too_many_arguments)]
    fn add_invoke_transaction_v3(
        &self,
        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> impl std::future::Future<Output = Result<AddInvokeTransactionResult<Felt>, OpenRpcTestGenError>>;

    #[allow(clippy::too_many_arguments)]
    fn invoke_contract_v1(
        &self,
        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> impl std::future::Future<Output = Result<AddInvokeTransactionResult<Felt>, OpenRpcTestGenError>>;

    #[allow(clippy::too_many_arguments)]
    fn invoke_contract_v3(
        &self,
        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> impl std::future::Future<Output = Result<AddInvokeTransactionResult<Felt>, OpenRpcTestGenError>>;

    fn block_number(&self) -> impl std::future::Future<Output = Result<u64, OpenRpcTestGenError>>;

    fn chain_id(&self) -> impl std::future::Future<Output = Result<Felt, OpenRpcTestGenError>>;

    #[allow(clippy::too_many_arguments)]
    fn call(
        &self,
        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> impl std::future::Future<Output = Result<Vec<Felt>, OpenRpcTestGenError>>;

    #[allow(clippy::too_many_arguments)]
    fn estimate_message_fee(
        &self,
        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> impl std::future::Future<Output = Result<FeeEstimate<Felt>, OpenRpcTestGenError>>;

    fn get_block_transaction_count(
        &self,
    ) -> impl std::future::Future<Output = Result<u64, OpenRpcTestGenError>>;

    fn get_block_with_tx_hashes(
        &self,
    ) -> impl std::future::Future<Output = Result<BlockWithTxHashes<Felt>, OpenRpcTestGenError>>;

    fn get_block_with_txs(
        &self,
    ) -> impl std::future::Future<Output = Result<BlockWithTxs<Felt>, OpenRpcTestGenError>>;

    fn get_state_update(
        &self,
    ) -> impl std::future::Future<Output = Result<StateUpdate<Felt>, OpenRpcTestGenError>>;

    fn get_storage_at(
        &self,
        erc20_eth_contract_address: Option<Felt>,
    ) -> impl std::future::Future<Output = Result<Felt, OpenRpcTestGenError>>;

    #[allow(clippy::too_many_arguments)]
    fn get_transaction_status_succeeded(
        &self,
        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> impl std::future::Future<Output = Result<TxnStatus, OpenRpcTestGenError>>;

    #[allow(clippy::too_many_arguments)]
    fn get_transaction_by_hash_invoke(
        &self,
        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> impl std::future::Future<Output = Result<InvokeTxnV1<Felt>, OpenRpcTestGenError>>;

    #[allow(clippy::too_many_arguments)]
    fn get_transaction_by_hash_deploy_acc(
        &self,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> impl std::future::Future<Output = Result<DeployAccountTxnV3<Felt>, OpenRpcTestGenError>>;

    #[allow(clippy::too_many_arguments)]
    fn get_transaction_by_block_id_and_index(
        &self,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> impl std::future::Future<Output = Result<Txn<Felt>, OpenRpcTestGenError>>;

    fn get_transaction_by_hash_non_existent_tx(
        &self,
    ) -> impl std::future::Future<Output = Result<(), OpenRpcTestGenError>>;

    #[allow(clippy::too_many_arguments)]
    fn get_transaction_receipt(
        &self,
        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> impl std::future::Future<Output = Result<InvokeTxnReceipt<Felt>, OpenRpcTestGenError>>;

    // TODO: fix that
    // async fn get_transaction_receipt_revert(
    //     &self,
    //     url: Url,
    //     sierra_path: &str,
    //     casm_path: &str,
    //     account_class_hash: Option<Felt>,
    //     account_address: Option<Felt>,
    //     private_key: Option<Felt>,
    //     erc20_strk_contract_address: Option<Felt>,
    //     erc20_eth_contract_address: Option<Felt>,
    //     amount_per_test: Option<Felt>,
    // ) -> Result<(), OpenRpcTestGenError>;

    #[allow(clippy::too_many_arguments)]
    fn get_class(
        &self,
        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> impl std::future::Future<Output = Result<ContractClass<Felt>, OpenRpcTestGenError>>;

    #[allow(clippy::too_many_arguments)]
    fn get_class_hash_at(
        &self,
        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> impl std::future::Future<Output = Result<Felt, OpenRpcTestGenError>>;

    #[allow(clippy::too_many_arguments)]
    fn get_class_at(
        &self,
        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> impl std::future::Future<Output = Result<ContractClass<Felt>, OpenRpcTestGenError>>;
}

impl RpcEndpoints for Rpc {
    // async fn invoke_contract_erc20_transfer(
    //     &self,
    //     sierra_path: &str,
    //     casm_path: &str,
    //     account_class_hash: Option<Felt>,
    //     account_address: Option<Felt>,
    //     private_key: Option<Felt>,
    //     erc20_strk_contract_address: Option<Felt>,
    //     erc20_eth_contract_address: Option<Felt>,
    //     amount_per_test: Option<Felt>,
    // ) -> Result<Felt, OpenRpcTestGenError> {
    //     invoke_contract_erc20_transfer(
    //         self.url.clone(),
    //         sierra_path,
    //         casm_path,
    //         account_class_hash,
    //         account_address,
    //         private_key,
    //         erc20_strk_contract_address,
    //         erc20_eth_contract_address,
    //         amount_per_test,
    //     )
    //     .await
    // }

    async fn add_declare_transaction_v2(
        &self,
        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> Result<Felt, OpenRpcTestGenError> {
        add_declare_transaction_v2(
            self.url.clone(),
            sierra_path,
            casm_path,
            account_class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    }

    async fn add_declare_transaction_v3(
        &self,
        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> Result<Felt, OpenRpcTestGenError> {
        add_declare_transaction_v3(
            self.url.clone(),
            sierra_path,
            casm_path,
            account_class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    }

    async fn add_invoke_transaction_v1(
        &self,
        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> Result<AddInvokeTransactionResult<Felt>, OpenRpcTestGenError> {
        add_invoke_transaction_v1(
            self.url.clone(),
            sierra_path,
            casm_path,
            account_class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    }

    async fn add_invoke_transaction_v3(
        &self,
        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> Result<AddInvokeTransactionResult<Felt>, OpenRpcTestGenError> {
        add_invoke_transaction_v3(
            self.url.clone(),
            sierra_path,
            casm_path,
            account_class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    }

    async fn invoke_contract_v1(
        &self,
        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> Result<AddInvokeTransactionResult<Felt>, OpenRpcTestGenError> {
        invoke_contract_v1(
            self.url.clone(),
            sierra_path,
            casm_path,
            account_class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    }

    async fn invoke_contract_v3(
        &self,
        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> Result<AddInvokeTransactionResult<Felt>, OpenRpcTestGenError> {
        invoke_contract_v3(
            self.url.clone(),
            sierra_path,
            casm_path,
            account_class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    }

    async fn block_number(&self) -> Result<u64, OpenRpcTestGenError> {
        block_number(self.url.clone()).await
    }

    async fn chain_id(&self) -> Result<Felt, OpenRpcTestGenError> {
        chain_id(self.url.clone()).await
    }

    async fn call(
        &self,
        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> Result<Vec<Felt>, OpenRpcTestGenError> {
        call(
            self.url.clone(),
            sierra_path,
            casm_path,
            account_class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    }

    async fn estimate_message_fee(
        &self,
        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> Result<FeeEstimate<Felt>, OpenRpcTestGenError> {
        estimate_message_fee(
            self.url.clone(),
            sierra_path,
            casm_path,
            account_class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    }

    async fn get_block_transaction_count(&self) -> Result<u64, OpenRpcTestGenError> {
        get_block_transaction_count(self.url.clone()).await
    }

    async fn get_block_with_tx_hashes(
        &self,
    ) -> Result<BlockWithTxHashes<Felt>, OpenRpcTestGenError> {
        get_block_with_tx_hashes(self.url.clone()).await
    }

    async fn get_block_with_txs(&self) -> Result<BlockWithTxs<Felt>, OpenRpcTestGenError> {
        get_block_with_txs(self.url.clone()).await
    }

    async fn get_state_update(&self) -> Result<StateUpdate<Felt>, OpenRpcTestGenError> {
        get_state_update(self.url.clone()).await
    }

    async fn get_storage_at(
        &self,

        erc20_eth_contract_address: Option<Felt>,
    ) -> Result<starknet_types_core::felt::Felt, OpenRpcTestGenError> {
        get_storage_at(self.url.clone(), erc20_eth_contract_address).await
    }

    async fn get_transaction_status_succeeded(
        &self,

        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> Result<TxnStatus, OpenRpcTestGenError> {
        get_transaction_status_succeeded(
            self.url.clone(),
            sierra_path,
            casm_path,
            account_class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    }

    async fn get_transaction_by_hash_invoke(
        &self,
        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> Result<InvokeTxnV1<Felt>, OpenRpcTestGenError> {
        get_transaction_by_hash_invoke(
            self.url.clone(),
            sierra_path,
            casm_path,
            account_class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    }

    async fn get_transaction_by_hash_deploy_acc(
        &self,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> Result<DeployAccountTxnV3<Felt>, OpenRpcTestGenError> {
        get_transaction_by_hash_deploy_acc(
            self.url.clone(),
            account_class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    }

    async fn get_transaction_by_block_id_and_index(
        &self,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> Result<Txn<Felt>, OpenRpcTestGenError> {
        get_transaction_by_block_id_and_index(
            self.url.clone(),
            account_class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    }

    async fn get_transaction_by_hash_non_existent_tx(&self) -> Result<(), OpenRpcTestGenError> {
        get_transaction_by_hash_non_existent_tx(self.url.clone()).await
    }

    async fn get_transaction_receipt(
        &self,

        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> Result<InvokeTxnReceipt<Felt>, OpenRpcTestGenError> {
        get_transaction_receipt(
            self.url.clone(),
            sierra_path,
            casm_path,
            account_class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    }
    // TODO: fix that
    // async fn get_transaction_receipt_revert(
    //     &self,
    //     url: Url,
    //     sierra_path: &str,
    //     casm_path: &str,
    //     account_class_hash: Option<Felt>,
    //     account_address: Option<Felt>,
    //     private_key: Option<Felt>,
    //     erc20_strk_contract_address: Option<Felt>,
    //     erc20_eth_contract_address: Option<Felt>,
    //     amount_per_test: Option<Felt>,
    // ) -> Result<(), OpenRpcTestGenError> {
    //     get_transaction_receipt_revert(
    //         url.clone(),
    //         sierra_path,
    //         casm_path,
    //         account_class_hash,
    //         account_address,
    //         private_key,
    //         erc20_strk_contract_address,
    //         erc20_eth_contract_address,
    //         amount_per_test,
    //     )
    //     .await
    // }

    async fn get_class(
        &self,

        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> Result<ContractClass<Felt>, OpenRpcTestGenError> {
        get_class(
            self.url.clone(),
            sierra_path,
            casm_path,
            account_class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    }

    async fn get_class_hash_at(
        &self,

        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> Result<Felt, OpenRpcTestGenError> {
        get_class_hash_at(
            self.url.clone(),
            sierra_path,
            casm_path,
            account_class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    }

    async fn get_class_at(
        &self,

        sierra_path: &str,
        casm_path: &str,
        account_class_hash: Option<Felt>,
        account_address: Option<Felt>,
        private_key: Option<Felt>,
        erc20_strk_contract_address: Option<Felt>,
        erc20_eth_contract_address: Option<Felt>,
        amount_per_test: Option<Felt>,
    ) -> Result<ContractClass<Felt>, OpenRpcTestGenError> {
        get_class_at(
            self.url.clone(),
            sierra_path,
            casm_path,
            account_class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn test_rpc_endpoints_v0_0_7(
    url: Url,
    sierra_path: &str,
    casm_path: &str,
    sierra_path_2: &str,
    casm_path_2: &str,
    class_hash: Option<Felt>,
    account_address: Option<Felt>,
    private_key: Option<Felt>,
    erc20_strk_contract_address: Option<Felt>,
    erc20_eth_contract_address: Option<Felt>,
    amount_per_test: Option<Felt>,
) -> Result<(), OpenRpcTestGenError> {
    info!("{}", "⌛ Testing Rpc V7 endpoints -- START ⌛".yellow());

    let rpc = Rpc::new(url.clone())?;
    // match rpc
    //     .invoke_contract_erc20_transfer(
    //         sierra_path,
    //         casm_path,
    //         class_hash,
    //         account_address,
    //         private_key,
    //         erc20_strk_contract_address,
    //         erc20_eth_contract_address,
    //         amount_per_test,
    //     )
    //     .await
    // {
    //     Ok(_) => {
    //         info!(
    //             "{} {}",
    //             "\n✓ Rpc Test paymaster via invoke erc20 transfer COMPATIBLE".green(),
    //             "✓".green()
    //         )
    //     }
    //     Err(e) => error!(
    //         "{} {} {}",
    //         "✗ Rpc Test paymaster via invoke erc20 transfer INCOMPATIBLE:".red(),
    //         e.to_string().red(),
    //         "✗".red()
    //     ),
    // }

    match rpc
        .add_declare_transaction_v2(
            sierra_path,
            casm_path,
            class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    {
        Ok(_) => {
            info!(
                "{} {}",
                "\n✓ Rpc add_declare_transaction V2 COMPATIBLE".green(),
                "✓".green()
            )
        }
        Err(e) => error!(
            "{} {} {}",
            "✗ Rpc add_declare_transaction V2 INCOMPATIBLE:".red(),
            e.to_string().red(),
            "✗".red()
        ),
    }

    match rpc
        .add_declare_transaction_v3(
            sierra_path_2,
            casm_path_2,
            class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    {
        Ok(_) => {
            info!(
                "{} {}",
                "\n✓ Rpc add_declare_transaction V3 COMPATIBLE".green(),
                "✓".green()
            )
        }
        Err(e) => error!(
            "{} {} {}",
            "✗ Rpc add_declare_transaction V3 INCOMPATIBLE:".red(),
            e.to_string().red(),
            "✗".red()
        ),
    }

    match rpc
        .add_invoke_transaction_v1(
            sierra_path,
            casm_path,
            class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    {
        Ok(_) => {
            info!(
                "{} {}",
                "\n✓ Rpc add_invoke_transaction V1 COMPATIBLE".green(),
                "✓".green()
            )
        }
        Err(e) => error!(
            "{} {} {}",
            "✗ Rpc add_invoke_transaction V1 INCOMPATIBLE:".red(),
            e.to_string().red(),
            "✗".red()
        ),
    }

    match rpc
        .add_invoke_transaction_v3(
            sierra_path,
            casm_path,
            class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    {
        Ok(_) => {
            info!(
                "{} {}",
                "\n✓ Rpc add_invoke_transaction V3 COMPATIBLE".green(),
                "✓".green()
            )
        }
        Err(e) => error!(
            "{} {} {}",
            "✗ Rpc add_invoke_transaction V3 INCOMPATIBLE:".red(),
            e.to_string().red(),
            "✗".red()
        ),
    }

    match rpc
        .invoke_contract_v1(
            sierra_path,
            casm_path,
            class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    {
        Ok(_) => {
            info!(
                "{} {}",
                "\n✓ Rpc invoke_contract V1 COMPATIBLE".green(),
                "✓".green()
            )
        }
        Err(e) => error!(
            "{} {} {}",
            "✗ Rpc invoke_contract V1 INCOMPATIBLE:".red(),
            e.to_string().red(),
            "✗".red()
        ),
    }

    match rpc
        .invoke_contract_v3(
            sierra_path,
            casm_path,
            class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    {
        Ok(_) => {
            info!(
                "{} {}",
                "\n✓ Rpc invoke_contract V3 COMPATIBLE".green(),
                "✓".green()
            )
        }
        Err(e) => error!(
            "{} {} {}",
            "✗ Rpc invoke_contract V3 INCOMPATIBLE:".red(),
            e.to_string().red(),
            "✗".red()
        ),
    }

    match rpc.block_number().await {
        Ok(_) => {
            info!(
                "{} {}",
                "\n✓ Rpc block_number COMPATIBLE".green(),
                "✓".green()
            )
        }
        Err(e) => error!(
            "{} {} {}",
            "✗ Rpc block_number INCOMPATIBLE:".red(),
            e.to_string().red(),
            "✗".red()
        ),
    }

    match rpc.chain_id().await {
        Ok(_) => {
            info!("{} {}", "\n✓ Rpc chain_id COMPATIBLE".green(), "✓".green())
        }
        Err(e) => error!(
            "{} {} {}",
            "✗ Rpc chain_id INCOMPATIBLE:".red(),
            e.to_string().red(),
            "✗".red()
        ),
    }

    match rpc
        .call(
            sierra_path,
            casm_path,
            class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    {
        Ok(_) => {
            info!("{} {}", "\n✓ Rpc call COMPATIBLE".green(), "✓".green())
        }
        Err(e) => error!(
            "{} {} {}",
            "✗ Rpc call INCOMPATIBLE:".red(),
            e.to_string().red(),
            "✗".red()
        ),
    }

    match rpc
        .estimate_message_fee(
            sierra_path,
            casm_path,
            class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    {
        Ok(_) => {
            info!(
                "{} {}",
                "\n✓ Rpc estimate_message_fee COMPATIBLE".green(),
                "✓".green()
            )
        }
        Err(e) => error!(
            "{} {} {}",
            "✗ Rpc estimate_message_fee INCOMPATIBLE:".red(),
            e.to_string().red(),
            "✗".red()
        ),
    }
    match rpc.get_block_transaction_count().await {
        Ok(_) => {
            info!(
                "{} {}",
                "\n✓ Rpc get_block_transaction_count COMPATIBLE".green(),
                "✓".green()
            )
        }
        Err(e) => error!(
            "{} {} {}",
            "✗ Rpc get_block_transaction_count INCOMPATIBLE:".red(),
            e.to_string().red(),
            "✗".red()
        ),
    }
    match rpc.get_block_with_tx_hashes().await {
        Ok(_) => {
            info!(
                "{} {}",
                "\n✓ Rpc get_block_with_tx_hashes COMPATIBLE".green(),
                "✓".green()
            )
        }
        Err(e) => error!(
            "{} {} {}",
            "✗ Rpc get_block_with_tx_hashes INCOMPATIBLE:".red(),
            e.to_string().red(),
            "✗".red()
        ),
    }

    match rpc.get_block_with_txs().await {
        Ok(_) => {
            info!(
                "{} {}",
                "\n✓ Rpc get_block_with_txs COMPATIBLE".green(),
                "✓".green()
            )
        }
        Err(e) => error!(
            "{} {} {}",
            "✗ Rpc get_block_with_txs INCOMPATIBLE:".red(),
            e.to_string().red(),
            "✗".red()
        ),
    }

    match rpc.get_state_update().await {
        Ok(_) => {
            info!(
                "{} {}",
                "\n✓ Rpc get_state_update COMPATIBLE".green(),
                "✓".green()
            )
        }
        Err(e) => error!(
            "{} {} {}",
            "✗ Rpc get_state_update INCOMPATIBLE:".red(),
            e.to_string().red(),
            "✗".red()
        ),
    }

    match rpc.get_storage_at(erc20_eth_contract_address).await {
        Ok(_) => {
            info!(
                "{} {}",
                "\n✓ Rpc get_storage_at COMPATIBLE".green(),
                "✓".green()
            )
        }
        Err(e) => error!(
            "{} {} {}",
            "✗ Rpc get_storage_at INCOMPATIBLE:".red(),
            e.to_string().red(),
            "✗".red()
        ),
    }

    match rpc
        .get_transaction_status_succeeded(
            sierra_path,
            casm_path,
            class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    {
        Ok(_) => {
            info!(
                "{} {}",
                "\n✓ Rpc get_transaction_status_succeeded COMPATIBLE".green(),
                "✓".green()
            )
        }
        Err(e) => error!(
            "{} {} {}",
            "✗ Rpc get_transaction_status_succeeded INCOMPATIBLE:".red(),
            e.to_string().red(),
            "✗".red()
        ),
    }

    match rpc
        .get_transaction_by_hash_invoke(
            sierra_path,
            casm_path,
            class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    {
        Ok(_) => {
            info!(
                "{} {}",
                "\n✓ Rpc get_transaction_by_hash_invoke COMPATIBLE".green(),
                "✓".green()
            )
        }
        Err(e) => error!(
            "{} {} {}",
            "✗ Rpc get_transaction_by_hash_invoke INCOMPATIBLE:".red(),
            e.to_string().red(),
            "✗".red()
        ),
    }

    match rpc
        .get_transaction_by_hash_deploy_acc(
            class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    {
        Ok(_) => {
            info!(
                "{} {}",
                "\n✓ Rpc get_transaction_by_hash_deploy_acc COMPATIBLE".green(),
                "✓".green()
            )
        }
        Err(e) => error!(
            "{} {} {}",
            "✗ Rpc get_transaction_by_hash_deploy_acc INCOMPATIBLE:".red(),
            e.to_string().red(),
            "✗".red()
        ),
    }

    match rpc
        .get_transaction_by_block_id_and_index(
            class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    {
        Ok(_) => {
            info!(
                "{} {}",
                "\n✓ Rpc get_transaction_by_block_id_and_index COMPATIBLE".green(),
                "✓".green()
            )
        }
        Err(e) => error!(
            "{} {} {}",
            "✗ Rpc get_transaction_by_block_id_and_index INCOMPATIBLE:".red(),
            e.to_string().red(),
            "✗".red()
        ),
    }

    match rpc.get_transaction_by_hash_non_existent_tx().await {
        Ok(_) => {
            info!(
                "{} {}",
                "\n✓ Rpc get_transaction_by_hash_non_existent_tx COMPATIBLE".green(),
                "✓".green()
            )
        }
        Err(e) => error!(
            "{} {} {}",
            "✗ Rpc get_transaction_by_hash_non_existent_tx INCOMPATIBLE:".red(),
            e.to_string().red(),
            "✗".red()
        ),
    }

    match rpc
        .get_transaction_receipt(
            sierra_path,
            casm_path,
            class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    {
        Ok(_) => {
            info!(
                "{} {}",
                "\n✓ Rpc get_transaction_receipt COMPATIBLE".green(),
                "✓".green()
            )
        }
        Err(e) => error!(
            "{} {} {}",
            "✗ Rpc get_transaction_receipt INCOMPATIBLE:".red(),
            e.to_string().red(),
            "✗".red()
        ),
    }

    // match rpc
    //     .get_transaction_receipt_revert(
    //         url.clone(),
    //         sierra_path,
    //         casm_path,
    //         class_hash,
    //         account_address,
    //         private_key,
    //         erc20_strk_contract_address,
    //         erc20_eth_contract_address,
    //         amount_per_test,
    //     )
    //     .await
    // {
    //     Ok(_) => {
    //         info!(
    //             "{} {}",
    //             "\n✓ Rpc get_transaction_receipt_revert COMPATIBLE".green(),
    //             "✓".green()
    //         )
    //     }
    //     Err(e) => error!(
    //         "{} {} {}",
    //         "✗ Rpc get_transaction_receipt_revert INCOMPATIBLE:".red(),
    //         e.to_string().red(),
    //         "✗".red()
    //     ),
    // }

    match rpc
        .get_class(
            sierra_path,
            casm_path,
            class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    {
        Ok(_) => {
            info!("{} {}", "\n✓ Rpc get_class COMPATIBLE".green(), "✓".green())
        }
        Err(e) => error!(
            "{} {} {}",
            "✗ Rpc get_class INCOMPATIBLE:".red(),
            e.to_string().red(),
            "✗".red()
        ),
    }

    match rpc
        .get_class_hash_at(
            sierra_path,
            casm_path,
            class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    {
        Ok(_) => {
            info!(
                "{} {}",
                "\n✓ Rpc get_class_hash_at COMPATIBLE".green(),
                "✓".green()
            )
        }
        Err(e) => error!(
            "{} {} {}",
            "✗ Rpc get_class_hash_at INCOMPATIBLE:".red(),
            e,
            "✗".red()
        ),
    }

    match rpc
        .get_class_at(
            sierra_path,
            casm_path,
            class_hash,
            account_address,
            private_key,
            erc20_strk_contract_address,
            erc20_eth_contract_address,
            amount_per_test,
        )
        .await
    {
        Ok(_) => {
            info!(
                "{} {}",
                "\n✓ Rpc get_class_at COMPATIBLE".green(),
                "✓".green()
            )
        }
        Err(e) => error!(
            "{} {}",
            "✗ Rpc get_class_at INCOMPATIBLE:".red(),
            e.to_string().red(),
        ),
    }

    info!("{}", "🏁 Testing Devnet V7 endpoints -- END 🏁".yellow());

    Ok(())
}
