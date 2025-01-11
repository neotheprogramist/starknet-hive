use crate::utils::v7::providers::provider::Provider;
use crate::utils::v7::signers::signer::Signer;

use starknet_types_core::felt::Felt;
use starknet_types_rpc::v0_7_1::{BlockId, BlockTag};

use super::{
    AccountFactory, PreparedAccountDeploymentV1, PreparedAccountDeploymentV3,
    RawAccountDeploymentV1, RawAccountDeploymentV3,
};

pub struct OpenZeppelinAccountFactory<S, P> {
    class_hash: Felt,
    chain_id: Felt,
    public_key: Felt,
    signer: S,
    provider: P,
    block_id: BlockId<Felt>,
}

impl<S, P> OpenZeppelinAccountFactory<S, P>
where
    S: Signer,
{
    pub async fn new(
        class_hash: Felt,
        chain_id: Felt,
        signer: S,
        provider: P,
    ) -> Result<Self, S::GetPublicKeyError> {
        let public_key = signer.get_public_key().await?;
        Ok(Self {
            class_hash,
            chain_id,
            public_key: public_key.scalar(),
            signer,
            provider,
            block_id: BlockId::Tag(BlockTag::Pending),
        })
    }

    pub fn set_block_id(&mut self, block_id: BlockId<Felt>) -> &Self {
        self.block_id = block_id;
        self
    }
}

impl<S, P> AccountFactory for OpenZeppelinAccountFactory<S, P>
where
    S: Signer + Sync + Send,
    P: Provider + Sync + Send,
{
    type Provider = P;
    type SignError = S::SignError;

    fn class_hash(&self) -> Felt {
        self.class_hash
    }

    fn calldata(&self) -> Vec<Felt> {
        vec![self.public_key]
    }

    fn chain_id(&self) -> Felt {
        self.chain_id
    }

    fn provider(&self) -> &Self::Provider {
        &self.provider
    }

    fn is_signer_interactive(&self) -> bool {
        self.signer.is_interactive()
    }

    fn block_id(&self) -> BlockId<Felt> {
        self.block_id.clone()
    }

    async fn sign_deployment_v1(
        &self,
        deployment: &RawAccountDeploymentV1,
        query_only: bool,
    ) -> Result<Vec<Felt>, Self::SignError> {
        let tx_hash = PreparedAccountDeploymentV1::from_raw(deployment.clone(), self)
            .transaction_hash(query_only);
        let signature = self.signer.sign_hash(&tx_hash).await?;

        Ok(vec![signature.r, signature.s])
    }

    async fn sign_deployment_v3(
        &self,
        deployment: &RawAccountDeploymentV3,
        _query_only: bool,
    ) -> Result<Vec<Felt>, Self::SignError> {
        let tx_hash =
            PreparedAccountDeploymentV3::from_raw(deployment.clone(), self).transaction_hash(false);
        let signature = self.signer.sign_hash(&tx_hash).await?;

        Ok(vec![signature.r, signature.s])
    }
}
