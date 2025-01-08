use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;

// used in wait_for_tx. Txs will be fetched every 5s with timeout of 300s - so 60 attempts
pub const WAIT_TIMEOUT: u16 = 600;
pub const WAIT_RETRY_INTERVAL: u8 = 5;

pub struct Deploy {
    pub name: Option<String>,
    pub max_fee: Option<Felt>,
}
#[derive(Clone, Copy)]
pub struct WaitForTx {
    pub wait: bool,
    pub wait_params: ValidatedWaitParams,
}

#[derive(Deserialize, Serialize, Clone, Debug, Copy, PartialEq)]
pub struct ValidatedWaitParams {
    #[serde(default)]
    timeout: u16,

    #[serde(
        default,
        rename(serialize = "retry-interval", deserialize = "retry-interval")
    )]
    retry_interval: u8,
}

impl ValidatedWaitParams {
    #[must_use]
    pub fn new(retry_interval: u8, timeout: u16) -> Self {
        assert!(
            !(retry_interval == 0 || timeout == 0 || u16::from(retry_interval) > timeout),
            "Invalid values for retry_interval and/or timeout!"
        );

        Self {
            timeout,
            retry_interval,
        }
    }

    #[must_use]
    pub fn get_retries(&self) -> u16 {
        self.timeout / u16::from(self.retry_interval)
    }

    #[must_use]
    pub fn remaining_time(&self, steps_done: u16) -> u16 {
        steps_done * u16::from(self.retry_interval)
    }

    #[must_use]
    pub fn get_retry_interval(&self) -> u8 {
        self.retry_interval
    }

    #[must_use]
    pub fn get_timeout(&self) -> u16 {
        self.timeout
    }
}

impl Default for ValidatedWaitParams {
    fn default() -> Self {
        Self::new(WAIT_RETRY_INTERVAL, WAIT_TIMEOUT)
    }
}
