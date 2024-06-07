use clap::Parser;
use starknet_crypto::FieldElement;

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[arg(long, short, env)]
    pub sender_address: FieldElement,
}
