pub mod args;
pub mod txn_hashes;
pub mod txn_validation;
use args::Args;
use clap::Parser;
use txn_validation::validate::validate_txn_json;

fn main() {
    let args = Args::parse();
    match validate_txn_json(&args.file_path, args.public_key.as_deref(), &args.chain_id) {
        Ok(json_result) => {
            println!("Validation successful: {}", json_result);
        }
        Err(e) => {
            println!("Validation error: {}", e);
        }
    }
}
