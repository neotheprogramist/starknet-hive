# starknet-rpc-tests

Development Setup Instructions

## Starting the Development Network

To start the development network (Devnet) with a specific seed, run the following command:

```bash
starknet-devnet --seed 0
```

Running Tests
After starting the Devnet, you can run your tests using cargo. Execute the following command:

```bash
cargo test
```

Running a Specific Test
If you want to run a specific test, such as jsonrpc_add_declare_transaction, use the following command:


```bash
cargo test jsonrpc_add_declare_transaction -- --nocapture
```
