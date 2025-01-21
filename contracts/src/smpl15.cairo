#[starknet::interface]
pub trait IHelloStarknet<TContractState> {
    fn increase_balance(ref self: TContractState, amount: felt252);
    fn get_balance(self: @TContractState) -> felt252;
}

#[starknet::contract]
mod HelloStarknet {
    use starknet::storage::Map;

    #[storage]
    struct Storage {
        balance: felt252,
        balances: Map<felt252, felt252>,
        another_arg6: felt252,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        DepositFromL1: DepositFromL1,
    }

    #[derive(Drop, starknet::Event)]
    struct DepositFromL1 {
        #[key]
        user: felt252,
        #[key]
        amount: felt252,
    }

    #[l1_handler]
    fn deposit(ref self: ContractState, from_address: felt252, user: felt252, amount: felt252) {
        let balance = self.balances.read(user);
        self.balances.write(user, balance + amount);
        self.emit(DepositFromL1 { user, amount });
    }

    #[abi(embed_v0)]
    impl HelloStarknetImpl of super::IHelloStarknet<ContractState> {
        fn increase_balance(ref self: ContractState, amount: felt252) {
            self.balance.write(self.balance.read() + amount);
        }

        fn get_balance(self: @ContractState) -> felt252 {
            self.balance.read()
        }
    }
}
