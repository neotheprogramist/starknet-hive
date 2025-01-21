#[starknet::interface]
pub trait IHelloStarknet<TContractState> {
    fn increase_balance(ref self: TContractState, amount: felt252);
    fn decrease_balance(ref self: TContractState, amount: felt252);
    fn get_balance(self: @TContractState) -> felt252;
    fn get_extra_data(self: @TContractState) -> felt252;
    fn get_extra_data_2(self: @TContractState) -> felt252;
    fn get_extra_data_3(self: @TContractState) -> felt252;
    fn get_sample_6(self: @TContractState) -> felt252;
}

#[starknet::contract]
mod HelloStarknet {
    use starknet::storage::Map;

    #[storage]
    struct Storage {
        balance: felt252,
        balances: Map<felt252, felt252>,
        extra_data: felt252,
        extra_data_2: felt252,
        extra_data_3: felt252,
        sample_6: felt252,
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

        fn decrease_balance(ref self: ContractState, amount: felt252) {
            self.balance.write(self.balance.read() - amount);
        }

        fn get_balance(self: @ContractState) -> felt252 {
            self.balance.read()
        }

        fn get_extra_data(self: @ContractState) -> felt252 {
            self.extra_data.read()
        }

        fn get_extra_data_2(self: @ContractState) -> felt252 {
            self.extra_data_2.read()
        }
        fn get_extra_data_3(self: @ContractState) -> felt252 {
            self.extra_data_3.read()
        }
        fn get_sample_6(self: @ContractState) -> felt252 {
            self.sample_6.read()
        }
    }
}
