// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts for Cairo ^0.20.0

#[starknet::contract(account)]
mod MyAccountExec {
    use openzeppelin::account::AccountComponent;
    use openzeppelin::account::extensions::SRC9Component;
    use openzeppelin::introspection::src5::SRC5Component;

    component!(path: AccountComponent, storage: account, event: AccountEvent);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);
    component!(path: SRC9Component, storage: src9, event: SRC9Event);

    // External
    #[abi(embed_v0)]
    impl SRC6Impl = AccountComponent::SRC6Impl<ContractState>;
    #[abi(embed_v0)]
    impl SRC6CamelOnlyImpl = AccountComponent::SRC6CamelOnlyImpl<ContractState>;
    #[abi(embed_v0)]
    impl DeclarerImpl = AccountComponent::DeclarerImpl<ContractState>;
    #[abi(embed_v0)]
    impl DeployableImpl = AccountComponent::DeployableImpl<ContractState>;
    #[abi(embed_v0)]
    impl SRC5Impl = SRC5Component::SRC5Impl<ContractState>;
    #[abi(embed_v0)]
    impl OutsideExecutionV2Impl = SRC9Component::OutsideExecutionV2Impl<ContractState>;

    // Internal
    impl AccountInternalImpl = AccountComponent::InternalImpl<ContractState>;
    impl OutsideExecutionInternalImpl = SRC9Component::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        account: AccountComponent::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage,
        #[substorage(v0)]
        src9: SRC9Component::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        AccountEvent: AccountComponent::Event,
        #[flat]
        SRC5Event: SRC5Component::Event,
        #[flat]
        SRC9Event: SRC9Component::Event,
    }

    #[constructor]
    fn constructor(ref self: ContractState, public_key: felt252) {
        self.account.initializer(public_key);
        self.src9.initializer();
    }
}