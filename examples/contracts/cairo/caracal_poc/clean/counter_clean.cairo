// A deliberately clean Starknet contract: storage with a read-only view, no
// external state changes, no syscalls. Negative fixture (expected: zero findings).
#[starknet::interface]
trait ICounter<TContractState> {
    fn get(self: @TContractState) -> u128;
}

#[starknet::contract]
mod Counter {
    #[storage]
    struct Storage {
        value: u128,
    }

    #[abi(embed_v0)]
    impl CounterImpl of super::ICounter<ContractState> {
        fn get(self: @ContractState) -> u128 {
            self.value.read()
        }
    }
}
