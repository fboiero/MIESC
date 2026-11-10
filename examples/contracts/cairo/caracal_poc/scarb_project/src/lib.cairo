#[starknet::contract]
mod ScarbFixture {
    use starknet::storage::StoragePointerWriteAccess;

    #[storage]
    struct Storage {
        value: felt252,
    }

    // BAD: `unused` is never read — the unused-arguments detector must
    // report it WITH a source location, which only the in-process path
    // provides for Scarb projects.
    #[external(v0)]
    fn set_value(ref self: ContractState, v: felt252, unused: felt252) {
        self.value.write(v);
    }
}
