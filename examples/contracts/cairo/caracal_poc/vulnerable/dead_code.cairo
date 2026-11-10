// GOOD: a component used only through its internal impl leaves the
// compiler-generated `unsafe_new_component_state::<...>` constructor
// uncalled. Like its sibling `unsafe_new_contract_state`, it is compiler
// plumbing, not user-written dead code.
#[starknet::component]
mod testcomp {
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};

    #[storage]
    pub struct Storage {
        pub value: felt252,
    }

    #[generate_trait]
    pub impl InternalImpl<
        TContractState, +HasComponent<TContractState>,
    > of InternalTrait<TContractState> {
        fn bump(ref self: ComponentState<TContractState>) {
            let v = self.value.read();
            self.value.write(v + 1);
        }
    }
}

#[starknet::contract]
mod DeadCode {
    use super::testcomp;
    use testcomp::InternalTrait;

    component!(path: testcomp, storage: comp, event: CompEvent);

    #[storage]
    struct Storage {
        #[substorage(v0)]
        comp: testcomp::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        CompEvent: testcomp::Event,
    }

    #[external(v0)]
    fn poke(ref self: ContractState) {
        self.comp.bump();
    }

    #[external(v0)]
    fn use_add_1(self: @ContractState, amount: felt252) -> felt252{
        add_1(amount)
    }

    fn add_1(amount: felt252) -> felt252 {
        amount + 1
    }

    // The compiler completely remove dead code at the sierra representation
    // so we can not correclty detect dead code as of now
    fn add_2(amount: felt252) -> felt252 {
        amount + 2
    }

}
