use array::ArrayTrait;

// GOOD: monomorphized generic function — its path carries a turbofish
// (`unused_arguments::generic_unused::<...>`), the shape of library default
// impls and macro plumbing, which are out of the detector's scope.
fn generic_unused<T, +Drop<T>>(a: T, b: felt252) -> felt252 {
    b + 1
}

#[starknet::interface]
trait ITestComponent<TState> {
    fn get(self: @TState) -> felt252;
}

// GOOD: the `#[starknet::component]` / `component!` macros generate glue
// (`HasComponentImpl_*::get_contract`, `ComponentStateDeref::<...>::deref`)
// whose intentionally-unused parameters are not user code.
#[starknet::component]
mod testcomp {
    #[storage]
    pub struct Storage {
        pub value: felt252,
    }

    #[embeddable_as(TestImpl)]
    pub impl Test<
        TContractState, +HasComponent<TContractState>,
    > of super::ITestComponent<ComponentState<TContractState>> {
        fn get(self: @ComponentState<TContractState>) -> felt252 {
            1
        }
    }
}

#[starknet::contract]
mod UnusedArguments {
    use super::testcomp;

    component!(path: testcomp, storage: comp, event: CompEvent);

    #[storage]
    struct Storage {
        value: felt252,
        #[substorage(v0)]
        comp: testcomp::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        CompEvent: testcomp::Event,
    }

    #[abi(embed_v0)]
    impl TestImpl = testcomp::TestImpl<ContractState>;

    #[external(v0)]
    fn unused_1(ref self: ContractState, a: felt252, b: felt252) {
        self.value.write(a);
    }

    #[external(v0)]
    fn unused_2(self: @ContractState, array: Array::<felt252>, l: felt252) -> felt252{
        let _a = 1; // Need this otherwise the function is optimized away and put directly in the wrapper
        1
    }

    // GOOD: `helper` never touches its snapshot self — the state parameter is
    // mandated by the receiver syntax, ignoring it is not a bug.
    #[external(v0)]
    fn call_helper(ref self: ContractState) {
        let x = helper(@self, 3);
        self.value.write(x);
    }

    fn helper(self: @ContractState, x: felt252) -> felt252 {
        x + 1
    }

    // GOOD: instantiates the generic function above; the monomorphized
    // instance ignores `a` but is not user-written contract code.
    #[external(v0)]
    fn call_generic(ref self: ContractState) {
        self.value.write(super::generic_unused(5_u128, 7));
    }

    // GOOD: `comp_helper` never touches its component-state snapshot self —
    // same self exemption as `helper` but for `ComponentState`.
    #[external(v0)]
    fn call_comp_helper(ref self: ContractState) {
        let comp = testcomp::HasComponent::get_component(@self);
        self.value.write(comp_helper(comp, 3));
    }

    // GOOD: an empty function is a stub/hook conformance (e.g. a hooks-trait
    // method left with its empty default body); its arguments are ignored by
    // design, not by accident.
    #[external(v0)]
    fn call_empty_hook(ref self: ContractState) {
        empty_hook(ref self, 1, 2);
    }

    fn empty_hook(ref self: ContractState, from: felt252, to: felt252) {}

    fn comp_helper(
        self: @testcomp::ComponentState<ContractState>, x: felt252,
    ) -> felt252 {
        x + 2
    }
}
