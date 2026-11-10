#[starknet::interface]
trait IERC20<T> {
    fn transfer(ref self: T, recipient: starknet::ContractAddress, amount: u256) -> bool;
    fn transfer_from(
        ref self: T,
        sender: starknet::ContractAddress,
        recipient: starknet::ContractAddress,
        amount: u256,
    ) -> bool;
    fn transferFrom(
        ref self: T,
        sender: starknet::ContractAddress,
        recipient: starknet::ContractAddress,
        amount: u256,
    ) -> bool;
}

#[starknet::contract]
mod UncheckedTransfer {
    use starknet::ContractAddress;
    use super::{IERC20Dispatcher, IERC20DispatcherTrait};

    #[storage]
    struct Storage {}

    // BAD: the transfer's boolean result is silently dropped — a token that
    // returns false on failure would leave this contract thinking the
    // transfer succeeded.
    #[external(v0)]
    fn bad_transfer(
        ref self: ContractState, token: ContractAddress, to: ContractAddress, amount: u256,
    ) {
        IERC20Dispatcher { contract_address: token }.transfer(to, amount);
    }

    // BAD: same for transfer_from.
    #[external(v0)]
    fn bad_transfer_from(
        ref self: ContractState,
        token: ContractAddress,
        sender: ContractAddress,
        to: ContractAddress,
        amount: u256,
    ) {
        IERC20Dispatcher { contract_address: token }.transfer_from(sender, to, amount);
    }

    // BAD: camelCase interfaces are matched too.
    #[external(v0)]
    fn bad_transfer_from_camel(
        ref self: ContractState,
        token: ContractAddress,
        sender: ContractAddress,
        to: ContractAddress,
        amount: u256,
    ) {
        IERC20Dispatcher { contract_address: token }.transferFrom(sender, to, amount);
    }

    // GOOD: the boolean result is checked.
    #[external(v0)]
    fn good_transfer(
        ref self: ContractState, token: ContractAddress, to: ContractAddress, amount: u256,
    ) {
        let success = IERC20Dispatcher { contract_address: token }.transfer(to, amount);
        assert(success, 'transfer failed');
    }

    // GOOD: the boolean result is propagated to the caller.
    #[external(v0)]
    fn good_transfer_propagated(
        ref self: ContractState,
        token: ContractAddress,
        sender: ContractAddress,
        to: ContractAddress,
        amount: u256,
    ) -> bool {
        IERC20Dispatcher { contract_address: token }.transfer_from(sender, to, amount)
    }
}
