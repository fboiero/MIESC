// VulnerableVault.cairo
// Intentionally vulnerable Starknet contract for testing MIESC Cairo analyzer.
// DO NOT USE IN PRODUCTION.

#[starknet::contract]
mod VulnerableVault {
    use starknet::{ContractAddress, get_caller_address};
    use starknet::syscalls::replace_class_syscall;

    #[storage]
    struct Storage {
        owner: ContractAddress,
        balances: LegacyMap<ContractAddress, felt252>,
        total_supply: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner_: ContractAddress) {
        self.owner.write(owner_);
    }

    // Vulnerability: external function without access control
    #[external]
    fn mint(ref self: ContractState, amount: felt252, to: ContractAddress) {
        // No owner check! Anyone can mint.
        let current = self.balances.read(to);
        // Felt overflow risk: no bound checks
        self.balances.write(to, current + amount);
        self.total_supply.write(self.total_supply.read() + amount);
    }

    // Vulnerability: caller not validated before privileged action
    #[external]
    fn withdraw(ref self: ContractState, amount: felt252) {
        let caller = get_caller_address();
        let balance = self.balances.read(caller);
        // External call before state update = reentrancy risk
        self.balances.write(caller, balance - amount);
    }

    // Vulnerability: L1 handler without validating from_address
    #[l1_handler]
    fn on_receive_from_l1(ref self: ContractState, from_address: felt252, amount: felt252) {
        // Should check from_address but doesn't
        self.total_supply.write(self.total_supply.read() + amount);
    }

    // Vulnerability: unprotected class replacement
    #[external]
    fn upgrade(ref self: ContractState, new_class_hash: starknet::ClassHash) {
        // Should check caller == owner but doesn't
        replace_class_syscall(new_class_hash);
    }
}
