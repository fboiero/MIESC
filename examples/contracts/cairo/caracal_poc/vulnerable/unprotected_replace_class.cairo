#[starknet::contract]
mod UnprotectedReplaceClass {
    use starknet::class_hash::ClassHash;
    use starknet::syscalls::replace_class_syscall;
    use starknet::{ContractAddress, get_caller_address};

    #[storage]
    struct Storage {
        owner: ContractAddress,
        pending_implementation: ClassHash,
    }

    // BAD: anyone can trigger the class replacement, even though the hash
    // itself is operator-controlled (read from storage).
    #[external(v0)]
    fn bad_upgrade(ref self: ContractState) {
        let h = self.pending_implementation.read();
        replace_class_syscall(h).unwrap();
    }

    // BAD: the syscall is reached through a private helper and no caller
    // check happens anywhere on the path.
    #[external(v0)]
    fn bad_upgrade_indirect(ref self: ContractState) {
        let _pad = 2_u128; // keep the private helper from being fully inlined
        do_upgrade(ref self);
    }

    fn do_upgrade(ref self: ContractState) {
        let h = self.pending_implementation.read();
        replace_class_syscall(h).unwrap();
    }

    // GOOD: the caller is checked against the stored owner before upgrading.
    #[external(v0)]
    fn good_upgrade(ref self: ContractState) {
        assert(get_caller_address() == self.owner.read(), 'not owner');
        let h = self.pending_implementation.read();
        replace_class_syscall(h).unwrap();
    }

    // GOOD: the caller check lives in a private helper (modifier style).
    #[external(v0)]
    fn good_upgrade_guarded(ref self: ContractState) {
        assert_only_owner(@self);
        let h = self.pending_implementation.read();
        replace_class_syscall(h).unwrap();
    }

    fn assert_only_owner(self: @ContractState) {
        assert(get_caller_address() == self.owner.read(), 'not owner');
    }

    // GOOD: externally reachable but never reaches replace_class.
    #[external(v0)]
    fn good_unrelated(ref self: ContractState, owner: ContractAddress) {
        self.owner.write(owner);
    }
}
