#[starknet::contract]
mod DeployContract {
    use starknet::class_hash::ClassHash;
    use starknet::syscalls::deploy_syscall;

    #[storage]
    struct Storage {
        implementation: ClassHash,
    }

    // BAD: the deployed class hash comes straight from calldata.
    #[external(v0)]
    fn bad_direct(ref self: ContractState, class_hash: ClassHash) {
        let calldata: Array<felt252> = array![];
        deploy_syscall(class_hash, 0, calldata.span(), false).unwrap();
    }

    // BAD: user-controlled class hash reaches deploy through a private
    // helper.
    #[external(v0)]
    fn bad_indirect(ref self: ContractState, class_hash: ClassHash) {
        let _pad = 2_u128; // keep the private helper from being fully inlined
        do_deploy(class_hash);
    }

    fn do_deploy(h: ClassHash) {
        let calldata: Array<felt252> = array![];
        deploy_syscall(h, 0, calldata.span(), false).unwrap();
    }

    // GOOD: the class hash is read from storage (operator-controlled); only
    // the salt is user controlled, which alone is not worth flagging.
    #[external(v0)]
    fn good_salt_only(ref self: ContractState, salt: felt252) {
        let h = self.implementation.read();
        let calldata: Array<felt252> = array![];
        deploy_syscall(h, salt, calldata.span(), false).unwrap();
    }
}
