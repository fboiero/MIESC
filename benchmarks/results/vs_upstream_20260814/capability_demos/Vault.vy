# @version 0.3.7

owner: public(address)
balances: public(HashMap[address, uint256])

@external
def __init__():
    self.owner = msg.sender

@external
def deposit():
    self.balances[msg.sender] += msg.value

@external
def withdraw(amount: uint256):
    assert self.balances[msg.sender] >= amount
    send(msg.sender, amount)
    self.balances[msg.sender] -= amount

@external
def kill():
    selfdestruct(self.owner)
