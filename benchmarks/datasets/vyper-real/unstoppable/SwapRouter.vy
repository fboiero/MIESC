# @version ^0.3.7

from vyper.interfaces import ERC20

# struct ExactInputSingleParams {
#         address tokenIn;
#         address tokenOut;
#         uint24 fee;
#         address recipient;
#         uint256 deadline;
#         uint256 amountIn;
#         uint256 amountOutMinimum;
#         uint160 sqrtPriceLimitX96;
#     }
struct ExactInputSingleParams:
    tokenIn: address
    tokenOut: address
    fee: uint24
    recipient: address
    deadline: uint256
    amountIn: uint256
    amountOutMinimum: uint256
    sqrtPriceLimitX96: uint160

# struct ExactInputParams {
#     bytes path;
#     address recipient;
#     uint256 deadline;
#     uint256 amountIn;
#     uint256 amountOutMinimum;
# }
struct ExactInputParams:
    path: Bytes[66]
    recipient: address
    deadline: uint256
    amountIn: uint256
    amountOutMinimum: uint256


# function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut);
interface UniswapV3SwapRouter:
    def exactInputSingle(_params: ExactInputSingleParams) -> uint256: payable
    def exactInput(_params: ExactInputParams) -> uint256: payable

UNISWAP_ROUTER: constant(address) = 0xE592427A0AEce92De3Edee1F18E0157C05861564

# token_in -> token_out -> fee
direct_route: public(HashMap[address, HashMap[address, uint24]])
paths: public(HashMap[address, HashMap[address, Bytes[66]]])

admin: public(address)


@nonpayable
@external
def __init__():
    self.admin = msg.sender


@external
def swap(
    _token_in: address,
    _token_out: address,
    _amount_in: uint256,
    _min_amount_out: uint256,
) -> uint256:
    ERC20(_token_in).transferFrom(msg.sender, self, _amount_in)
    ERC20(_token_in).approve(UNISWAP_ROUTER, _amount_in)

    if self.direct_route[_token_in][_token_out] != 0:
        return self._direct_swap(_token_in, _token_out, _amount_in, _min_amount_out)
    else:
        return self._multi_hop_swap(_token_in, _token_out, _amount_in, _min_amount_out)


@internal
def _direct_swap(
    _token_in: address,
    _token_out: address,
    _amount_in: uint256,
    _min_amount_out: uint256,
) -> uint256:
    fee: uint24 = self.direct_route[_token_in][_token_out]
    assert fee != 0, "no direct route"

    params: ExactInputSingleParams = ExactInputSingleParams(
        {
            tokenIn: _token_in,
            tokenOut: _token_out,
            fee: fee,
            recipient: msg.sender,
            deadline: block.timestamp,
            amountIn: _amount_in,
            amountOutMinimum: _min_amount_out,
            sqrtPriceLimitX96: 0,
        }
    )
    return UniswapV3SwapRouter(UNISWAP_ROUTER).exactInputSingle(params)


@internal
def _multi_hop_swap(
    _token_in: address,
    _token_out: address,
    _amount_in: uint256,
    _min_amount_out: uint256,
) -> uint256:
    path: Bytes[66] = self.paths[_token_in][_token_out]
    assert path != empty(Bytes[66]), "no path configured"

    uni_params: ExactInputParams = ExactInputParams(
        {
            path: path,
            recipient: msg.sender,
            deadline: block.timestamp,
            amountIn: _amount_in,
            amountOutMinimum: _min_amount_out,
        }
    )
    return UniswapV3SwapRouter(UNISWAP_ROUTER).exactInput(uni_params)


@external
def add_direct_route(_token1: address, _token2: address, _fee: uint24):
    assert msg.sender == self.admin, "unauthorized"
    self.direct_route[_token1][_token2] = _fee
    self.direct_route[_token2][_token1] = _fee


@external
def add_path(_token1: address, _token2: address, _path: Bytes[66]):
    assert msg.sender == self.admin, "unauthorized"
    self.paths[_token1][_token2] = _path
    self.paths[_token2][_token1] = _path
