// Copyright (C) 2020 Zerion Inc. <https://zerion.io>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: LGPL-3.0-only

pragma solidity 0.7.3;
pragma experimental ABIEncoderV2;

import {
    AbsoluteTokenAmount,
    Action,
    AmountType,
    Fee,
    Input,
    PermitType,
    TokenAmount,
    TransactionData
} from "../shared/Structs.sol";
import { ERC20 } from "../interfaces/ERC20.sol";
import { SafeERC20 } from "../shared/SafeERC20.sol";
import { Helpers } from "../shared/Helpers.sol";
import { Core } from "./Core.sol";
import { BaseRouter } from "./BaseRouter.sol";
import { Ownable } from "./Ownable.sol";
import { SignatureVerifier } from "./SignatureVerifier.sol";
import { UniswapRouter } from "./UniswapRouter.sol";

interface Chi {
    function freeFromUpTo(address, uint256) external;
}

contract Router is
    Ownable,
    BaseRouter,
    UniswapRouter,
    SignatureVerifier("Zerion Router (Mainnet, v1.1)")
{
    using SafeERC20 for ERC20;
    using Helpers for address;

    address internal immutable core_;

    address internal constant CHI = 0x0000000000004946c0e9F43F4Dee607b0eF1fA1c;

    modifier useCHI {
        uint256 gasStart = gasleft();
        _;
        uint256 gasSpent = 21000 + gasStart - gasleft() + 7 * msg.data.length;
        Chi(CHI).freeFromUpTo(msg.sender, (gasSpent + 25171) / 41852);
    }

    constructor(address payable core) {
        require(core != address(0), "R: empty core");

        core_ = core;
    }

    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}

    function returnLostTokens(address token, address payable beneficiary) external onlyOwner {
        if (token == ETH) {
            transferEther(beneficiary, address(this).balance, "R: bad beneficiary");
        } else {
            ERC20(token).safeTransfer(beneficiary, ERC20(token).balanceOf(address(this)), "R");
        }
    }

    /**
     * @return Address of the Core contract used.
     */
    function core() external view returns (address) {
        return core_;
    }

    /**
     * @notice Executes actions and returns tokens to account.
     * @param actions Array of actions to be executed.
     * @param inputs Array of tokens to be taken from the signer of this data.
     * @param fee Fee struct with fee details.
     * @param requiredOutputs Array of requirements for the returned tokens.
     * @param salt Number that makes this data unique.
     * @param signature EIP712-compatible signature of data.
     * @return Array of AbsoluteTokenAmount structs with the returned tokens.
     */
    function execute(
        Action[] memory actions,
        Input[] memory inputs,
        Fee memory fee,
        AbsoluteTokenAmount[] memory requiredOutputs,
        uint256 salt,
        bytes memory signature
    ) public payable returns (AbsoluteTokenAmount[] memory) {
        bytes32 hashedData = hashData(actions, inputs, fee, requiredOutputs, salt);
        address payable account = getAccountFromSignature(hashedData, signature);

        markHashUsed(hashedData, account);

        return execute(actions, inputs, fee, requiredOutputs, account);
    }

    /**
     * @notice Executes actions and returns tokens to account.
     * @param actions Array of actions to be executed.
     * @param inputs Array of tokens to be taken from the signer of this data.
     * @param fee Fee struct with fee details.
     * @param requiredOutputs Array of requirements for the returned tokens.
     * @return Array of AbsoluteTokenAmount structs with the returned tokens.
     */
    function execute(
        Action[] memory actions,
        Input[] memory inputs,
        Fee memory fee,
        AbsoluteTokenAmount[] memory requiredOutputs
    ) public payable returns (AbsoluteTokenAmount[] memory) {
        return execute(actions, inputs, fee, requiredOutputs, msg.sender);
    }

    /**
     * @notice Executes actions and returns tokens to account.
     * @param actions Array of actions to be executed.
     * @param inputs Array of tokens to be taken from the signer of this data.
     * @param fee Fee struct with fee details.
     * @param requiredOutputs Array of requirements for the returned tokens.
     * @param salt Number that makes this data unique.
     * @param signature EIP712-compatible signature of data.
     * @return Array of AbsoluteTokenAmount structs with the returned tokens.
     * @dev This function uses CHI token to refund some gas.
     */
    function executeWithCHI(
        Action[] memory actions,
        Input[] memory inputs,
        Fee memory fee,
        AbsoluteTokenAmount[] memory requiredOutputs,
        uint256 salt,
        bytes memory signature
    ) public payable useCHI returns (AbsoluteTokenAmount[] memory) {
        bytes32 hashedData = hashData(actions, inputs, fee, requiredOutputs, salt);
        address payable account = getAccountFromSignature(hashedData, signature);

        markHashUsed(hashedData, account);

        return execute(actions, inputs, fee, requiredOutputs, account);
    }

    /**
     * @notice Executes actions and returns tokens to account.
     * @param actions Array of actions to be executed.
     * @param inputs Array of tokens to be taken from the signer of this data.
     * @param fee Fee struct with fee details.
     * @param requiredOutputs Array of requirements for the returned tokens.
     * @return Array of AbsoluteTokenAmount structs with the returned tokens.
     * @dev This function uses CHI token to refund some gas.
     */
    function executeWithCHI(
        Action[] memory actions,
        Input[] memory inputs,
        Fee memory fee,
        AbsoluteTokenAmount[] memory requiredOutputs
    ) public payable useCHI returns (AbsoluteTokenAmount[] memory) {
        return execute(actions, inputs, fee, requiredOutputs, msg.sender);
    }

    function execute(
        Action[] memory actions,
        Input[] memory inputs,
        Fee memory fee,
        AbsoluteTokenAmount[] memory requiredOutputs,
        address payable account
    ) internal returns (AbsoluteTokenAmount[] memory) {
        // Transfer tokens to Core contract, handle fees (if any), and add these tokens to outputs
        transferTokens(inputs, fee, account);
        AbsoluteTokenAmount[] memory modifiedOutputs = modifyOutputs(requiredOutputs, inputs);

        // Call Core contract with all provided ETH, actions, expected outputs and account address
        AbsoluteTokenAmount[] memory actualOutputs =
            Core(payable(core_)).executeActions(actions, modifiedOutputs, account);

        // Emit event so one could track account and fees of this tx.
        emit Executed(account, fee.share, fee.beneficiary);

        // Return tokens' addresses and amounts that were returned to the account address
        return actualOutputs;
    }

    function transferTokens(
        Input[] memory inputs,
        Fee memory fee,
        address account
    ) internal {
        if (fee.share > 0) {
            require(fee.beneficiary != address(0), "R: bad beneficiary");
            require(fee.share <= FEE_LIMIT, "R: bad fee");
        }

        uint256 length = inputs.length;
        for (uint256 i = 0; i < length; i++) {
            // ignore output amount as we don't need it
            handleTokenInput(account, core_, inputs[i], fee);
        }

        if (msg.value > 0) {
            // ignore output amount as we don't need it
            handleETHInput(account, core_, fee);
        }
    }

    function modifyOutputs(AbsoluteTokenAmount[] memory requiredOutputs, Input[] memory inputs)
        internal
        view
        returns (AbsoluteTokenAmount[] memory)
    {
        uint256 ethInput = msg.value > 0 ? 1 : 0;
        AbsoluteTokenAmount[] memory modifiedOutputs =
            new AbsoluteTokenAmount[](requiredOutputs.length + inputs.length + ethInput);

        for (uint256 i = 0; i < requiredOutputs.length; i++) {
            modifiedOutputs[i] = requiredOutputs[i];
        }

        for (uint256 i = 0; i < inputs.length; i++) {
            modifiedOutputs[requiredOutputs.length + i] = AbsoluteTokenAmount({
                token: inputs[i].tokenAmount.token,
                absoluteAmount: 0
            });
        }

        if (ethInput > 0) {
            modifiedOutputs[requiredOutputs.length + inputs.length] = AbsoluteTokenAmount({
                token: ETH,
                absoluteAmount: 0
            });
        }

        return modifiedOutputs;
    }
}
