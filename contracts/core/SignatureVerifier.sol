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
    TransactionData,
    Action,
    Input,
    TokenAmount,
    Permit,
    AbsoluteTokenAmount,
    Fee
} from "../shared/Structs.sol";
import { ECDSA } from "../shared/ECDSA.sol";

contract SignatureVerifier {
    mapping(bytes32 => mapping(address => bool)) internal isHashUsed_;

    bytes32 internal immutable domainSeparator_;

    bytes32 internal constant DOMAIN_SEPARATOR_TYPEHASH =
        keccak256(
            abi.encodePacked("EIP712Domain(", "string name,", "address verifyingContract", ")")
        );
    bytes32 internal constant TX_DATA_TYPEHASH =
        keccak256(
            abi.encodePacked(
                TX_DATA_ENCODED_TYPE,
                ACTION_ENCODED_TYPE,
                FEE_ENCODED_TYPE,
                INPUT_ENCODED_TYPE,
                TOKEN_AMOUNT_ENCODED_TYPE
            )
        );
    bytes32 internal constant ABSOLUTE_TOKEN_AMOUNT_TYPEHASH =
        keccak256(ABSOLUTE_TOKEN_AMOUNT_ENCODED_TYPE);
    bytes32 internal constant INPUT_TYPEHASH =
        keccak256(
            abi.encodePacked(INPUT_ENCODED_TYPE, TOKEN_AMOUNT_ENCODED_TYPE, PERMIT_ENCODED_TYPE)
        );
    bytes32 internal constant TOKEN_AMOUNT_TYPEHASH = keccak256(TOKEN_AMOUNT_ENCODED_TYPE);
    bytes32 internal constant PERMIT_TYPEHASH = keccak256(PERMIT_ENCODED_TYPE);
    bytes32 internal constant ACTION_TYPEHASH =
        keccak256(abi.encodePacked(ACTION_ENCODED_TYPE, TOKEN_AMOUNT_ENCODED_TYPE));
    bytes32 internal constant FEE_TYPEHASH = keccak256(FEE_ENCODED_TYPE);

    bytes internal constant TX_DATA_ENCODED_TYPE =
        abi.encodePacked(
            "TransactionData(",
            "Action[] actions,",
            "Input[] inputs,",
            "Fee fee,",
            "AbsoluteTokenAmount[] requiredOutputs,",
            "uint256 salt",
            ")"
        );
    bytes internal constant ABSOLUTE_TOKEN_AMOUNT_ENCODED_TYPE =
        abi.encodePacked("AbsoluteTokenAmount(", "address token,", "uint256 absoluteAmount", ")");
    bytes internal constant INPUT_ENCODED_TYPE =
        abi.encodePacked("Input(", "TokenAmount tokenAmount,", "Permit permit", ")");
    bytes internal constant TOKEN_AMOUNT_ENCODED_TYPE =
        abi.encodePacked(
            "TokenAmount(",
            "address token,",
            "uint256 amount,",
            "uint8 amountType",
            ")"
        );
    bytes internal constant PERMIT_ENCODED_TYPE =
        abi.encodePacked("Permit(", "uint8 permitType,", "bytes permitCallData", ")");
    bytes internal constant ACTION_ENCODED_TYPE =
        abi.encodePacked(
            "Action(",
            "bytes32 protocolAdapterName,",
            "uint8 actionType,",
            "TokenAmount[] tokenAmounts,",
            "bytes data",
            ")"
        );
    bytes internal constant FEE_ENCODED_TYPE =
        abi.encodePacked("Fee(", "uint256 share,", "address beneficiary", ")");

    constructor(string memory name) {
        domainSeparator_ = keccak256(
            abi.encode(DOMAIN_SEPARATOR_TYPEHASH, keccak256(abi.encodePacked(name)), address(this))
        );
    }

    /**
     * @return Address of the Core contract used.
     */
    function isHashUsed(bytes32 hash, address account) public view returns (bool) {
        return isHashUsed_[hash][account];
    }

    function getAccountFromSignature(bytes32 hashedData, bytes memory signature)
        public
        pure
        returns (address payable)
    {
        return payable(ECDSA.recover(hashedData, signature));
    }

    function hashData(TransactionData memory data) public view returns (bytes32) {
        return
            keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator_, hash(data)));
    }

    function markHashUsed(bytes32 hash, address account) internal {
        require(!isHashUsed_[hash][account], "SV: used hash!");
        isHashUsed_[hash][account] = true;
    }

    /// @return Hash to be signed by tokens supplier.
    function hash(TransactionData memory data) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    TX_DATA_TYPEHASH,
                    hash(data.actions),
                    hash(data.inputs),
                    hash(data.fee),
                    hash(data.requiredOutputs),
                    data.salt
                )
            );
    }

    function hash(Action[] memory actions) internal pure returns (bytes32) {
        bytes memory actionsData = new bytes(0);

        uint256 length = actions.length;
        for (uint256 i = 0; i < length; i++) {
            actionsData = abi.encodePacked(
                actionsData,
                keccak256(
                    abi.encode(
                        ACTION_TYPEHASH,
                        actions[i].protocolAdapterName,
                        actions[i].actionType,
                        hash(actions[i].tokenAmounts),
                        keccak256(actions[i].data)
                    )
                )
            );
        }

        return keccak256(actionsData);
    }

    function hash(TokenAmount[] memory tokenAmounts) internal pure returns (bytes32) {
        bytes memory tokenAmountsData = new bytes(0);

        uint256 length = tokenAmounts.length;
        for (uint256 i = 0; i < length; i++) {
            tokenAmountsData = abi.encodePacked(tokenAmountsData, hash(tokenAmounts[i]));
        }

        return keccak256(tokenAmountsData);
    }

    function hash(TokenAmount memory tokenAmount) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    TOKEN_AMOUNT_TYPEHASH,
                    tokenAmount.token,
                    tokenAmount.amount,
                    tokenAmount.amountType
                )
            );
    }

    function hash(Input[] memory inputs) internal pure returns (bytes32) {
        bytes memory inputsData = new bytes(0);

        uint256 length = inputs.length;
        for (uint256 i = 0; i < length; i++) {
            inputsData = abi.encodePacked(
                inputsData,
                keccak256(
                    abi.encode(INPUT_TYPEHASH, hash(inputs[i].tokenAmount), hash(inputs[i].permit))
                )
            );
        }

        return keccak256(inputsData);
    }

    function hash(Permit memory permit) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    PERMIT_TYPEHASH,
                    permit.permitType,
                    keccak256(abi.encodePacked(permit.permitCallData))
                )
            );
    }

    function hash(Fee memory fee) internal pure returns (bytes32) {
        return keccak256(abi.encode(FEE_TYPEHASH, fee.share, fee.beneficiary));
    }

    function hash(AbsoluteTokenAmount[] memory absoluteTokenAmounts)
        internal
        pure
        returns (bytes32)
    {
        bytes memory absoluteTokenAmountsData = new bytes(0);

        uint256 length = absoluteTokenAmounts.length;
        for (uint256 i = 0; i < length; i++) {
            absoluteTokenAmountsData = abi.encodePacked(
                absoluteTokenAmountsData,
                keccak256(
                    abi.encode(
                        ABSOLUTE_TOKEN_AMOUNT_TYPEHASH,
                        absoluteTokenAmounts[i].token,
                        absoluteTokenAmounts[i].absoluteAmount
                    )
                )
            );
        }

        return keccak256(absoluteTokenAmountsData);
    }
}
