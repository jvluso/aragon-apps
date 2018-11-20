/*
 * SPDX-License-Identitifer:    GPL-3.0-or-later
 */

pragma solidity 0.4.24;

import "./SignatureValidator.sol";
import "./standards/IERC165.sol";
import "./standards/IERC1271.sol";
import "./ScriptHelpers.sol";

import "@aragon/apps-vault/contracts/Vault.sol";

import "@aragon/os/contracts/common/IForwarder.sol";


contract Actor is Vault, IERC165, IERC1271, IForwarder {
    using ScriptHelpers for bytes;
    bytes32 public constant RUN_SCRIPT_ROLE = keccak256("RUN_SCRIPT_ROLE");

    bytes4 public constant ISVALIDSIG_INTERFACE_ID = 0xabababab; // TODO: Add actual interfaceId

    string private constant ERROR_EXECUTE_ETH_NO_DATA = "VAULT_EXECUTE_ETH_NO_DATA";
    string private constant ERROR_EXECUTE_TARGET_NOT_CONTRACT = "VAULT_EXECUTE_TARGET_NOT_CONTRACT";

    mapping (bytes32 => bool) public isPresigned;

    event PresignHash(address indexed sender, bytes32 indexed hash);
    event SetDesignatedSigner(address indexed sender, address indexed oldSigner, address indexed newSigner);

    function presignHash(bytes32 _hash)
        external
        authP(RUN_SCRIPT_ROLE, arr(_hash))
    {
        isPresigned[_hash] = true;

        emit PresignHash(msg.sender, _hash);
    }

    function isForwarder() external pure returns (bool) {
        return true;
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == ISVALIDSIG_INTERFACE_ID;
    }

    function forward(bytes _evmScript)
        public
        authP(RUN_SCRIPT_ROLE, arr(getScriptACLParam(_evmScript)))
    {
        bytes memory input = ""; // no input
        address[] memory blacklist = new address[](0); // no addr blacklist, can interact with anything
        runScript(_evmScript, input, blacklist);
        // We don't need to emit an event here as EVMScriptRunner will emit ScriptResult if successful
    }

    function isValidSignature(bytes data, bytes signature) public view returns (bool) {
        return isValidSignature(keccak256(data), signature);
    }

    function isValidSignature(bytes32 hash, bytes signature) public view returns (bool) {
        // Short-circuit in case the hash was presigned. Optimization as performing calls
        // and ecrecover is more expensive than an SLOAD.
        if (isPresigned[hash]) {
            return true;
        }

        address designatedSigner = signature.addressAt(36);
        bytes designatedSignature = signature.bytesAt(56,signature.length-20);//TODO: needs to be written
        //should return the entire signature except the address

        if (!canPerform(designatedSigner,RUN_SCRIPT_ROLE)) {
            return false;
        }

        // Checks if designatedSigner is a contract, and if it supports the isValidSignature interface
        if (safeSupportsInterface(IERC165(designatedSigner), ISVALIDSIG_INTERFACE_ID)) {
            // designatedSigner.isValidSignature(hash, signature) as a staticall
            IERC1271 signerContract = IERC1271(designatedSigner);
            bytes memory calldata = abi.encodeWithSelector(signerContract.isValidSignature.selector, hash, designatedSignature);
            return safeBoolStaticCall(signerContract, calldata);
        }

        // `safeSupportsInterface` returns false if designatedSigner is a contract but it
        // doesn't support the interface. Here we check the validity of the ECDSA sig
        // which will always fail if designatedSigner is not an EOA

        return SignatureValidator.isValidSignature(hash, designatedSigner, designatedSignature);
    }

    function canForward(address sender, bytes evmScript) public view returns (bool) {
        uint256[] memory params = new uint256[](1);
        params[0] = getScriptACLParam(evmScript);
        return canPerform(sender, RUN_SCRIPT_ROLE, params);
    }

    function safeSupportsInterface(IERC165 target, bytes4 interfaceId) internal view returns (bool) {
        if (!isContract(target)) {
            return false;
        }

        bytes memory calldata = abi.encodeWithSelector(target.supportsInterface.selector, interfaceId);
        return safeBoolStaticCall(target, calldata);
    }

    function safeBoolStaticCall(address target, bytes calldata) internal view returns (bool) {
        bool ok;
        assembly {
            ok := staticcall(gas, target, add(calldata, 0x20), mload(calldata), 0, 0)
        }

        if (!ok) {
            return false;
        }

        uint256 size;
        assembly { size := returndatasize }
        if (size != 32) {
            return false;
        }

        bool result;
        assembly {
            let ptr := mload(0x40)       // get next free memory ptr
            returndatacopy(ptr, 0, size) // copy return from above `staticcall`
            result := mload(ptr)         // read data at ptr and set it to result
            mstore(ptr, 0)               // set pointer memory to 0 so it still is the next free ptr
        }

        return result;
    }

    function getScriptACLParam(bytes evmScript) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(evmScript)));
    }

    function getSig(bytes data) internal pure returns (bytes4 sig) {
        assembly { sig := add(data, 0x20) }
    }
}
