// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console2 as console} from "forge-std/Test.sol";
import {ZeroHashMerkleTree} from "../src/ZeroHashMerkleTree.sol";
import {SSTORE2} from "./../lib/solady/src/utils/SSTORE2.sol";

contract ZeroHashMerkleTreeTest is Test {
    ZeroHashMerkleTree public base;

    function setUp() public {
        bytes32[] memory zeroHashes = new bytes32[](32);
        for (uint height = 0; height < 32 - 1; height++)
            zeroHashes[height + 1] = keccak256(
                abi.encodePacked(zeroHashes[height], zeroHashes[height])
            );

        bytes memory data = abi.encodePacked(zeroHashes);
        address pointer = SSTORE2.write(data);
        address pointerWithoutStop = write(data);

        base = new ZeroHashMerkleTree(pointer, pointerWithoutStop);
    }

    function testGasBenchmarks() public view {
        uint sstore2ReadSum;
        uint readPointerSum;
        uint readFromStorageSum;
        uint readFromSwitchSum;
        for (uint i; i < 32; i++) {
            uint gas = gasleft();
            bytes32 value = bytes32(
                SSTORE2.read(base.pointer(), i * 32, (i + 1) * 32)
            );
            sstore2ReadSum += gas - gasleft();

            gas = gasleft();
            // bytes32 readPointer = base.zerosFromPointer(i);
            bytes32 readPointer = base.zerosFromPointerWithoutTheExtraStop(i);
            readPointerSum += gas - gasleft();
            assertEq(readPointer, value);

            gas = gasleft();
            bytes32 readFromStorage = base.zerosFromStorage(i);
            readFromStorageSum += gas - gasleft();
            assertEq(readFromStorage, value);

            gas = gasleft();
            bytes32 readFromSwitch = base.zerosFromSwitch(i);
            readFromSwitchSum += gas - gasleft();

            assertEq(readFromSwitch, value);
        }

        console.log("sstore2ReadSum", sstore2ReadSum);
        console.log("readPointerSum", readPointerSum);
        console.log("readFromStorageSum", readFromStorageSum);
        console.log("readFromSwitchSum", readFromSwitchSum);
    }

    // taken from solmate: https://github.com/transmissions11/solmate/blob/main/src/utils/SSTORE2.sol
    // does not pad the initial 00 (STOP) opcode for keccack hashed merkle trees where
    // the first zero root is bytes32(0) which naturally lends the initial STOP opcode
    function write(bytes memory data) internal returns (address pointer) {
        bytes memory runtimeCode = abi.encodePacked(data);
        bytes memory creationCode = abi.encodePacked(
            hex"60_0B_59_81_38_03_80_92_59_39_F3",
            runtimeCode
        );
        assembly {
            pointer := create(0, add(creationCode, 32), mload(creationCode))
        }
        require(pointer != address(0), "DEPLOYMENT_FAILED");
    }
}
