// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract ZeroHashMerkleTree {
    address internal immutable _pointer;
    address internal immutable _pointerWithoutStop;

    constructor(address pointer, address pointerWithoutStop) {
        _pointer = pointer;
        _pointerWithoutStop = pointerWithoutStop;

        _constructZeroHashesAndStore();
    }

    // the storage way: eth 2 deposit contract: https://github.com/ethereum/consensus-specs/blob/dev/solidity_deposit_contract/deposit_contract.sol#L72-L78
    uint constant DEPOSIT_CONTRACT_TREE_DEPTH = 32;
    bytes32[DEPOSIT_CONTRACT_TREE_DEPTH] zeroHashes;

    function _constructZeroHashesAndStore() internal {
        // Compute hashes in empty sparse Merkle tree
        for (
            uint height = 0;
            height < DEPOSIT_CONTRACT_TREE_DEPTH - 1;
            height++
        )
            zeroHashes[height + 1] = keccak256(
                abi.encodePacked(zeroHashes[height], zeroHashes[height])
            );
    }
    function zerosFromStorage(uint i) external view returns (bytes32 ret) {
        ret = zeroHashes[i];
    }

    function zerosFromPointer(uint i) external view returns (bytes32 ret) {
        address pointer = _pointer;
        assembly {
            let fmp := mload(64)
            extcodecopy(pointer, fmp, add(mul(i, 32), 1), 32) // add 1 to skip the extra 00 (stop)
            ret := mload(fmp)
            mstore(fmp, 0) // imp if used internally
        }
    }
    function zerosFromPointerWithoutStop(
        uint i
    ) public view returns (bytes32 ret) {
        address pointerWithoutStop = _pointerWithoutStop;
        assembly {
            let fmp := mload(64)
            extcodecopy(pointerWithoutStop, fmp, mul(i, 32), 32)
            ret := mload(fmp)
            mstore(fmp, 0)
        }
    }

    // the switch: tornado cash https://github.com/tornadocash/tornado-core/blob/master/contracts/MerkleTreeWithHistory.sol#L125-L159
    function zerosFromSwitch(uint i) external pure returns (bytes32) {
        if (i == 0)
            return
                0x0000000000000000000000000000000000000000000000000000000000000000;
        if (i == 1)
            return
                0xad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5;
        if (i == 2)
            return
                0xb4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30;
        if (i == 3)
            return
                0x21ddb9a356815c3fac1026b6dec5df3124afbadb485c9ba5a3e3398a04b7ba85;
        if (i == 4)
            return
                0xe58769b32a1beaf1ea27375a44095a0d1fb664ce2dd358e7fcbfb78c26a19344;
        if (i == 5)
            return
                0x0eb01ebfc9ed27500cd4dfc979272d1f0913cc9f66540d7e8005811109e1cf2d;
        if (i == 6)
            return
                0x887c22bd8750d34016ac3c66b5ff102dacdd73f6b014e710b51e8022af9a1968;
        if (i == 7)
            return
                0xffd70157e48063fc33c97a050f7f640233bf646cc98d9524c6b92bcf3ab56f83;
        if (i == 8)
            return
                0x9867cc5f7f196b93bae1e27e6320742445d290f2263827498b54fec539f756af;
        if (i == 9)
            return
                0xcefad4e508c098b9a7e1d8feb19955fb02ba9675585078710969d3440f5054e0;
        if (i == 10)
            return
                0xf9dc3e7fe016e050eff260334f18a5d4fe391d82092319f5964f2e2eb7c1c3a5;
        if (i == 11)
            return
                0xf8b13a49e282f609c317a833fb8d976d11517c571d1221a265d25af778ecf892;
        if (i == 12)
            return
                0x3490c6ceeb450aecdc82e28293031d10c7d73bf85e57bf041a97360aa2c5d99c;
        if (i == 13)
            return
                0xc1df82d9c4b87413eae2ef048f94b4d3554cea73d92b0f7af96e0271c691e2bb;
        if (i == 14)
            return
                0x5c67add7c6caf302256adedf7ab114da0acfe870d449a3a489f781d659e8becc;
        if (i == 15)
            return
                0xda7bce9f4e8618b6bd2f4132ce798cdc7a60e7e1460a7299e3c6342a579626d2;
        if (i == 16)
            return
                0x2733e50f526ec2fa19a22b31e8ed50f23cd1fdf94c9154ed3a7609a2f1ff981f;
        if (i == 17)
            return
                0xe1d3b5c807b281e4683cc6d6315cf95b9ade8641defcb32372f1c126e398ef7a;
        if (i == 18)
            return
                0x5a2dce0a8a7f68bb74560f8f71837c2c2ebbcbf7fffb42ae1896f13f7c7479a0;
        if (i == 19)
            return
                0xb46a28b6f55540f89444f63de0378e3d121be09e06cc9ded1c20e65876d36aa0;
        if (i == 20)
            return
                0xc65e9645644786b620e2dd2ad648ddfcbf4a7e5b1a3a4ecfe7f64667a3f0b7e2;
        if (i == 21)
            return
                0xf4418588ed35a2458cffeb39b93d26f18d2ab13bdce6aee58e7b99359ec2dfd9;
        if (i == 22)
            return
                0x5a9c16dc00d6ef18b7933a6f8dc65ccb55667138776f7dea101070dc8796e377;
        if (i == 23)
            return
                0x4df84f40ae0c8229d0d6069e5c8f39a7c299677a09d367fc7b05e3bc380ee652;
        if (i == 24)
            return
                0xcdc72595f74c7b1043d0e1ffbab734648c838dfb0527d971b602bc216c9619ef;
        if (i == 25)
            return
                0x0abf5ac974a1ed57f4050aa510dd9c74f508277b39d7973bb2dfccc5eeb0618d;
        if (i == 26)
            return
                0xb8cd74046ff337f0a7bf2c8e03e10f642c1886798d71806ab1e888d9e5ee87d0;
        if (i == 27)
            return
                0x838c5655cb21c6cb83313b5a631175dff4963772cce9108188b34ac87c81c41e;
        if (i == 28)
            return
                0x662ee4dd2dd7b2bc707961b1e646c4047669dcb6584f0d8d770daf5d7e7deb2e;
        if (i == 29)
            return
                0x388ab20e2573d171a88108e79d820e98f26c0b84aa8b2f4aa4968dbb818ea322;
        if (i == 30)
            return
                0x93237c50ba75ee485f4c22adf2f741400bdf8d6a9cc7df7ecae576221665d735;
        if (i == 31)
            return
                0x8448818bb4ae4562849e949e17ac16e0be16688e156b5cf15e098c627c0056a9;
        else revert("Index out of bounds");
    }

    function concactZeroHashes() external view returns (bytes memory ret) {
        ret = abi.encodePacked(zeroHashes);
    }

    uint constant MAX_DEPOSIT_COUNT = 2 ** DEPOSIT_CONTRACT_TREE_DEPTH - 1;
    bytes32[DEPOSIT_CONTRACT_TREE_DEPTH] internal _branch;
    uint depositCount;

    function getRoot() public view virtual returns (bytes32) {
        bytes32 node;
        uint size = depositCount;

        for (uint height = 0; height < DEPOSIT_CONTRACT_TREE_DEPTH; height++) {
            if (((size >> height) & 1) == 1)
                node = keccak256(abi.encodePacked(_branch[height], node));
            else node = keccak256(abi.encodePacked(node, _zeros(height)));
        }
        return node;
    }

    function _addLeaf(bytes32 leaf) internal {
        bytes32 node = leaf;

        if (depositCount >= 2 ** DEPOSIT_CONTRACT_TREE_DEPTH - 1) {
            assembly {
                mstore(0, 0xef5ccf66) // 'MerkleTreeFull()'
                revert(0x1c, 0x04)
            }
        }

        uint256 size = ++depositCount;
        for (
            uint256 height = 0;
            height < DEPOSIT_CONTRACT_TREE_DEPTH;
            height++
        ) {
            if (((size >> height) & 1) == 1) {
                _branch[height] = node;
                return;
            }
            node = keccak256(abi.encodePacked(_branch[height], node));
        }
        assert(false);
    }

    function _zeros(uint i) internal view returns (bytes32 ret) {
        ret = zeroHashes[i];
    }
}
