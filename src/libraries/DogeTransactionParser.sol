// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "./BTCStyleMerkle.sol";

/**
 * @title DogeTransactionParser
 * @dev Dogecoin transaction parser library, parse a raw Dogecoin transaction byte array
 */
library DogeTransactionParser {
    enum Network {
        MAINNET,
        TESTNET,
        REGTEST
    }

    bytes3 private constant P2PKH_NETWORK_VERSION = bytes3(0x1e6f6f);
    bytes3 private constant P2SH_NETWORK_VERSION = bytes3(0x16c4c4);

    // p2pkh output
    struct P2PKHOutput {
        uint64 value;
        bytes20 publicKeyHash;
    }

    // Base58 alphabet used in Bitcoin and other systems
    string private constant BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    function encodeBase58(bytes memory data) public pure returns (string memory) {
        uint256 len = data.length;
        uint256[] memory digits = new uint256[](len * 2);

        for (uint256 i = 0; i < len; i++) {
            uint256 carry = uint8(data[i]);
            for (uint256 j = digits.length - 1; j >= 0; j--) {
                carry += digits[j] * 256;
                digits[j] = carry % 58;
                carry /= 58;
                if (carry == 0 && j == 0) break;
            }
        }

        // calculate the number of leading zeros
        uint256 zeroCount = 0;
        while (data[zeroCount] == 0 && zeroCount < data.length) {
            zeroCount++;
        }

        // result array
        bytes memory result = new bytes(zeroCount + len * 2); // the length may be needed
        uint256 index = 0;

        // leading zero processing
        for (uint256 i = 0; i < zeroCount; i++) {
            result[index++] = 0x31; // the '1' character in Base58
        }

        // convert Base58
        for (uint256 i = 0; i < digits.length; i++) {
            if (digits[i] > 0 || index > zeroCount) {
                result[index++] = bytes(BASE58_ALPHABET)[digits[i]];
            }
        }

        // trim the trailing whitespace characters
        bytes memory finalResult = new bytes(index);
        for (uint256 i = 0; i < index; i++) {
            finalResult[i] = result[i];
        }

        return string(finalResult);
    }

    // P2PKH network version bytes: 0x1e (mainnet); 0x6f (testnet); 0x6f (regtest)
    // P2SH network version bytes: 0x16 (mainnet); 0xc4 (testnet); 0xc4 (regtest)
    /**
     * @dev get the Dogecoin address from the public key hash
     * @param pubKeyHash the public key hash
     * @param network the network
     * @param version the version, 0-P2PKH, 1-P2SH
     * @return the Dogecoin address
     */
    function getDogecoinAddress(bytes20 pubKeyHash, Network network, uint8 version)
        public
        pure
        returns (bytes memory)
    {
        bytes memory versionedPayload = new bytes(21);

        // add version prefix
        if (version == 0) {
            versionedPayload[0] = P2PKH_NETWORK_VERSION[uint8(network)];
        } else if (version == 1) {
            versionedPayload[0] = P2SH_NETWORK_VERSION[uint8(network)];
        } else {
            revert("Invalid version");
        }

        // add pubKeyHash
        for (uint256 i = 0; i < 20; i++) {
            versionedPayload[i + 1] = pubKeyHash[i];
        }

        // calculate checksum
        bytes4 checksum = bytes4(BTCStyleMerkle.doubleSha256Bytes(versionedPayload));

        // concat versionedPayload and checksum
        bytes memory finalPayload = new bytes(25);
        for (uint256 i = 0; i < 21; i++) {
            finalPayload[i] = versionedPayload[i];
        }
        for (uint256 i = 0; i < 4; i++) {
            finalPayload[21 + i] = checksum[i];
        }
        return finalPayload;
    }

    // Read a uint16 value from buffer in little endian format.
    function readUint16LE(bytes memory data, uint256 pos) private pure returns (uint16) {
        return uint16(uint8(data[pos])) + (uint16(uint8(data[pos + 1])) << 8);
    }

    // Read a uint32 value from buffer in little endian format.
    function readUint32LE(bytes memory data, uint256 pos) private pure returns (uint32) {
        return uint32(uint8(data[pos])) + (uint32(uint8(data[pos + 1])) << 8) + (uint32(uint8(data[pos + 2])) << 16)
            + (uint32(uint8(data[pos + 3])) << 24);
    }

    // Read a uint64 value from buffer in little endian format.
    function readUint64LE(bytes memory data, uint256 pos) private pure returns (uint64 value) {
        // Use inline assembly to load 8 bytes and compute little-endian value
        assembly {
            let dataPtr := add(data, 32)
            let word := mload(add(dataPtr, pos))
            let b0 := byte(0, word)
            let b1 := byte(1, word)
            let b2 := byte(2, word)
            let b3 := byte(3, word)
            let b4 := byte(4, word)
            let b5 := byte(5, word)
            let b6 := byte(6, word)
            let b7 := byte(7, word)
            value :=
                add(
                    b0,
                    add(
                        mul(b1, 0x100),
                        add(
                            mul(b2, 0x10000),
                            add(
                                mul(b3, 0x1000000),
                                add(
                                    mul(b4, 0x100000000),
                                    add(mul(b5, 0x10000000000), add(mul(b6, 0x1000000000000), mul(b7, 0x100000000000000)))
                                )
                            )
                        )
                    )
                )
        }
    }

    // Read uint256 value from buffer in little endian format.
    function readUint256LE(bytes memory data, uint256 start) private pure returns (uint256 res) {
        require(start + 31 < data.length, "Invalid uint256 LE read from buffer");
        for (uint256 i = 0; i < 32; i++) {
            res += uint256(uint8(data[i + start])) << (8 * i);
        }
    }

    /**
     * @dev get the tx hash of the transaction
     * @param txBytes the bytes of the transaction
     * @return the hash of the transaction
     */
    function getTxid(bytes memory txBytes) public pure returns (bytes32) {
        return BTCStyleMerkle.doubleSha256Bytes(txBytes);
    }

    /**
     * @dev parse a P2PKH transaction with Dogecoin bridge style.
     *      output[0] is the P2PKH output, output[1] is the OP_RETURN data.
     * @param txData the bytes of the transaction
     * @return p2pkhOutput the P2PKH output
     * @return opReturnData the OP_RETURN data
     * @return isP2PKHWithOpReturn true if the transaction is a P2PKH transaction with OP_RETURN, false otherwise
     */
    function parseBridgeInP2PKHTransaction(bytes memory txData)
        public
        pure
        returns (P2PKHOutput memory p2pkhOutput, bytes memory opReturnData, bool isP2PKHWithOpReturn)
    {
        uint256 offset = 4; // skip the version field

        // ---------------------------------------------------------------------
        // 1) Skip the single input (we assume exactly 1 input)
        // ---------------------------------------------------------------------
        // inputCount (1 byte)
        // txid (32 bytes)
        // vout (4 bytes)
        // scriptSig length (1 byte)
        // scriptSig (scriptSigLength bytes)
        // sequence (4 bytes)

        // Read the number of inputs (1 byte)
        uint8 inputCount = uint8(txData[offset]);
        offset += 1;

        // Skip through the inputs
        for (uint256 i = 0; i < inputCount; i++) {
            offset += 32; // Skip txid
            offset += 4; // Skip vout index
            uint8 scriptSigLength = uint8(txData[offset]);
            offset += 1; // Skip scriptSigLength
            offset += scriptSigLength; // Skip scriptSig
            offset += 4; // Skip sequence
        }

        // ---------------------------------------------------------------------
        // 2) Parse outputs (we assume exactly 2 outputs)
        // ---------------------------------------------------------------------
        // outputCount (1 byte)
        // ---------------------------------------------------------------------
        // For output 0 (P2PKH):
        //   value (8 bytes, little endian)
        //   scriptPubKey length (1 byte)
        //   scriptPubKey (scriptPubKeyLength bytes)
        //
        // For output 1 (OP_RETURN):
        //   value (8 bytes, likely 0)
        //   scriptPubKey length (1 byte)
        //   scriptPubKey (at least 2 bytes => 0x6a + dataLen)
        // ---------------------------------------------------------------------

        // Read the number of outputs (1 byte)
        uint8 outputCount = uint8(txData[offset]);
        offset += 1;

        // Process outputs
        for (uint256 i = 0; i < outputCount; i++) {
            uint64 value;
            // 8 length little endian
            value = readUint64LE(txData, offset);
            offset += 8;

            // Read scriptPubKeyLength, 1 length
            // uint8 scriptPubKeyLength = uint8(txData[offset]);
            uint8 scriptPubKeyLength;
            assembly {
                // load 32 bytes from txData at current offset, first byte is scriptPubKeyLength
                scriptPubKeyLength := byte(0, mload(add(add(txData, 32), offset)))
            }
            offset += 1;

            // Check minimal pattern for P2PKH:
            //   0x76 (OP_DUP)
            //   0xa9 (OP_HASH160)
            //   0x14 (push 20 bytes) ... pubKeyHash ...
            //   0x88 (OP_EQUALVERIFY)
            //   0xac (OP_CHECKSIG)
            //
            // Typically scriptPubKeyLength == 25 for a standard P2PKH
            // Check for P2PKH pattern: 0x76, 0xa9, ... , 0x88, 0xac
            if (
                i == 0 && scriptPubKeyLength >= 5 && txData[offset] == 0x76 // OP_DUP
                    && txData[offset + 1] == 0xa9 // OP_HASH160
                    && txData[offset + scriptPubKeyLength - 2] == 0x88 // OP_EQUALVERIFY
                    && txData[offset + scriptPubKeyLength - 1] == 0xac // OP_CHECKSIG
            ) {
                // Extract the 20-byte pubKeyHash at offset+3
                // (Because after 0x76, 0xa9, and 1-byte push of 0x14)
                // That’s 3 bytes before the 20 bytes themselves.
                bytes20 pubKeyHash;
                assembly {
                    pubKeyHash :=
                        mload(
                            add(
                                add(txData, 32), // start of txData contents
                                add(offset, 3) // offset + 3
                            )
                        )
                }
                p2pkhOutput = P2PKHOutput(value, pubKeyHash);
                // No need to process further for this output, continue loop
            }
            // -------------------------
            // Output #1: OP_RETURN
            // -------------------------
            // Check for OP_RETURN output: first byte is 0x6a
            else if (i == 1 && scriptPubKeyLength >= 2 && txData[offset] == 0x6a) {
                uint8 dataLength = uint8(txData[offset + 1]);
                opReturnData = new bytes(dataLength);
                // Copy the OP_RETURN data from txData (starting at offset+2)
                assembly {
                    let src := add(txData, add(32, add(offset, 2)))
                    let dest := add(opReturnData, 32)
                    // Copy dataLength bytes (using 32-byte chunks)
                    for { let j := 0 } lt(j, dataLength) { j := add(j, 32) } {
                        mstore(add(dest, j), mload(add(src, j)))
                    }
                }
                isP2PKHWithOpReturn = true;
                break;
            }
            offset += scriptPubKeyLength;
        }

        return (p2pkhOutput, opReturnData, isP2PKHWithOpReturn);
    }

    /**
     * @dev parse a Bridge Out P2PKH transaction.
     * @param txData the bytes of the transaction
     * @return allOutputs an array of P2PKH outputs
     * @return p2pkhOutputCount the count of valid P2PKH outputs found
     */
    function parseBridgeOutP2PKHTransaction(bytes memory txData)
        public
        pure
        returns (P2PKHOutput[] memory allOutputs, uint8 p2pkhOutputCount)
    {
        uint256 offset = 4; // skip the version field

        // Read the number of inputs (1 byte)
        uint8 inputCount = uint8(txData[offset]);
        offset += 1;

        // Skip through the inputs
        for (uint256 i = 0; i < inputCount; i++) {
            offset += 32; // Skip txid
            offset += 4; // Skip vout index
            uint8 scriptSigLength = uint8(txData[offset]);
            offset += 1; // Skip scriptSigLength
            offset += scriptSigLength; // Skip scriptSig
            offset += 4; // Skip sequence
        }

        // Read the number of outputs (1 byte)
        uint8 outputCount = uint8(txData[offset]);
        offset += 1;

        if (outputCount == 0) {
            return (new P2PKHOutput[](0), 0);
        }
        allOutputs = new P2PKHOutput[](outputCount);

        // Process outputs
        for (uint256 i = 0; i < outputCount; i++) {
            uint64 value;
            value = readUint64LE(txData, offset);
            offset += 8;

            // Read scriptPubKeyLength, 1 length
            // uint8 scriptPubKeyLength = uint8(txData[offset]);
            uint8 scriptPubKeyLength;
            assembly {
                // load 32 bytes from txData at current offset, first byte is scriptPubKeyLength
                scriptPubKeyLength := byte(0, mload(add(add(txData, 32), offset)))
            }
            offset += 1;

            // Check for P2PKH pattern using direct byte checks
            uint8 byte0 = uint8(txData[offset]);
            uint8 byte1 = uint8(txData[offset + 1]);
            uint8 secondLast = uint8(txData[offset + scriptPubKeyLength - 2]);
            uint8 last = uint8(txData[offset + scriptPubKeyLength - 1]);

            if (scriptPubKeyLength >= 5 && byte0 == 0x76 && byte1 == 0xa9 && secondLast == 0x88 && last == 0xac) {
                bytes20 extractedAddress;
                // Directly load pubKeyHash from txData (offset+3)
                assembly {
                    let dataPtr := add(txData, 32)
                    extractedAddress := mload(add(dataPtr, add(offset, 3)))
                }
                allOutputs[p2pkhOutputCount++] = P2PKHOutput(value, extractedAddress);
            }
            offset += scriptPubKeyLength;
        }
    }
}
