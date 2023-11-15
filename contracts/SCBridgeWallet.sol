pragma solidity 0.8.19;

// SPDX-License-Identifier: MIT
import {IAccount} from "contracts/interfaces/IAccount.sol";
import {UserOperation} from "contracts/interfaces/UserOperation.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {HTLC, State, hashState, checkSignatures, Participant} from "./state.sol";
import {UserOperationLib} from "contracts/core/UserOperationLib.sol";
import {ExecuteChainInfo, PaymentChainInfo} from "./state.sol";

enum WalletStatus {
  OPEN,
  CHALLENGE_RAISED,
  FINALIZED
}

enum NonceKey {
  SHARED,
  OWNER
}

uint constant CHALLENGE_WAIT = 1 days;

contract SCBridgeWallet is IAccount {
  using ECDSA for bytes32;

  address entrypoint;

  address public owner;
  address payable public intermediary;

  bytes32[] activeHTLCs;
  mapping(bytes32 => HTLC) htlcs;

  uint highestTurnNum = 0;
  uint challengeExpiry = 0;
  uint public intermediaryBalance = 0;

  function getStatus() public view returns (WalletStatus) {
    if (challengeExpiry == 0) {
      return WalletStatus.OPEN;
    }

    if (block.timestamp > challengeExpiry) {
      return WalletStatus.FINALIZED;
    }

    return WalletStatus.CHALLENGE_RAISED;
  }

  // Define the fallback function so that the wallet can receive funds
  receive() external payable {}

  function unlockHTLC(bytes32 hashLock, bytes memory preImage) public {
    HTLC memory htlc = htlcs[hashLock];

    require(htlc.timelock > block.timestamp, "HTLC already expired");
    require(
      htlc.hashLock == keccak256(preImage) || htlc.hashLock == sha256(preImage), // For lightening network compatible HTLCs
      "Invalid preImage"
    );

    removeActiveHTLC(hashLock);

    if (htlc.to == Participant.INTERMEDIARY) {
      intermediaryBalance += htlc.amount;
    }
  }

  function removeActiveHTLC(bytes32 hashLock) private {
    for (uint i = 0; i < activeHTLCs.length; i++) {
      if (activeHTLCs[i] == hashLock) {
        // Shift elements over
        for (uint j = i; j < activeHTLCs.length - 1; j++) {
          activeHTLCs[j] = activeHTLCs[j + 1];
        }
        // remove the duplicate at the end
        activeHTLCs.pop();
        break;
      }
    }
    delete htlcs[hashLock];
  }

  function reclaim() public {
    require(getStatus() == WalletStatus.FINALIZED, "Wallet not finalized");

    // Release any expired funds back to the sender
    for (uint i = 0; i < activeHTLCs.length; i++) {
      HTLC memory htlc = htlcs[activeHTLCs[i]];
      if (htlc.to == Participant.OWNER) {
        intermediary.transfer(htlc.amount);
      }

      // Any funds that are left over are defacto controlled by the owner
    }

    intermediary.transfer(intermediaryBalance);

    intermediaryBalance = 0;
    activeHTLCs = new bytes32[](0);
  }

  function challenge(
    State calldata state,
    bytes calldata ownerSignature,
    bytes calldata intermediarySignature
  ) external {
    checkSignatures(state, ownerSignature, intermediarySignature);
    internalChallenge(state);
  }

  function internalChallenge(State calldata state) internal {
    WalletStatus status = getStatus();

    require(status != WalletStatus.FINALIZED, "Wallet already finalized");
    require(
      status != WalletStatus.CHALLENGE_RAISED || state.turnNum > highestTurnNum,
      "Challenge already exists with a larger TurnNum"
    );

    highestTurnNum = state.turnNum;
    intermediaryBalance = state.intermediaryBalance;

    uint largestTimeLock = 0;
    activeHTLCs = new bytes32[](state.htlcs.length);
    for (uint256 i = 0; i < state.htlcs.length; i++) {
      activeHTLCs[i] = state.htlcs[i].hashLock;
      htlcs[state.htlcs[i].hashLock] = state.htlcs[i];
      if (state.htlcs[i].timelock > largestTimeLock) {
        largestTimeLock = state.htlcs[i].timelock;
      }
    }

    challengeExpiry = largestTimeLock + CHALLENGE_WAIT;
  }

  /// crossChain is a special function that handles cross chain execution and payment
  function crossChain(
    ExecuteChainInfo[] calldata e,
    PaymentChainInfo[] calldata p
  ) public {
    // Only the entrypoint should trigger this by excecuting a UserOp
    require(msg.sender == entrypoint, "account: not EntryPoint");
    for (uint i = 0; i < e.length; i++) {
      if (e[i].chainId == block.chainid) {
        execute(e[i].dest, e[i].value, e[i].callData);
      }
    }
    for (uint i = 0; i < p.length; i++) {
      if (p[i].chainId == block.chainid) {
        internalChallenge(p[i].paymentState);
      }
    }
  }

  function execute(address dest, uint256 value, bytes calldata func) public {
    if (getStatus() == WalletStatus.FINALIZED && activeHTLCs.length == 0) {
      // If the wallet has finalized and all the funds have been reclaimed then the owner can do whatever they want with the remaining funds
      // The owner can call this function directly or the entrypoint can call it on their behalf
      require(
        msg.sender == entrypoint || msg.sender == owner,
        "account: not Owner or EntryPoint"
      );
    } else {
      // If the wallet is not finalized then the owner isn't allowed to spend funds however they want
      // Any interaction with the wallet must be done by signing and submitting a userOp to the entrypoint
      require(msg.sender == entrypoint, "account: not EntryPoint");
    }

    (bool success, bytes memory result) = dest.call{value: value}(func);
    if (!success) {
      assembly {
        revert(add(result, 32), mload(result))
      }
    }
  }

  function permitted(bytes4 functionSelector) internal pure returns (bool) {
    return (functionSelector == this.challenge.selector ||
      functionSelector == this.reclaim.selector ||
      functionSelector == this.unlockHTLC.selector);
  }

  function validateUserOp(
    UserOperation calldata userOp,
    bytes32 userOpHash,
    uint256 // missingAccountFunds
  ) external view returns (uint256 validationData) {
    bytes memory ownerSig = userOp.signature[0:65];
    // The owner of the wallet must always approve of any user operation to execute on it's behalf
    if (
      validateSignature(userOpHash, ownerSig, owner) != SIG_VALIDATION_SUCCEEDED
    ) {
      return SIG_VALIDATION_FAILED;
    }

    // If the wallet is finalized then the owner can do whatever they want with the remaining funds
    if (getStatus() == WalletStatus.FINALIZED) {
      return SIG_VALIDATION_SUCCEEDED;
    }

    bytes4 functionSelector = bytes4(userOp.callData[0:4]);
    NonceKey key = NonceKey(userOp.nonce >> 64);

    // If the function is crossChain, we use validate using the chainids and entrypoints from the calldata
    if (
      functionSelector == this.crossChain.selector && key == NonceKey.SHARED
    ) {
      validateCrossChain(userOp);
    }

    // If the function is permitted, it can be called at any time
    // (including when the wallet is in CHALLENGE_RAISED) with no futher checks.
    if (permitted(functionSelector) && key == NonceKey.OWNER)
      return SIG_VALIDATION_SUCCEEDED;

    // If the wallet is open, we need to apply extra conditions:
    if (getStatus() == WalletStatus.OPEN && key == NonceKey.SHARED) {
      bytes memory intermediarySig = userOp.signature[65:130];
      return validateSignature(userOpHash, intermediarySig, intermediary);
    }

    return SIG_VALIDATION_FAILED;
  }

  constructor(address o, address payable i, address e) {
    owner = o;
    intermediary = i;
    entrypoint = e;
  }

  uint256 internal constant SIG_VALIDATION_SUCCEEDED = 0;
  uint256 internal constant SIG_VALIDATION_FAILED = 1;

  /// This validates the crossChain UserOp
  /// It ensures that it signed by the owner and intermediary on every chain
  /// It also ensures that the UserOp targets the current chain and entrypoint
  function validateCrossChain(UserOperation calldata userOp) private view {
    (ExecuteChainInfo[] memory e, PaymentChainInfo[] memory p) = abi.decode(
      userOp.callData[4:],
      (ExecuteChainInfo[], PaymentChainInfo[])
    );

    bool foundExecute = false;
    bool foundPayment = false;

    // We expect every owner and intermediary on every chain to have signed the userOpHash
    // For each chain we expect a signature from the owner and intermediary
    require(
      userOp.signature.length == (e.length + p.length) * 65 * 2,
      "Invalid signature length"
    );

    for (uint i = 0; i < e.length; i++) {
      if (e[i].chainId == block.chainid && e[i].entrypoint == entrypoint) {
        foundExecute = true;
      }

      // TODO: I think we could just have everyone signed the UserOpHash for the first chain, instead of generating a new hash for each chain?
      // Check that the owner and intermediary have signed the userOpHash on the execution chain
      bytes32 userOpHash = generateUserOpHash(
        userOp,
        e[i].entrypoint,
        e[i].chainId
      );

      uint offset = i * 65;
      bytes memory ownerSig = userOp.signature[offset:offset + 65];
      bytes memory intermediarySig = userOp.signature[offset + 65:offset + 130];
      validateSignature(userOpHash, ownerSig, e[i].owner);
      validateSignature(userOpHash, intermediarySig, e[i].intermediary);
    }

    for (uint i = 0; i < p.length; i++) {
      if (p[i].chainId == block.chainid && p[i].entrypoint == entrypoint) {
        foundPayment = true;
      }

      // Check that the owner and intermediary have signed the userOpHash on the payment chain
      bytes32 userOpHash = generateUserOpHash(
        userOp,
        p[i].entrypoint,
        p[i].chainId
      );
      uint offset = (e.length + i) * 65;
      bytes memory ownerSig = userOp.signature[offset:offset + 65];
      bytes memory intermediarySig = userOp.signature[offset + 65:offset + 130];
      validateSignature(userOpHash, ownerSig, p[i].paymentState.owner);
      validateSignature(
        userOpHash,
        intermediarySig,
        p[i].paymentState.intermediary
      );
    }

    require(
      foundExecute || foundPayment,
      "Must target execution or payment chain"
    );
  }

  function validateSignature(
    bytes32 userOpHash,
    bytes memory signature,
    address expectedSigner
  ) private pure returns (uint256 validationData) {
    bytes32 hash = userOpHash.toEthSignedMessageHash();
    if (expectedSigner != hash.recover(signature)) {
      return SIG_VALIDATION_FAILED;
    }
    return 0;
  }

  function isZero(bytes memory b) internal pure returns (bool) {
    for (uint256 i = 0; i < b.length; i++) {
      if (b[i] != 0) {
        return false;
      }
    }
    return true;
  }
}
using UserOperationLib for UserOperation;

/// @dev Based on the entrypoint implementation
function generateUserOpHash(
  UserOperation calldata userOp,
  address entrypoint,
  uint chainId
) pure returns (bytes32) {
  return keccak256(abi.encode(userOp.hash(), entrypoint, chainId));
}
