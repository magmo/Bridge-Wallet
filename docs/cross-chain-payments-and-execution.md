## Cross chain payments and execution

This document suggests an approach of using `UserOp`s to perform cross-chain payments and execution. At a very high level this approach can be thought of as a cross-chain state channel, where we have some state, that when fully signed can be submitted to an adjudicator contract to claim the funds based on the outcome of that state.

However instead of implementing the state channel framework ourselves, we're making use of some of ERC 4337 infrastructure. Instead of signing a state, participants sign a **UserOp** that contains the state information. Instead of having a specific "adjudicator" contract, we have the **entrypoint** and the **BridgeWallet SCW** to handle adjudicating funds. Instead of making a on-chain call to challenge on the adjudicator, we can submit the `UserOp` to an entrypoint to trigger a challenge.

Since we can specify the UserOp calldata, we can include whatever additional state information we want in that calldata. That lets us embed payment or execution information for different chains in one UserOp. When submitted to chain the UserOp will behave depending on the chain Id and the embedded payment or execution information.

# Payments

We embed payment information in the UserOp using a `PaymentChainInfo`

```sol
/// Contains information to execute a payment
struct PaymentChainInfo {
  uint chainId;
  address entrypoint;
  State paymentState;
}

```

Whenever a fully signed UserOp containing a `PaymentChainInfo` is submitted to chain, it forces a challenge on that chain. This means that once you have a fully signed UserOp you know you can always use it to get your funds via challenge. In the happy path, we would expect participants to just exchange signed states afterwards, so they can discard the UserOp.

## Cross-chain Payment Example

Let's say we have Alice, Bob,and Irene. Alice and Irene have a BridgeWallet on chain A, Bob and Irene have a BridgeWallet on Chain B. Alice and Irene have both signed a state with a balance of `[A:5,I:5]`, and bob and Irene have likewise have a signed state with a balance of`[B:5,I:5]`. Let's say Alice wants to pay Bob.

1. Alice creates two new unsigned states `[A:4,I:6]` and `[B:6,I:4]`
2. Alice includes them in a UserOp(wrapped in a `PaymentChainInfo`), and signs the UserOp. She sends this to Bob and Irene.
3. Bob and Irene validate the UserOp and also sign it, and broadcast it.
4. At this point the UserOp is fully signed and can be used to force a challenge on either chain, by submitting the signed UserOp to the entrypoint on either chain.

# Cross-chain Execution

We can also extend this idea to cross chain execution. Instead of embedding a payment state in the `UserOp` we embed information to make an on-chain function call. If the `UserOp` is submitted to the `entrypoint` the function will be executed **if the chainId matches the chain**.

We embed this information using a `ExecuteChainInfo`

```sol
/// Contains information to execute a function call
struct ExecuteChainInfo {
  uint chainId;
  address entrypoint;
  address dest;
  uint value;
  bytes callData;
  address owner;
  address intermediary;
}
```

A UserOp can contain multiple `ExecuteChainInfo`s, meaning you can have "atomic" cross chain execution (once the UserOp is fully signed, you're guaranteed you can trigger the execution on either chain). A UserOp can also contain `PaymentChainInfo`s and `ExecuteChainInfos` allowing to pay for cross-chain execution.

# Multihop

Since a UserOp can contain multiple `PaymentChainInfo`s and `ExecuteChainInfos`, this approach can be used for multi-hop execution or payments. We just require the `owner` and `intermediary` of every BridgeWallet involved to sign the UserOp.

# Replay Attacks

It's important that we're not vulnerable to replay attacks, where a `UserOp` is submitted again using a different entrypoint or chain.

If we're working on one chain, it's fairly easy to prevent replay attacks. The `userOpHash` [provided by the Entrypoint](https://github.com/magmo/Bridge-Wallet/blob/ad6d24fa2435f449751d1b61e24d12faff1f83a9/contracts/core/EntryPoint.sol#L298) to `validateUserOp` is hashed against the current chain and entrypoint. This means that if the UserOp is run against a different chain or entrypoint, there will be a different `userOpHash` causing all the signature checks to fail.

With cross-chain execution and payments we need a slightly more complicated check. To prevent replay attacks we ensure that one of the `ExecuteChainInfo` or `PaymentChainInfo` matches our chainId and entrypoint. This ensures that the `UserOp` will only be handled by the chain/entrypoint specified by the `ExecuteChainInfo/PaymentChainInfo`.

# Signatures

We expect the UserOp to be signed by the `owner` and `intermediary` of every BridgeWallet involved. So based on the example above with Alice,Irene,Bob, we'd expect the signatures `[AliceSigChainA,IreneSigChainA,IreneSigChainB,BobSigChainB]`.

When validating signatures we iterate through the `ExecuteChainInfo` and `PaymentChainInfo` and check the signatures against the hash generated using the chain id/entrypoint from the ChainInfo. It's important that we validate the signature for other chains, because that guarantees the UserOp is "atomic". Otherwise a partially signed UserOp could be redeemed on one chain, while not being redeemable on the other chain.

# Nonces

**NOTE:** This hasn't been done in the test yet.

We need to be careful with how we use nonces. The `owner` of a BridgeWallet can always submit a UserOp to [trigger a](https://github.com/magmo/Bridge-Wallet/blob/66dbb9c41ea8830218265b4def76824320df6bca/contracts/SCBridgeWallet.sol#L207) `Challenge` or `Reclaim` call. So if we have a UserOp signed by everyone with some `nonce`, the `owner` could submit a UserOp just signed by them burning the nonce, and preventing the UserOp signed by everyone from being handled.

Luckily ERC 4337 provides ["Semi-abstracted Nonce Support"](https://eips.ethereum.org/EIPS/eip-4337#semi-abstracted-nonce-support) where the first 192 bits of the nonce are treated as a `key` and the last 64 bits are the `sequence`. This means we can use a separate nonce for calls to `crossChain`, preventing the `owner` from burning the nonce and preventing the `crossChain` call.
