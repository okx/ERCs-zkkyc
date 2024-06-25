---
eip: <to be assigned>
title: Verifiable Zero-Knowledge KYC Store
description: A commitment store for KYC, with verifiable zero-knowledge claims, allows users to participate in diverse dApps while preserving privacy.
author: Icer Liang (@wizicer)
discussions-to: <tbd>
status: Draft
type: Standards Track
category: ERC
created: 2023-08-08
requires: 165
---

## Abstract

Know Your Customer (KYC) is an essential element in numerous services,
ensures customer data complies with laws and regulations. This proposal
aims to create a standard that can be adopted by KYC holders and
third-party decentralized applications (dApps), enabling on-chain
verification and reducing privacy leaks. We also elaborate the
specification and discusses the potential expansion based on specific
business scenarios. We also debates the pros and cons of individual
stores versus a global registry, the need for versioning of commitments,
off-chain verification strategies, and privacy considerations. Finally,
we address security considerations including replay attacks,
frontrunning attacks, user ID blindness, identifier reuse, and phishing
attacks. We underscores the need for a standard that not only ensures
compliance with KYC protocols but also enhances user privacy and
security.

## Motivation

KYC is a critical component in various services, aimed at ensuring that
customer identity information meets legal and regulatory requirements.
By using existing KYC information, customers can easily complete
third-party personhood, age, and nationality verification. KYC
information is highly confidential, and it is essential to trust that a
client\'s KYC information meets the requirements (also known as claim)
without disclosing the details to third parties. This is a crucial step
in simplifying the customer onboarding process.

The motivation behind this proposal is to create a standard that can be
adopted by KYC holders and third-party dApps. By enabling on-chain
verification, the possibility of privacy leaks can be greatly reduced.
This proposal fosters trust in customers by guaranteeing the privacy of
their KYC information, thereby enabling them to confidently participate
in a wider range of on-chain and off-chain activities that require the
use of their KYC information.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 and RFC 8174.

### Definition

- Commitment: In cryptography, a commitment scheme is a protocol that
  allows a party to commit to a value without revealing the value itself.
  Once the committer is ready to reveal the value, they can do so, and
  others can verify that the revealed value matches the commitment.

- Zero knowledge proof (ZKP): In cryptography, the **prover** is trying to
  convince the **verifier** that they know some secret information,
  without revealing the actual secret information.

- Public Signals: In ZKP, public signals are pieces of information that
  are made publicly available to all parties involved in the proof. These
  signals are used to ensure that the proof is valid and the prover is not
  cheating without knowing anything about the prover\'s secret information
  to preserve prover\'s privacy. Public signals can include things like
  random numbers, hashes, or other pieces of data that can effectively
  prevent replay attacks. From the traditional program\'s perspective,
  public signals include public inputs and public outputs.

- Proof: In ZKP, the verifier can use these public signals to verify the
  validity of the proof, without actually having access to the secret
  information itself.

### Interfaces Specification

```solidity
pragma solidity ^0.8.0;

/// @title Verifiable Commitment Store
/// @dev reference implementation is here: https://github.com/OKX/zkkycpoc/blob/main/src/contracts/kycCommitmentStore.sol
/// @notice the ERC-165 identifier for this interface is 0xd355a1aa
interface IVerifiableCommitmentStore /* is ERC165 */ {
    // bytes4(keccak256("verifyProof(bytes32,uint[],uint[])"))
    bytes4 constant internal MAGICVALUE = 0xc7d7057a;

    function metadataURI(
        bytes32 _version
    ) external view returns (string memory);
    
    function verifyProof(
        bytes32 _version,
        uint[] calldata _proof,
        uint[] calldata _publicSignals
    ) external view returns (bytes4 magicVlue);
}

interface ERC165 {
    /// @notice Query if a contract implements an interface
    /// @param interfaceID The interface identifier, as specified in ERC-165
    /// @dev Interface identification is specified in ERC-165. This function
    ///  uses less than 30,000 gas.
    /// @return `true` if the contract implements `interfaceID` and
    ///  `interfaceID` is not 0xffffffff, `false` otherwise
    function supportsInterface(bytes4 interfaceID) external view returns (bool);
}
```

### Commitment Metadata

This is the "Commitment Metadata JSON Schema" by _metadataURI.

```json
{
  "title": "Commitment Metadata",
  "type": "object",
  "properties": {
    "version": {
      "type": "string",
      "description": "Identifies the version to which this metadata represents"
    },
    "commitment": {
      "type": "string",
      "description": "The commitment corresponding to this metadata"
    },
    "proofURI": {
      "type": "string",
      "description": "A URI pointing to a resource representing the proof to which this commitment represents."
    }
  }
}
```

The content corresponding to the `proofURI` here is intended to convince the public that the commitment itself corresponds to the correct information that follows, without any fabrication or tampering of user information. It is likely impossible to completely prevent fabrication. Even when using biometric identification technology like Worldcoin, there is still a need to trust that the identification machine itself is not fabricating information, so the trust model remains the same. Therefore, depending on the volume of data and the content that needs to be proven, different information can be included, hence the content can be arbitrary. The specific content is beyond the scope of this specification. Different KYC Holders will have different implementations.

### Standard Public Signals

For security consideration, from this proposal, we have general
suggestions on standard public signals that could reduce the known
attack vectors.

| Field      | Type    | Description                                                                                                                                                 |
| --         | --      | --                                                                                                                                                          |
| isMixed    | bool    | If the proof originates from the Mix Proof Pool, this field ought to be set to true.                                                                        |
| timestamp  | uint    | Enforce proof should be within a certain time range, to avoid expired submissions.                                                                          |
| chainId    | uint    | Enforce proof should bind to a specific chain, to prevent cross-chain replay attacks.                                                                       |
| appId      | uint    | Enforce proof should bind to a specific dApp, to prevent phishing attacks where users may prove to an dApp they do not know.                                |
| userId     | uint    | Enforce proof should bind to a specific user, to prevent the Sybil attack.                                                                                  |
| address    | address | Enforce proof should bind to a specific address, to prevent the benefit address tampering.                                                                  |
| commitment | uint    | Enforce proof should bind to a specific commitment, which will be checked in the contract and is critical in verifying the existence of user and its claim. |
| claimHash  | uint    | Enforce proof should bind to a specific claim, to ensure that only users who meet the claim can obtain a valid proof.                                       |

### Claim Structures

There are two types of claim structures. The first one has a very simple
expression but limited functionality, while the second one has high
generality but complex implementation.

#### Simple Claim

| Field          | Type   | Description
| --             | --   | --                                                                                                                                                                                                                                 |
| claimAttribute | uint | It refers to the index of attributes that the claim is making about the user. e.g. it could be the index of user\'s name, age, or country.                                                                                         |
| claimLogic     | uint | It specifies the relationship between the attribute and the value. There are several types of logic operators. See the following table for details.  These logic operators are used to compare the attribute of user to the value.                                                                  |
| claimValue     | uint[] | This is the actual value of the attribute that the claim is making. e.g. if the attribute is the user\'s age and the logic operator is greater than, the value might be 18.                                                                                                                         |


The value of claimLogic can be referred to the following table:

| Logic | Index | Description  | Parameter Number|
| --    | --    | --           | -- |
| ==    | 0     | Equals       | 1 |
| !=    | 1     | Not equals   | 1 |
| \>    | 2     | Greater than | 1 |
| \<    | 3     | Less than    | 1 |
| $\geq$    | 4     | Greater than equal | 1 |
| $\leq$    | 5     | Less than equal   | 1 |
| in    | 6     | In value set    | * |
| not-in    | 7     | Not in value set    | * |
| between    | 8     | Between two value    | 2 |
| not-between    | 9     | Not between two value    | 2 |

The operator of claimLogic can be expanded according to specific
business scenarios, but I will not elaborate further here.

#### Polynomial Claim

Here we propose a Polynomial Claim, but given its complexity, and the
fact that this content goes beyond the scope of this specification, it
is only discussed here.

As the claimPolynomial has the best generality, it is difficult for
ordinary users to read the claim in the form of a polynomial and judge
whether the description of the claim itself is correct. Therefore, it is
necessary to use a DSL that expresses the claim, so that users can
understand the description of the claim in the form of a high-level
language. At the same time, the client interface should able to compile
this DSL into the polynomial. Then users are allowed to check whether
the DSL claim expression is indeed the same expression as
claimPolynomial.

TODO: fill more details here

### Proof Scope

ZK is used to hide users\' private information, including attributes and
the salt number. ZK is also used to improve scalability, avoiding the
transmission of full inclusion proofs. Overall, the following proofs
need to be made in the ZK circuit:

- Prove userId and user\'s attributes are included in the commitment.
- Prove user\'s attributes meet the requirement of claim.
- Prove public signals are included in the witness according to proof.

## Rationale

### Individual store vs global registry(store vs registry)

If we use a store, each KYC Holder can have their own independent
contract, giving them complete control over the internal permission
control of the contract. However, if we use a global registry, there are
some trade-offs to consider. On the one hand, the advantage is that it
provides a unique addressing system, where all Ethereum Compatible
chains can use the same contract address. On the other hand, the
disadvantage is that different KYC Holders may have varying permission
management requirements, or they may race to preempt a certain
commitmentId, or some may want to implement commitment verification
mechanism.

### Version of commitment

The version number can bring benefits to smooth updates of commitments.
Imagine if there isn\'t a version number, when the user tries to submit
the proof against the old commitment during commitment refreshing. It
may cause `VerifyProof` to fail and reduce the user experience
significantly.

Sometimes, users may be revoked by the system. And the corresponding
earlier commitments should not be used any more. Best design the
contract to only hold two version numbers in the contract and perform
expiration time checks in the dApp.

### Off-chain verification

For some third-party applications that may not be on-chain, it is also
very important to verify the correctness of the proof off-chain. These
applications can choose two methods:

Directly call the RPC interface of the on-chain node, and verify the
proof through the `verifyProof` interface gas-free, which is why the
`verifyProof` interface is specifically marked as `external view`.

Real-time synchronize the commitments in the on-chain contract to
off-chain database. And implement the logic of function `verifyProof`
off-chain for verification. This method requires special attention to
ensure the correctness of the off-chain `verifyProof` function.

### Privacy

In standard public signals, the only fields concerned privacy are the
userId and address. These two fields will be discussed separately in the
Security Consideration under Blindness of User Id and Identifier Reuse .

### Public Signals vs Named Fields

Obviously, public signals provides greater flexibility, but considering
the importance of several key fields, it is critical for the dApp
contract to perform checks and take logs when necessary. For example,
userId must not be duplicated, chainId must match the current chain, and
claim must match the requirements of the dApp. Therefore, the use of
named fields seems important, but in reality, we encourage dApp contract
developers to read the entire contract code and ZK circuit code (at
least the API). Thus, dApp developers can easily find the definition of
the corresponding field in public signals. Therefore, we believe that
using public signals not only retains flexibility but also discloses the
fields\' information.

## Backwards Compatibility

At the time this EIP was first proposed, there was no implementation on
the Ethereum main net

## Test Cases

Test cases are included in the code repository.

## Reference Implementation

See https://github.com/OKX/zkkycpoc

## Security Considerations

### Replay Attacks

This standard is only about update commitment and verifiying proofs. In
many practical applications, proofs are used to authorize an action, for
example an exchange of tokens. It is very important that implementers
make sure the application behaves correctly when it sees the same signed
message twice. For example, the repeated message should be rejected or
the authorized action should be idempotent. How this is implemented is
specific to the application and out of scope for this standard.

Furthermore, the proof could potentially be replayed on different
chains. Similar to the suggestion before, the application should take
care of rejecting the repeated proof and make use of chain id in public
signals to invalid the proof on any other chain.

### Frontrunning Attacks

The mechanism for reliably broadcasting a proof is application-specific
and out of scope for this standard. When the proof is broadcast to a
blockchain for use in a contract, the application has to be secure
against frontrunning attacks. In this kind of attack, an attacker
intercepts the proof and submits it to the contract before the original
intended use takes place. The application should behave correctly when
the signature is submitted first by an attacker, for example by
rejecting it or simply producing exactly the same effect as intended by
the prover.

### Blindness of User Id

The system ensures users\' KYC information is never exposed using ZKP.
However, if the same userId is provided every time during verification,
it can be exploited by malicious adversaries to discover the correlation
between user interactions. On the contrary, if we generate different
userIds for the same user everytime, it would also be a disaster because
the dApp would find it difficult to determine the personhood of the
user. Therefore, we need to blind userId, and there are many methods to
achieve this. The most common one is to calculate the hash of internal
userId, appId, and a secret salt to generate a new userId.

### Identifier Reuse

- Towards perfect privacy, it would be ideal to use a new uncorrelated
  identifier (e.g., Ethereum address) per digital interaction, selectively
  disclosing the information required and no more. However, if users
  attempt to perform operations such as fund aggregation, it may break
  perfect privacy and expose the relationships between these uncorrelated
  identifiers.

- This concern is less relevant to certain user demographics who are
  likely to be socialite, such as those who manage an Ethereum address
  and/or ENS names intentionally associated with their public presence.
  These users often prefer identifier reuse to maintain a single
  correlated identity across many services. However, attention should be
  given to such users, with different claims being correlated together,
  the original privacy information may be disclosed.

- In addition to the above two scenarios, KYC Holders usually possess the
  capability to associate these identifiers. However, this is not the case
  if the KYC Holder employs the **Mix Proof Pool**. This system empowers
  users to maintain a secret and generate their own group proof.
  Consequently, it becomes impossible for the KYC Holder to associate the
  user with the group identifier. This topic extends beyond the scope of
  this standard. For more details, please refer to the following link:
  [Mix Proof Pool](https://github.com/OKX/zkkycpoc#mix-proof-pool).

### Phishing (Man-in-the-middle) Attack

It's worth pointing out a special form of replay attack by phishing. An
adversary can design another smart contract in a way that the user is
tricked into generating valid proof for a seemingly legitimate purpose,
but the data scheme matches the target application. As a countermeasure,
users should be able to see `appId` and `address` in the UI during
generating proof, to prevent address tampering. If it is determined that
the `appId` and `address` are both correct, the adversary can only transmit
messages obediently and can not tamper with the fact that user is the
beneficiary.

## References

[ERC-165](https://eips.ethereum.org/EIPS/eip-165) Standard Interface Detection.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
