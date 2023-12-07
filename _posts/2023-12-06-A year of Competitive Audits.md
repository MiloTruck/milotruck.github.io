---
title: "A year of Competitive Audits"
date: 2023-12-06
categories: Blog
--- 

A look into audit contests from the eyes of a competitive auditor in 2023.

# Stats

Here's an overview of my results:

| Contest | Platform | SLOC | Findings | Ranking | Payout | 
|:--|:--:|:--:|:--:|:--:|:--:|
| [Ethos Reserve](https://code4rena.com/contests/2023-02-ethos-reserve-contest) | Code4rena | 3500 | 1 M | #49 | $142.85 | 
| [Wenwin](https://code4rena.com/contests/2023-03-wenwin-contest) | Code4rena |  962 | 1 M | #18 | $397.60 |
| [Polynomial Protocol](https://code4rena.com/contests/2023-03-polynomial-protocol-contest) | Code4rena |  1849 | 1 H, 2 M | #14 | $759.68 |
| [Asymmetry Finance](https://code4rena.com/contests/2023-03-asymmetry-contest) | Code4rena | 645 |  5 H, 2 M | #29 | $224.11 |
| [Contest 225](https://code4rena.com/contests/2023-03-contest-225-contest) | Code4rena | 1000 | 2 H, 2 M | #22 | $833.23 |
| [Teller V2](https://app.sherlock.xyz/audits/contests/62) | Sherlock | 1428 | 1 H, 5 M | #25 | $193.70 |
| [Caviar Private Pools](https://code4rena.com/contests/2023-04-caviar-private-pools) | Code4rena | 725 | 1 M | #105 | $9.33 | 
| [Frankencoin](https://code4rena.com/contests/2023-04-frankencoin) | Code4rena | 949 | 2 M | #13 | $832.81 |
| [EigenLayer](https://code4rena.com/contests/2023-04-eigenlayer-contest) | Code4rena | 1393 | 1 H, 1 M | #9 | $1,978.72 |
| [Footium](https://app.sherlock.xyz/audits/contests/71) | Sherlock | 524 | 1 H, 1 M | #19 | $120.88 |
| [Chainlink CCIP](https://code4rena.com/contests/2023-05-chainlink-cross-chain-services-ccip-and-arm-network) | Code4rena | 2985 | 3 H | #8 | $6,300.97 |
| [LUKSO](https://code4rena.com/contests/2023-06-lukso) | Code4rena | 3469 | 6 M | #1 | $44,459.52 |
| [Lens Protocol V2](https://code4rena.com/contests/2023-07-lens-protocol-v2) | Code4rena | 4108 | 8 M | #1 | $29,747.31 |
| [Arbitrum Security Council Elections](https://code4rena.com/contests/2023-08-arbitrum-security-council-election-system) | Code4rena | 2184 | 1 H, 3 M | #1 | $15,482.70 |
| [StakeWise V3](https://stakewise.io/) | Hats Finance | 3497 | 1 M, 3 L | #1 | $11,703 |
| [Chainlink Staking v0.2](https://code4rena.com/contests/2023-08-chainlink-staking-v02) | Code4rena | 2538 | 10 M | #1 | $48,797.95 |
| [Wildcat](https://code4rena.com/contests/2023-10-the-wildcat-protocol) | Code4rena | 2332 | 3 H, 7 M | #2 | $10,093.23 |
| Total | | 34,088 | 18 H, 52 M | | $172,077.59 |

I took part in 17 different contests and reviewed over 34K lines of Solidity, finding 70 H/M bugs and earning a total of ~$172K in rewards. You can find the details of every single bug in [this repository](https://github.com/MiloTruck/audits/blob/main/audit-contests.md).

I don't track my time unfortunately, but I'm pretty sure I clocked an insane number of hours staring intensely at Solidity. 

# 2022: The Beginning

## Learning Web3 security

A lot of newcomers to the space ask me how I learnt Web3 security. Well, here's what I did at the start:

1. Went through [CryptoZombies](https://cryptozombies.io/) to get a grasp of Solidity and DeFi concepts.
2. Read the following blogs:
   1. [How to become a smart contract auditor](https://cmichel.io/how-to-become-a-smart-contract-auditor/) by [@cmichelio](https://twitter.com/cmichelio)
   2. [Hacking the Blockchain: Ethereum](https://medium.com/immunefi/hacking-the-blockchain-an-ultimate-guide-4f34b33c6e8b) by Immunefi
3. Read chapters  1, 2, 3, 4, 5, 6, 13, and 14 of [Mastering Ethereum](https://github.com/ethereumbook/ethereumbook).
4. Did the following CTFs to familiarize myself with security concepts and common exploits:
- [Capture the Ether](https://capturetheether.com/)
- [Ethernaut](https://ethernaut.openzeppelin.com/)
- [Damn Vulnerable DeFi](https://www.damnvulnerabledefi.xyz/)
- [Paradigm CTF 2021](https://github.com/paradigmxyz/paradigm-ctf-2021) - I didn't complete this one.

After that, I dove headfirst into contests.

<p align="center">
    <img src="{{site.baseurl}}/assets/images/code4rena_msg.png" width=700>
</p>

This suited my learning style very well - most of the knowledge I know came from reading up on Solidity patterns and concepts that I would see in contests, but didn't understand.

If you're a newcomer to the space in 2023, I don't recommend following this as a roadmap - many of the items in my list are now outdated and there are probably better resources out there. The takeaway here is that you should aim to have "real-life security experience" as fast as possible, be it in audit contests or bug bounties.

## Bot Racing before it was cool

Doing those few CTFs actually set me up quite well for audit contests - from my first contest onwards, I was [consistently finding mediums and occasionally finding highs](https://github.com/MiloTruck/audits/blob/main/audit-contests.md#2022). 

However, back in 2022, I didn't have much time for Web3 security and couldn't dedicate more than a day of my week to contests. I would eventually pivot into writing my own static analyzer, [Regast](https://github.com/MiloTruck/regast-public), and running them in contests for QA and gas reports.

<img src="{{site.baseurl}}/assets/images/alex_msg.png" width=800>

This made me ~$7K in 2022, which is pretty decent considering I didn't put in much time into contests.

# 2023: The Journey

## February - Entering the arena

| Contest | Platform | SLOC | Findings | Ranking | Payout | 
|:--|:--:|:--:|:--:|:--:|:--:|
| [Ethos Reserve](https://code4rena.com/contests/2023-02-ethos-reserve-contest) | Code4rena | 3500 | 1 M | #49 | $142.85 | 

My first return to competitive audits was in the second half of February, where I would compete in only one contest.

### Ethos Reserve

Wow, my first contest was 3.5K SLOC.

Ethos Reserve is a fork of [Liquity](https://www.liquity.org/), which is not an easy protocol to understand by any means. 

My goal heading into this contest was just to understand the protocol as best as I could, and maybe find a bug. Guess what - it worked! I ended up finding [a pretty simple DOS vector](https://github.com/code-423n4/2023-02-ethos-findings/issues/768), which is a win in my book.

On hindsight, this was an extremely good protocol to audit for my first contest. Ethos Reserve (and Liquity) uses the staking reward mechanism from [Sushiswap's Masterchef contract](https://medium.com/coinmonks/analysis-of-the-billion-dollar-algorithm-sushiswaps-masterchef-smart-contract-81bb4e479eb6), which in my opinion is one of the core mechanisms of DeFi. Learning how it worked helped me a ton in future contests as basically every single protocol that has staking rewards implements this same mechanism.

## March - Humble beginnings

| Contest | Platform | SLOC | Findings | Ranking | Payout | 
|:--|:--:|:--:|:--:|:--:|:--:|
| [Wenwin](https://code4rena.com/contests/2023-03-wenwin-contest) | Code4rena |  962 | 1 M | #18 | $397.60 |
| [Polynomial Protocol](https://code4rena.com/contests/2023-03-polynomial-protocol-contest) | Code4rena |  1849 | 1 H, 2 M | #14 | $759.68 |
| [Asymmetry Finance](https://code4rena.com/contests/2023-03-asymmetry-contest) | Code4rena | 645 |  5 H, 2 M | #29 | $224.11 |
| [Contest 225](https://code4rena.com/contests/2023-03-contest-225-contest) | Code4rena | 1000 | 2 H, 2 M | #22 | $833.23 |
| Total | | 4456 | 7 H, 7 M | | $2,214.62 |

I participated in four audit contests in my first month fully dedicated to Web3 security. Looking back at this now, I honestly didn't realize I participated in so many contests during March...

### Wenwin

A lottery protocol, which falls under GameFi.

From what I remember, I was able to understand most of the protocol except the [`LotteryMath.sol`](https://github.com/code-423n4/2023-03-wenwin/blob/main/src/LotteryMath.sol#L50-L53) contract, since I didn't have a good grasp of DeFi math at that time. This contract would end up containing [the only high finding](https://code4rena.com/reports/2023-03-wenwin#h-01-lotterymathcalculatenewprofit-returns-wrong-profit-when-there-is-no-jackpot-winner) in the entire contest...

What I learnt from this - math is complicated, and complex areas are where bugs are most likely to occur. If you can't understand the code, chances are others (including the devs) probably had a hard time understanding it too.

My only medium finding was also [selected for report](https://github.com/code-423n4/2023-03-wenwin-findings/issues/245), which is a pretty huge testament to the quality of my reports even when I first started out.

<img src="{{site.baseurl}}/assets/images/wenwin_finding.png" width=800>

### Polynomial Protocol

Classified contest, so I can't say much. 

Something noteworthy is that all three of [my](https://code4rena.com/reports/2023-03-polynomial#h-03-short-positions-can-be-burned-while-holding-collateral) [medium](https://code4rena.com/reports/2023-03-polynomial#m-09-short-positions-with-minimum-collateral-can-be-liquidated-even-though-canliquidate-returns-false) [findings](https://code4rena.com/reports/2023-03-polynomial#m-02-users-can-receive-less-collateral-than-expected-from-liquidations) were selected for the final report, which once again assured me that my reports were of high quality.

This led to my first time receiving a significant payout (over $500, that's huge!), which motivated me to try harder in contests.

### Asymmetry Finance

This was the first codebase I actually fully understood in-depth, partially due to its small SLOC. The protocol also wasn't very hard to understand - it's essentially an aggregator for liquid ETH staking over [Rocket Pool](https://rocketpool.net/), [Lido](https://lido.fi/) and [Frax Finance](https://frax.finance/), as such, there wasn't much complexity or math to begin with.

I believe this was what led me to find 5/8 highs, which I consider a win despite the small payout in the end. Finding 7 H/M bugs in a single contest was no small feat for someone who just started focusing on audits. 

In the words of [@sockdrawermoney](https://twitter.com/sockdrawermoney):

<p align="center">
  <img src="{{site.baseurl}}/assets/images/sock_tweet.png" width=600>
</p>

P.S. Shoutout to him for the encouragement at that time, and for being an awesome person overall.

### Contest 225

Another classified contest, so nothing much to say here. 

The results for this contest came out around the same time as Polynomial Protocol, so I was pretty motivated and happy with my progress during that period of time. For some reason all my larger payouts are in classified contests...

## April - Peak FOMO

| Contest | Platform | SLOC | Findings | Ranking | Payout | 
|:--|:--:|:--:|:--:|:--:|:--:|
| [Teller V2](https://app.sherlock.xyz/audits/contests/62) | Sherlock | 1428 | 1 H, 5 M | #25 | $193.70 |
| [Footium](https://app.sherlock.xyz/audits/contests/71) | Sherlock | 524 | 1 H, 1 M | #19 | $120.88 |
| [Caviar Private Pools](https://code4rena.com/contests/2023-04-caviar-private-pools) | Code4rena | 725 | 1 M | #105 | $9.33 | 
| [Frankencoin](https://code4rena.com/contests/2023-04-frankencoin) | Code4rena | 949 | 2 M | #13 | $832.81 |
| [EigenLayer](https://code4rena.com/contests/2023-04-eigenlayer-contest) | Code4rena | 1393 | 1 H, 1 M | #9 | $1,978.72 |
| Total | | 5019 | 3 H, 10 M | | $3135.44 |

I participated in _another_ five audit contests again in second month. 

This was honestly FOMO at its peak - I would participate in one contest, see a new one pop up and hop over to it after a day or so. Unless you're a genius and have some god-given talent for auditing, no one should be reviewing 5K SLOC over 5 different protocols in their second month of auditing. 

> _"Be like a postage stamp. Stick to one thing until you get there."_
> <div style="text-align: right"> - Some random quote from Google to make myself sound smart </div>

I would end up spending about 3-4 days on each contest due to this, which is a great way to find a whole lot of nothing.

### Teller V2, Footium

My first two (and only) contests on Sherlock!

I had wanted to try out Sherlock for some time now, especially since I had seen others (most notably [@0x52](https://twitter.com/IAm0x52)) landing some massive payouts. They also introduced [judging contests](https://docs.sherlock.xyz/audits/judging/guide-to-judging-contests) around this period of time, which I thought was a good way to learn and make some quick bucks at the same time.

I didn't end up doing well in either contest, mostly due to the fact that I didn't spend a lot of time on either of them. Footium was also an extremely popular contest due to its small SLOC and simplicity, which ended up diluting my rewards even further. 

What I learnt from this - choose contests according to your skill level and avoid overly simple or small contests. There probably won't be much to find, and even if there are many bugs, everyone is probably going to find most of them.

A fun fact is that I ended up placing second in the judging contest for Teller, which is the only judging contest I've ever participated in.

<p align="center">
  <img src="{{site.baseurl}}/assets/images/teller_judging.png" width=500>
</p>

This gave me a lot of points on the [Judging Leaderboard](https://audits.sherlock.xyz/judging-leaderboard), and I actually sat at a pretty high rank (5th place) for a long period of time. However, I didn't realize it until half a year later when someone told me.

<p align="center">
  <img src="{{site.baseurl}}/assets/images/judging_msg.png" width=600>
</p>

**A note on Sherlock's judging contests:** I still think this is one of the most effective ways to learn since you have an instant feedback loop - you get to see what bugs you missed and learn from everyone's findings immediately after the contest ends.

### Caviar Private Pools

I honestly don't remember participating in this contest.

### Frankencoin

I didn't do too well in this contest either, both of my mediums were generic findings - one was a [first depositor attack](https://github.com/code-423n4/2023-04-frankencoin-findings/issues/915) and the other was simply [an error in the code](https://github.com/code-423n4/2023-04-frankencoin-findings/issues/941). Most of the payout actually came from my [QA report](https://github.com/code-423n4/2023-04-frankencoin-findings/blob/main/data/MiloTruck-Q.md) that was awarded grade-A.

For this contest, I believe that I actually had a pretty good understanding of the protocol and how it worked in its entirety. My mistake was hopping to another contest too soon instead of looking deeper for more nuanced bugs.

The lesson to learn here - after understanding the code, always spend more time to look for bugs or think of possible attack vectors. There's this idea of diminishing returns and when to stop looking for bugs, written in [cmichel's blog](https://cmichel.io/how-to-become-a-smart-contract-auditor/). But most of the time you'll never reach that point while the contest is ongoing, unless the contest duration is really long or you're a really good auditor.

### EigenLayer

My first four digit payout!

EigenLayer was my first introduction to the world of [Liquid Ethereum Staking](https://ethereum.org/en/staking/), which would end up becoming arguably the largest DeFi trend of the year.


Being new to ETH staking at the time, there was a huge portion of the protocol that was unfamiliar to me. In fact, before I fully understood how the ETH staking portion of the codebase worked, I actually stopped trying to find bugs midway into the contest and started looking at Footium instead.

On hindsight, this was an extremely bad decision. The contest ended up having two bugs related to ETH staking (one of which was a [high](https://code4rena.com/reports/2023-04-eigenlayer#h-01-slot-and-block-number-proofs-not-required-for-verification-of-withdrawal-multiple-withdrawals-possible) worth ~$5k), both of which I missed simply because I didn't try. 

What I learnt from this - don't be afraid of complexity and unfamiliar topics, all you have to do is research harder (we're called security _researchers_ for a reason) and pick up the related concepts as best as you can. This was the approach [@0xVolodya](https://twitter.com/0xVolodya) had going into the contest, which [worked out extremely well for him](https://0xvolodya.hashnode.dev/how-i-earned-25000-auditing-and-ranked-1-on-60-day-leaderboard#heading-eigenlayerhttpscode4renacomcontests2023-04-eigenlayer-contesttop-12200dollar).

I would end up finding 2 out of 4 H/M bugs in this contest - one high due to [a misplaced `++i` in a for-loop](https://github.com/code-423n4/2023-04-eigenlayer-findings/issues/119) and another medium which was [a not very impactful DOS vector](https://github.com/code-423n4/2023-04-eigenlayer-findings/issues/122). Honestly, I don't really understand why the high bug wasn't found by more auditors since it was extremely easy to spot, but I'm not complaining as it resulted in my first four digit payout.

## June - The turning point

| Contest | Platform | SLOC | Findings | Ranking | Payout | 
|:--|:--:|:--:|:--:|:--:|:--:|
| [Chainlink CCIP](https://code4rena.com/contests/2023-05-chainlink-cross-chain-services-ccip-and-arm-network) | Code4rena | 2985 | 3 H | #8 | $6,300.97 |

My entire first two weeks of June (and part of May) was spent on a single contest. 

The second half of the month was dedicated to Immunefi, during which I found [this critical bug](https://github.com/MiloTruck/audits/blob/main/immunefi/beluga-C-01.md) but sadly got ghosted by the protocol.

### Chainlink CCIP

This contest had a $185,000 USD H/M pot, which was what led me to focus only on it for its entire duration.

For the entire two weeks, nearly all my time went into looking at this codebase. I remember telling myself that I would find every possible bug and do better than all other wardens participating, including  [@trust_90](https://twitter.com/trust__90). Of course, that didn't happen.

Before the contest started, I did research beforehand to prepare myself and get an idea of what I would be auditing. This included:

- Reading through Chainlink's [public CCIP documentation](https://docs.chain.link/ccip).
- Watching the following keynote speeches to understand CCIP's architecture and its inner workings:
  - [Architecting Secure Cross-Chain Infrastructure With CCIP](https://www.youtube.com/watch?v=speIh3ctygM)
  - [Ben Chan: Exploring the Cross-Chain Interoperability Protocol (CCIP)](https://www.youtube.com/watch?v=HhK6maZxX68)
- Looking through Solodit for audits of similar protocols, mainly anything with cross-chain or bridging functionality.

Preparing myself prior ended up paying off well - I already had the entire protocol mapped out in my mind before the contest began. In the first week, I immediately started looking into the contracts at a detailed level and gained an understanding of how each contract worked. The second week was spent thinking of possible attack vectors and thoroughly looking through the codebase for bugs. 

This approach worked out well - I would end up finding 3/3 highs to finish 8th, which was my first time being in the top 10 for a contest.

Now, if anyone were to ask me at which point did I start to get the hang of auditing, I would point to this contest. I had found an approach that worked for me - focus on understanding the codebase in its entirety, and then start looking for bugs afterwards. I actually elaborate more on this (and the whole CCIP contest) in [my interview with JohnnyTime](https://www.youtube.com/watch?v=g5Obbl0cAwk), do check it out if you want more details.

## July - A new legend is born

| Contest | Platform | SLOC | Findings | Ranking | Payout | 
|:--|:--:|:--:|:--:|:--:|:--:|
| [LUKSO](https://code4rena.com/contests/2023-06-lukso) | Code4rena | 3469 | 6 M | #1 | $44,459.52 |
| [Lens Protocol V2](https://code4rena.com/contests/2023-07-lens-protocol-v2) | Code4rena | 4108 | 8 M | #1 | $29,747.31 |
| Total | | 7577 | 14 M | | $74,206.83 |

This was my best month - I reviewed ~7.5K SLOC and found 14 medium bugs, earning **over $74K in rewards in a single month.** There were two factors that led to this insane result. 

Firstly, July had a huge number of contests ongoing. In chronological order, they were:

| Contest | Prize Pool | Date | 
| :- | :--: | :--:| 
| LUKSO | $100K | 1 Jul - 15 Jul |
| Nouns DAO | $100K | 4 Jul - 14 Jul |
| Basin | $40K | 4 Jul - 11 Jul |
| Tapioca DAO | $390K | 6 Jul - 5 Aug |
| Chainlink CCIP Administration | $47.9K | 6 Jul - 13 Jul |
| PoolTogether | $121.65K | 8 Jul - 15 Jul |
| Axelar Network | $80K | 13 Jul - 22 Jul |
| Lens Protocol V2 | $85.5K | 18 Jul - 1 Aug |
| Arcade.xyz | $90.5K | 22 Jul - 29 Jul |
| Amphora Protocol | $65.5K | 22 Jul - 7 Jul |
| Moonwell | $100K | 25 Jul - 1 Aug |

That's **11 contests and ~$1.2M in rewards** over the span of one month, and that's not even including invitationals or mitigation reviews. When there are so many contests ongoing during the same period of time, competition becomes spread out, so awards naturally tend to become larger.

Secondly, both contests I took part in this month happened to be what I excelled at - non-typical protocols that didn't fall under your usual categories (e.g. staking, lending, AMM), and required creativity to identify bugs due to their unique implementations.

### LUKSO

An extremely interesting project with an even more awesome team. 

Their aim was to launch their own L1 EVM blockchain, with the goal of solving the problems observed on Ethereum the past few years. Just like how Ethereum has its [EIPs](https://eips.ethereum.org/), LUKSO has its own [LIPs](https://github.com/lukso-network/LIPs).

Additionally, the protocol clearly took security seriously. How did I know? Well, we were greeted with this upon opening [the contest page](https://github.com/code-423n4/2023-06-lukso#previous-audits):

<img src="{{site.baseurl}}/assets/images/LUKSO_previous_audits.png" width=800>

I think many wardens were scared off by the sight of all their previous audits and decided to participate in other contests instead.

Despite this, I would end up finding [6/8 medium bugs](https://code4rena.com/reports/2023-06-lukso) in this contest. This taught me that a huge number of audits doesn't mean a codebase is 100% secure - there's always one more bug that someone missed, or one more edge-case that the devs didn't consider. 

Another interesting point is that I had actually found the the other two medium bugs, just that I thought they considered "acceptable risks" as part of the protocol's design and didn't think they were bugs at all. 

The lesson to learn here - when you're unsure of a bug's severity, always ask the protocol team whether the behavior you observe is intended. If this isn't an option, you can always log what you found as low severity or informational, such that the protocol team can pick up on it when reading your report.

The protocol team would eventually approach me a few months down the road [to review their changes and fixes](https://github.com/MiloTruck/audits/blob/main/pdf/LUKSO%20Audit%20Report%202.pdf) before their mainnet launch.

### Lens Protocol V2

Lens Protocol is essentially a social network, similar to Twitter, but onchain.

This contest was an audit of their V2 upgrade from the existing V1 system, which consisted of ~4K SLOC. As of writing this, the findings still aren't public, so I can't say much.

What gave me an edge over other wardens was being thorough - I had an entire two weeks to go through the entire codebase, so I was able to dig deep into every part of the protocol and think of the implications of every line. I also reviewed their V1 contracts onchain to look for bugs pertaining to migrations, or any way to brick the V2 system by leveraging functionality in the V1 protocol.

This served me well - I would end up with 8/11 medium findings, which is 72% of all the bugs. I was also congratulated by the judge afterwards, which was a nice motivational boost.

<p align="center">
  <img src="{{site.baseurl}}/assets/images/picodes_msg.jpg" width=500> 
</p>

The protocol team would later reach out to me and [@0xJuancito](https://twitter.com/0xJuancito) for a review of their fixes, modifications and additions to the codebase. 

## August - Rising to the top

| Contest | Platform | SLOC | Findings | Ranking | Payout | 
|:--|:--:|:--:|:--:|:--:|:--:|
| [Arbitrum Security Council Elections](https://code4rena.com/contests/2023-08-arbitrum-security-council-election-system) | Code4rena | 2184 | 1 H, 3 M | #1 | $15,482.70 |
| [StakeWise V3](https://stakewise.io/) | Hats Finance | 3497 | 1 M, 3 L | #1 | $11,703 |
| Total | | 5681 | 1 H, 3 M | | $27,185.7 |

I participated in two contests in August, but you can already see that. Part of the month also went to hunting for bugs on Immunefi in between the two contests, where I found a few small bugs that I can't disclose.

### Arbitrum SC Elections

This was my first time reviewing a protocol related to governance. 

I was quite familiar with governance-related concepts (e.g. quorum, vote accounting) as I had looked at [SushiSwap's voting](https://medium.com/valixconsulting/sushiswap-voting-vulnerability-of-sushi-token-and-its-forks-56f220d4c9ba#:~:text=Overview%20of%20SUSHI%20Token's%20Voting%20Functionality,-Figure%201.&text=The%20SUSHI%20token%20holders%20can%20even%20delegate%20their%20votes%2C%20representing,as%20portrayed%20in%20Figure%201.) and other mechanisms while doing bug bounties before, but never got the chance to fully audit a codebase centered around governance.

I only spent four days on this contest, which went something like:

- 2 days to understand the protocol
- 1.5 days to find bugs
- A few hours to write up all my findings

Now I don't recommend rushing contests, or any audit for that matter, like this.

But it worked out pretty well for me - I would find 1/1 high and 3/5 medium severity bugs. I was quite satisfied with this result - I had identified all the bugs that, in my opinion, were important or worth fixing.

What was interesting was [the high severity bug](https://github.com/code-423n4/2023-08-arbitrum-findings/issues/252) - a signature replay that allowed attackers to use up someone else's votes due to a flawed implementation with Openzeppelin's [`GovernorUpgradeable.sol`](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/release-v4.7/contracts/governance/GovernorUpgradeable.sol) library. 

Openzeppelin's governance contracts were modelled after [Compound V2's governance](https://docs.compound.finance/v2/governance/) and were not built to be used for partial voting, which Arbitrum's elections allowed. If I hadn't taken the time to review the codebase's external dependencies and only focused on the contracts in-scope, I would have never found this bug. 

### StakeWise V3

My first contest on Hats Finance!

I won't delve into how contests on Hats Finance work, but essentially it's similar to traditional bug bounty contests - only the first submission gets paid out, and the project only pays a fixed amount for each bug they fix, depending on its severity.

Although my results from this contest were pretty good, I'm not too fond of this audit contest model. This is mainly due to the additional time pressure - I like to write PoCs and detailed explanations for my findings, which are unfortunately disincentivized in Hats Finance contests due to its first-come-first-serve rule.

StakeWise V3 was another protocol built around Liquid Ethereum Staking, similar to EigenLayer. 

A lot of time in this contest was spent on researching about Ethereum staking - how penalties and slashing worked, how other Liquid Staking Derivative protocols were built, and what were the common vulnerabilities for this category of protocols.

I would end up finding [all the bugs except one](https://github.com/hats-finance/StakeWise-0xd91cd6ed6c9a112fdc112b1a3c66e47697f522cd/issues?q=is%3Aopen+is%3Aissue+label%3AHigh%2CMedium%2CLow), among which was [a medium severity finding](https://github.com/hats-finance/StakeWise-0xd91cd6ed6c9a112fdc112b1a3c66e47697f522cd/issues/14) about using flashloans to steal yield that I submitted just 48 minutes after the contest started. This would also be the only bug above low severity for the entire contest.

## September - Momentum

| Contest | Platform | SLOC | Findings | Ranking | Payout | 
|:--|:--:|:--:|:--:|:--:|:--:|
| [Chainlink Staking v0.2](https://code4rena.com/contests/2023-08-chainlink-staking-v02) | Code4rena | 2538 | 10 M | #1 | $48,797.95 |

September was a pretty quiet month on Code4rena - Chainlink Staking v0.2 was the largest contest, with only [one other large contest](https://code4rena.com/contests/2023-09-maia-dao-ulysses) towards the end of the month. 

### Chainlink Staking v0.2

It's a classified contest, so no details about findings. 

At this point I was very familiar with staking and reward mechanisms, having audited quite a few of them throughout the year.

Given that this contest had a $190K prize pool, it ended up becoming one of the most heavily participated contests of 2023, with 1,031 submissions and 104 wardens getting a payout. Nevertheless, I managed to find 10 medium severity bugs and finish in 1st place.

## October - Slowing down?

| Contest | Platform | SLOC | Findings | Ranking | Payout | 
|:--|:--:|:--:|:--:|:--:|:--:|
| [Wildcat](https://code4rena.com/contests/2023-10-the-wildcat-protocol) | Code4rena | 2332 | 3 H, 7 M | #2 | $10,093.23 |

I didn't have a lot of time for contests in October, which is why I ended up participating in only one contest. 

A small part of the month also went to Immunefi bug hunting, during which I found this [high severity bug in Arcade.xyz](https://github.com/MiloTruck/audits/blob/main/immunefi/arcadexyz-H-01.md) that was closed as a duplicate.

### Wildcat

[@functi0nZer0](https://twitter.com/functi0nZer0) told us to take his money in the [contest's README](https://github.com/code-423n4/2023-10-wildcat/tree/main), so that's what I did.

> # The Wildcat Protocol
> Greetings, everyone! It's time to take our money!

Unfortunately, I didn't take enough money for 1st place.

<p align="center">
    <img src="{{site.baseurl}}/assets/images/paperparachute_msg.png" width=600>
</p>

Wildcat was a lending protocol with a twist - instead of having a pool of lenders offering loans, borrowers would open markets for lenders to deposit into. In return, they would receive tokens that gradually increased in value by rebasing to reflect the loan's interest rate.

This was my first time reviewing protocol that implemented a rebasing tokens. Apart from that, I was quite familiar with lending protocols at this point in time.

I would end up with 3/5 highs and 7/10 medium findings, including [a bug about using `.codehash` to check for contract existence](https://github.com/code-423n4/2023-10-wildcat-findings/issues/491) that I was thought was a pretty sick find.

I had missed a few bugs simply because I didn't read the protocol's documentation or whitepaper. One of them was even found by 37 wardens! I actually knew that the code would behave in a certain a way, but thought that these "features" were intended functionality instead of bugs.

My takeaway from this contest - always allocate some time to go through the documentation or whitepaper to look for inconsistencies with the code. This should be done near the end of the audit, where you have a good mental picture of the protocol and its functionality.

## Some gaps in the timeline

Those who are observant will probably have a few questions.

### 1. What happened in May? 
 
Well, I went on a overseas CTF + vacation in Korea with my friends for most of the month. The rest of the time in May was spent refining Regast and preparing for the Chainlink CCIP contest aftewards.

Something worth noting is that Regast actually managed to qualify for bot races later on, but I would end up not participating in any future bot races as Code4rena contests start at 4am where I live.

<img src="{{site.baseurl}}/assets/images/bot_race_qualify_msg.png" width=800>

### 2. Why isn't November included?

In the first half of November, I performed [a solo audit for Cega Finance](https://docs.cega.fi/cega/products/audits-and-security), which is my first (and only) ever "proper" solo audit till date. What I mean by "proper" - it's my only solo audit where I reviewed a codebase larger 500 SLOC from scratch to find bugs.

I also participated in my first review under [Spearbit](https://spearbit.com/) as an Associate Security Researcher (ASR) soon after.

### 3. You seem to have slowed down in contests after August, why?

A huge portion of my time was occupied by real-life commitments, and I was also exploring other opportunities during these months.

More specifically, during the second half of September, I had:
- A mitigation review for Lens Protocol after winning their contest. This would be my first ever private audit.
- [Asymmetry's AfEth invitational ](https://code4rena.com/contests/2023-09-asymmetry-finance-afeth-invitational) on Code4rena.

In October, after the Wildcat contest, I did two small private audits:
  - A [review of changes and fixes for LUKSO](https://github.com/MiloTruck/audits/blob/main/pdf/LUKSO%20Audit%20Report%202.pdf) after winning their contest.
  - An [audit for EPOCH island](https://github.com/MiloTruck/audits/blob/main/pdf/Epoch%20Island%20Audit%20Report.pdf).

## How did I achieve this?

Overall, my results from this year were good enough to reach the top of Code4rena's 2023 leaderboard in November.

<img src="{{site.baseurl}}/assets/images/c4_leaderboard.png" width=800>

I attribute my results to mostly two traits:

**1. I'm extremely competitive.**

I'm _very_ competitive, to the point that it borders on overly-competitive  sometimes. This allowed me to thrive in audit contests as I was constantly pushing myself to find more bugs, think of more creative attack vectors and one-up the competition. 

Even for the contests that I did win, most notably [LUKSO](https://code4rena.com/contests/2023-06-lukso), [Lens Protocol V2](https://code4rena.com/contests/2023-07-lens-protocol-v2) and [Chainlink Staking v0.2](https://code4rena.com/contests/2023-08-chainlink-staking-v02), I would focus on the bugs that I had missed and how I could adapt my auditing methodology, such that I wouldn't miss the same bugs in the future.

[Arbitrum Security Council Elections](https://code4rena.com/contests/2023-08-arbitrum-security-council-election-system) and [StakeWise V3](https://app.hats.finance/audit-competitions/stakewise-0xd91cd6ed6c9a112fdc112b1a3c66e47697f522cd/leaderboard) were the only two contests where I was truly satisfied with what I had found and how I performed.

**2. I hold myself to a pretty high standard.**

There were two metrics that I took pride in - having a low false positive rate and producing high quality reports. 

Even when I first started out,
[I](https://github.com/code-423n4/2023-02-ethos-findings/issues/768) 
[wrote](https://github.com/code-423n4/2023-03-wenwin-findings/issues/245)
[a](https://github.com/code-423n4/2023-03-polynomial-findings/issues/206)
[coded](https://github.com/code-423n4/2023-03-polynomial-findings/issues/236)
[PoC](https://github.com/code-423n4/2023-03-polynomial-findings/issues/146)
[for](https://github.com/code-423n4/2023-03-asymmetry-findings/issues/705)
[nearly](https://github.com/code-423n4/2023-03-asymmetry-findings/issues/846)
[every](https://github.com/code-423n4/2023-03-asymmetry-findings/issues/1138)
[single](https://github.com/code-423n4/2023-03-asymmetry-findings/issues/883)
[one](https://github.com/code-423n4/2023-04-frankencoin-findings/issues/915)
[of](https://github.com/code-423n4/2023-06-lukso-findings/issues/124)
[my](https://github.com/code-423n4/2023-06-lukso-findings/issues/123)
[findings](https://github.com/code-423n4/2023-08-arbitrum-findings/issues/254).
I believe this helped me to develop a solid foundation in understanding protocols, since I was essentially forced to figure out how they worked in-depth to write PoCs and validate my findings.

Something else that contributed was my mindset - I treat every audit contest as though it is a solo audit, where there isn't room for:

- Missing out on critical/high bugs.
- Reporting false bugs to the client.
- Providing bad recommendations, or worse, ones that introduce _another_ bug.

# Are contests worth it?

A somewhat heavily discussed topic I've seen pop up many times the past year is whether audit contests are worth it for top security researchers to participate in. Given that it's soon to be 2024 and you can no longer [earn $1 million purely from contests](https://cmichel.io/code4rena-first-1m-stats/) anymore, it's only natural that this becomes a point for contention.

[This tweet](https://twitter.com/alpeh_v/status/1726894008109256977) from [@alpeh_v](https://twitter.com/alpeh_v) and some other messages I've seen aptly sums up how contests might no longer have the best incentives for the top talent:

<p align="left">
    <img src="{{site.baseurl}}/assets/images/alpeh_msg.png" width=450>
    <img src="{{site.baseurl}}/assets/images/midrange_swe_msg.png" width=350>
</p>

Sherlock attempted to solve this problem with its [Lead Senior Watson (LSW)](https://docs.sherlock.xyz/audits/watsons/lead-senior-watson-selection-process) model, which allocated a fixed amount of the prize pool to a top security researcher just for participating in a contest. 

Understandably, it incited an extremely negative reaction from many auditors, especially since LSWs were getting insane amounts of money at the expense of all other watsons.

<p align="center">
  <img src="{{site.baseurl}}/assets/images/sherlock_lsw_pay.png" width=400 class="center">
</p>

This, amongst many other things, had arguably driven away many security researchers from Sherlock.

<p align="center">
  <img src="{{site.baseurl}}/assets/images/sherlock_coverage.png" width=500>
  <br>  
  <em> There were only 5 auditors with valid bugs in a $71.5K contest with 3 highs and 13 mediums </em>
</p>

Now, I'm not bringing this up because I dislike Sherlock or want to criticize their audit contest model. In fact, it's great that they're actively trying to find a way to retain the top talent, which is arguably the largest problem of the audit contest model as of now.

The point is - financial incentives for auditors in contests are clearly diminishing. I made ~$172K in competitive audits for consistently performing at what I would consider the top level in the second half of the year. It's by no means a small amount, don't get me wrong, but there are many more lucrative avenues out there:

- Find a critical bug (or multiple ones) doing bug bounties. The most prominent example would be [@100proof](https://twitter.com/1_00_proof), who netted a [$1M bounty from a single bug in KyberSwap](https://100proof.org/kyberswap-post-mortem.html). 
- Go the private auditor route - tweet aggressively and market yourself well, which [@pashovkrum](https://twitter.com/pashovkrum) and [@bytes032](https://twitter.com/bytes032) have done this year. [@PopPunkOnChain](https://twitter.com/PopPunkOnChain) also singlehandedly carved out a niche in gas audits (amusedly by dunking on people on Twitter).
- Work for a high-paying firm. The most obvious would be [Spearbit](https://spearbit.com/), which pays [$20K per week](https://docs.spearbit.com/spearbook/anatomy-of-a-spearbit-review/sow-and-rates#base-rates) to its top security researchers.

It's clear that if your goal as a security researcher is to earn as much money as possible, audit contests is not where you will achieve this.

**However, contests are great for those who have talent but can't find opportunity.**

As a security researcher, competitive audits are an undisputable way of demonstrating your skills. For firms, they are an unreasonably effective way of finding new and proven talent. 

Don't take my word for it, [@_hrkrshnn](https://twitter.com/_hrkrshnn) himself said this:

<img src="{{site.baseurl}}/assets/images/hari_msg.png" width=800>

In fact, this was what happened to me. A few days after I had posted [this tweet](https://twitter.com/milotruck/status/1702502451105165609), he reached out to me to join Spearbit. Soon after, [@trust_90](https://twitter.com/trust__90) also offered me a place in [Trust Security](https://www.trust-security.xyz/).

Additionally, for aspiring individuals that currently aren't performing at the top-level yet, contests are (in my opinion) the best way to hone your skills. The feedback loop that contests provide is invaluable - where else will you have the opportunity to see what bugs you missed in the code immediately after you finish auditing?

All in all, [this tweet](https://twitter.com/1_00_proof/status/1727106958430519345) sums up my points here pretty neatly:

<img src="{{site.baseurl}}/assets/images/100proof_tweet.png" width=800>

Many top security researchers from the 2021-2022 era have since moved on from competitive audits for more appealing opportunities, but I believe most, if not all of them, have a high regard for Code4rena as it is where they first started out.

# 2024: What's next?

**Contests:** I'll still be participating in contests on both Code4rena and Cantina, possibly not as often as this year.

**Bug Bounties:** This is something that's been on my mind for a period of time now. Throughout the past year, I've hunted for bugs on Immunefi in between contests when I was free, but never actually spent an extended period of time just doing bug bounties. I'll probably dedicate more time to hunting on Immunefi in the future.

**Collaborative Audits:** If the opportunity arises from Trust Security or Spearbit - there are many top security researchers in both that I would love to collaborate with and learn from. But honestly, it's kind of hard to get work under Spearbit since they already have many established names among their ranks.

**Solo Audits:** Like every other auditor out there, I would love to do more solo audits. However, this is what my DMs currently look like:

<p align="center">
  <img src="{{site.baseurl}}/assets/images/tumbleweed-crickets-chirping.gif" width=400>
</p>

Most of my solo audits so far have been [from Code4rena](https://code4rena.com/@MiloTruck) or protocols approaching me after I won their audit contest. I've only ever had three possible clients reach out to me directly for a fresh audit, and only one of them actually took place.

# Conclusion

Wow, this post ended up becoming way longer than I expected it to be. I could honestly turn this into an entire presentation if I wanted.

My goal was to provide an honest look into landscape of competitive audits from a security researcher's perspective, and possibly leave some of you with inspiration and insight into how to grow your skills and career in Web3 security.

Despite the many flaws of the audit contest model, it has undoubtedly created a positive and long-lasting impact on Web3 security as a whole. For myself, contests have opened many doors and provided me with great opportunities in the space, and hopefully it will do the same for many more aspiring individuals in the future.

_cue self-promotion_

If you're a protocol team reading this, feel free to reach out to me for solo audits on [Twitter](https://twitter.com/home) or explore more of my work in [this repository](https://github.com/MiloTruck/audits). Alternatively, you could ask for me on a [Spearbit](https://spearbit.com/) or [Cantina Managed](https://cantina.xyz/u/milotruck) review with other security researchers.

_end of self-promotion_

<p align="center">
  <img src="{{site.baseurl}}/assets/images/dm_for_audit_meme.jpg" width=500> 
</p>
