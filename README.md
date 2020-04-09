# DCKB

DAO / Deposit CKB.

DCKB is an extended UDT; it allows users to deposit CKB to NervosDAO to get compensation while they can still change ownership of the coins.

Usecase & Advantages:

* Deposit CKB to layer2 and still earning NervosDAO compensation.
* Deposit CKB to Defi and still earning NervosDAO compensation.
* No centralized service involved.

## Build

``` sh
make all-via-docker && cargo test
```

## Usage

### DCKB type

1,  SWAP DCKB

```
inputs:
  - capacity: X
output:
  - capacity: X - 140
    type: <dao>
    lock: <always success> # should be a special lock in the real world
    data: <0(8 bytes)>
  - capacity: 140
    type: <dckb>
    lock: <secp256k1 single lock>
    data: <X - 140(16 bytes) | 0(8 bytes)>
```

2, Transfer DCKB:


1. set witnesses args to index of aligned header.
2. align all inputs to header block number by apply DAO formula.
3. calculate output.

```
header_deps:
  - input1 header
  - input2 header
witnesses:
  - type: 1(8 bytes, index of header)
inputs:
  - capacity: 140
    type: <dckb>
    lock: <alice>
    data: <2000 | 0(8 bytes)>
  - capacity: 140
    type: <dckb>
    lock: <bob>
    data: <1000 | 100(8 bytes)>
output:
  - capacity: 140
    type: <dckb>
    lock: <alice>
    data: <1020 | 100(8 bytes)>
  - capacity: 140
    type: <dckb>
    lock: <bob>
    data: <2000 | 100(8 bytes)>
```

3, Withdraw DCKB:

1. Perform NervosDAO withdraw phase 1.
2. Prepare a DCKB input that has enough coins to cover the withdraw CKB
coins.
3. Put a withdrawed output.

```
header_deps:
  - withdraw1 cell header
  - input2 header
inputs:
  - capacity: 1000
    type: <dao>
    data: <100(8 bytes, deposit block number)>
  - capacity: 140
    type: <dckb>
    data: <1000(16 bytes) | 20(8 bytes, block number)>
output:
  - capacity: X
    lock: <alice lock> # withdrawed CKB
  - capacity: 140
    type: <dckb>
    lock: <alice lock>
    data: <200(16 bytes) | 200(8 bytes)> # withdrawed DCKB
```


### CKB deposit lock

> This lock script is not implemented yet.

This lock script is used as deposited NervosDAO lock in `DCKB` swap.

The first intention of this lock script is to allows anyone that hold `DCKB` to withdraw deposited CKB from NervosDAO no matter who is the original depositor.

The second intention is to prevent "half withdraw" situation:

DCKB holder reveives interest at every block height, just like the original NervosDAO.
When a holder try to withdraw from NervosDAO, the holder will send a phase 1 withdraw tx, and the NervosDAO interests will stopped at the block number that phase 1 withdraw get submmited on chain.

This is the withdraw process of NervosDAO, the problem is when we perform the withdraw process, at the phase 1, the NervosDAO CKB interests is stopped, but `DCKB` can't noticed, the interests of `DCKB` will still going on, until user perform the phase 2 withdraw and destroy corresponded `DCKB` (the deposited CKB + interests).

This works fine if everyone follow the rules. But image a situation, that a user perform the phase 1 withdraw, and not perform the phase 2 withdraw; and the user transfer DCKB to other people instead withdraw the native CKB, since after phase 1 withdraw the NervosDAO interests is stopped, the total `DCKB` coins will be more than the `CKB` coins locked in NervosDAO, this behavior breaks the 1 : 1 mapping relationship.

To solve this problem, the lock requires that phase 1 withdraw must destroy `DCKB` correspond to the original deopsit CKB in the NervosDAO; at phase 2 withdraw, the user only need to pay `DCKB` for the NervosDAO interests; to prevent a user stop perform phase 2 withdraw, after a period of time(say 100 blocks), anyone can pay `DCKB` only for to the interests part to withdraw coins. This mechanism incentives users to always get `DCKB` destroyed.

## License

MIT
