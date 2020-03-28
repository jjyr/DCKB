# WCKB

WCKB is an extended UDT, 1 to 1 mapping to native CKB.

WCKB allows your free to move your coins while the native CKB still locked in NervosDAO to earn compensation.

## Build

``` sh
make all-via-docker && cargo test
```

## Usage


1,  SWAP WCKB

```
inputs:
  - capacity: X
output:
  - capacity: X - 140
    type: <dao>
    lock: <always success> # should be a special lock in the real world
    data: <0(8 bytes)>
  - capacity: 140
    type: <wckb>
    lock: <secp256k1 single lock>
    data: <X - 140(16 bytes) | 0(8 bytes)>
```

2, Transfer WCKB:


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
    type: <wckb>
    lock: <alice>
    data: <2000 | 0(8 bytes)>
  - capacity: 140
    type: <wckb>
    lock: <bob>
    data: <1000 | 100(8 bytes)>
output:
  - capacity: 140
    type: <wckb>
    lock: <alice>
    data: <1020 | 100(8 bytes)>
  - capacity: 140
    type: <wckb>
    lock: <bob>
    data: <2000 | 100(8 bytes)>
```

3, Withdraw WCKB:

1. Perform NervosDAO withdraw phase 1.
2. Prepare a WCKB input that has enough coins to cover the withdraw CKB
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
    type: <wckb>
    data: <1000(16 bytes) | 20(8 bytes, block number)>
output:
  - capacity: X
    lock: <alice lock> # withdrawed CKB
  - capacity: 140
    type: <wckb>
    lock: <alice lock>
    data: <200(16 bytes) | 200(8 bytes)> # withdrawed WCKB
```

## License

MIT
