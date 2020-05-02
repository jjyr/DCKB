# DCKB

DCKB means (DAO/Deposited) CKB.

DCKB is an extended UDT that 1 to 1 mapping to NervosDAO deposited CKB, it enables users to transfer CKB from NervosDAO while still get NervosDAO compensation.

Advantages:

* Deposit CKB to layer2 / Defi while still earning NervosDAO compensation.
* Transfer CKB from NervosDAO.
* No centralized service involved.

Known limitation:

* After deposition, users need to wait for 4 epochs(~16 hours in mainnet) to use DCKB.
* Max deposition limitation is 10_000_000 CKB at once.

## Build

``` sh
make build && cargo test
```

## Usage

Contracts:

* DCKB - an extended UDT type script
* DAOLock - NervosDAO cell's lock script
* CustodianLock - lock script, used for custodian DCKB while withdraw from NervosDAO

[Documentation](https://github.com/jjyr/DCKB/wiki/Documentation)

## License

MIT

Copyright, 2020, by [JJy](https://justjjy.com)
