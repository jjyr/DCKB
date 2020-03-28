use super::{sign_tx, DummyDataLoader, MAX_CYCLES, WCKB};
use byteorder::{ByteOrder, LittleEndian};
use ckb_crypto::secp::{Generator, Privkey};
use ckb_dao_utils::pack_dao_data;
use ckb_script::TransactionScriptsVerifier;
use ckb_system_scripts::BUNDLED_CELL;
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMeta, CellMetaBuilder, ResolvedTransaction},
        BlockNumber, Capacity, DepType, EpochExt, EpochNumber, EpochNumberWithFraction,
        HeaderBuilder, HeaderView, ScriptHashType, TransactionBuilder, TransactionInfo,
        TransactionView,
    },
    packed::{Byte32, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
};
use lazy_static::lazy_static;
use rand::{thread_rng, Rng};

lazy_static! {
    static ref DAO_BIN: Bytes = Bytes::from(
        BUNDLED_CELL
            .get("specs/cells/dao")
            .expect("read from bundle")
            .to_owned()
            .to_vec()
    );
    static ref SIGHASH_ALL_BIN: Bytes = Bytes::from(
        BUNDLED_CELL
            .get("specs/cells/secp256k1_blake160_sighash_all")
            .expect("read from bundle")
            .to_owned()
            .to_vec()
    );
    static ref SECP256K1_DATA_BIN: Bytes = Bytes::from(
        BUNDLED_CELL
            .get("specs/cells/secp256k1_data")
            .expect("read from bundle")
            .to_owned()
            .to_vec()
    );
    static ref WCKB_CAPACITY: Capacity = Capacity::bytes(65).expect("bytes");
}

const DAO_TYPE_ID: [u8; 32] = [0u8; 32];

fn wckb_script() -> Script {
    let code_hash = CellOutput::calc_data_hash(&WCKB);
    Script::new_builder()
        .code_hash(code_hash)
        .hash_type(ScriptHashType::Data.into())
        .args(Bytes::from(DAO_TYPE_ID.to_vec()).pack())
        .build()
}

fn wckb_data(ckb: u128, block_number: u64) -> Bytes {
    let mut data = [0u8; 24];
    data[..16].copy_from_slice(&ckb.to_le_bytes()[..]);
    data[16..].copy_from_slice(&block_number.to_le_bytes()[..]);
    data.to_vec().into()
}

fn wckb_cell_output() -> CellOutput {
    CellOutput::new_builder()
        .capacity(WCKB_CAPACITY.pack())
        .type_(Some(wckb_script()).pack())
        .build()
}

fn cell_output_with_only_capacity(shannons: u64) -> CellOutput {
    CellOutput::new_builder()
        .capacity(Capacity::shannons(shannons).pack())
        .build()
}

fn generate_random_out_point() -> OutPoint {
    let tx_hash = {
        let mut rng = thread_rng();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        buf.pack()
    };
    OutPoint::new(tx_hash, 0)
}

fn script_cell(script_data: &Bytes) -> (CellOutput, OutPoint) {
    let out_point = generate_random_out_point();

    let cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(script_data.len())
                .expect("script capacity")
                .pack(),
        )
        .build();

    (cell, out_point)
}

fn secp_code_hash() -> Byte32 {
    CellOutput::calc_data_hash(&SIGHASH_ALL_BIN)
}

fn dao_code_hash() -> Byte32 {
    CellOutput::calc_data_hash(&DAO_BIN)
}

fn gen_normal_cell(
    dummy: &mut DummyDataLoader,
    capacity: Capacity,
    lock_args: Bytes,
) -> (CellOutput, OutPoint) {
    let out_point = generate_random_out_point();

    let lock = Script::new_builder()
        .args(lock_args.pack())
        .code_hash(secp_code_hash())
        .hash_type(ScriptHashType::Data.into())
        .build();
    let cell = CellOutput::new_builder()
        .capacity(capacity.pack())
        .lock(lock)
        .build();
    dummy
        .cells
        .insert(out_point.clone(), (cell.clone(), Bytes::new()));

    (cell, out_point)
}

fn gen_wckb_cell(
    dummy: &mut DummyDataLoader,
    capacity: Capacity,
    lock_args: Bytes,
    height: BlockNumber,
) -> (CellOutput, OutPoint, Bytes) {
    let out_point = generate_random_out_point();

    let lock = Script::new_builder()
        .args(lock_args.pack())
        .code_hash(secp_code_hash())
        .hash_type(ScriptHashType::Data.into())
        .build();
    let type_ = wckb_script();
    let cell = CellOutput::new_builder()
        .capacity(WCKB_CAPACITY.pack())
        .lock(lock)
        .type_(Some(type_).pack())
        .build();
    let data = wckb_data(capacity.as_u64().into(), height);
    dummy
        .cells
        .insert(out_point.clone(), (cell.clone(), data.clone()));

    (cell, out_point, data)
}

fn gen_dao_cell(
    dummy: &mut DummyDataLoader,
    capacity: Capacity,
    lock_args: Bytes,
) -> (CellOutput, OutPoint) {
    let out_point = generate_random_out_point();

    let lock = Script::new_builder()
        .args(lock_args.pack())
        .code_hash(secp_code_hash())
        .hash_type(ScriptHashType::Data.into())
        .build();
    let type_ = Script::new_builder()
        .args(Bytes::new().pack())
        .code_hash(dao_code_hash())
        .hash_type(ScriptHashType::Data.into())
        .build();
    let cell = CellOutput::new_builder()
        .capacity(capacity.pack())
        .lock(lock)
        .type_(Some(type_).pack())
        .build();
    dummy
        .cells
        .insert(out_point.clone(), (cell.clone(), Bytes::new()));

    (cell, out_point)
}

fn gen_header(
    number: BlockNumber,
    ar: u64,
    epoch_number: EpochNumber,
    epoch_start_block_number: BlockNumber,
    epoch_length: BlockNumber,
) -> (HeaderView, EpochExt) {
    let epoch_ext = EpochExt::new_builder()
        .number(epoch_number)
        .start_number(epoch_start_block_number)
        .length(epoch_length)
        .build();
    let header = HeaderBuilder::default()
        .number(number.pack())
        .epoch(epoch_ext.number_with_fraction(number).pack())
        .dao(pack_dao_data(
            ar,
            Capacity::shannons(0),
            Capacity::shannons(0),
            Capacity::shannons(0),
        ))
        .build();
    (header, epoch_ext)
}

fn gen_lock() -> (Privkey, Bytes) {
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    // compute pubkey hash
    let pubkey_hash = {
        let ser_pk = pubkey.serialize();
        ckb_hash::blake2b_256(ser_pk)[..20].to_vec()
    };
    let lock_args = pubkey_hash.into();
    (privkey, lock_args)
}

fn complete_tx(
    dummy: &mut DummyDataLoader,
    builder: TransactionBuilder,
) -> (TransactionView, Vec<CellMeta>) {
    let (secp_cell, secp_out_point) = script_cell(&SIGHASH_ALL_BIN);
    let (secp_data_cell, secp_data_out_point) = script_cell(&SECP256K1_DATA_BIN);
    let (dao_cell, dao_out_point) = script_cell(&DAO_BIN);
    let (wckb_cell, wckb_out_point) = script_cell(&WCKB);

    let secp_cell_meta =
        CellMetaBuilder::from_cell_output(secp_cell.clone(), SIGHASH_ALL_BIN.clone())
            .out_point(secp_out_point.clone())
            .build();
    let secp_data_cell_meta =
        CellMetaBuilder::from_cell_output(secp_data_cell.clone(), SECP256K1_DATA_BIN.clone())
            .out_point(secp_data_out_point.clone())
            .build();
    let dao_cell_meta = CellMetaBuilder::from_cell_output(dao_cell.clone(), DAO_BIN.clone())
        .out_point(dao_out_point.clone())
        .build();
    let wckb_cell_meta = CellMetaBuilder::from_cell_output(wckb_cell.clone(), WCKB.clone())
        .out_point(wckb_out_point.clone())
        .build();

    dummy
        .cells
        .insert(secp_out_point.clone(), (secp_cell, SIGHASH_ALL_BIN.clone()));
    dummy.cells.insert(
        secp_data_out_point.clone(),
        (secp_data_cell, SECP256K1_DATA_BIN.clone()),
    );
    dummy
        .cells
        .insert(dao_out_point.clone(), (dao_cell, DAO_BIN.clone()));
    dummy
        .cells
        .insert(wckb_out_point.clone(), (wckb_cell, WCKB.clone()));

    let tx = builder
        .cell_dep(
            CellDep::new_builder()
                .out_point(secp_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(secp_data_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(dao_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(wckb_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .build();

    let mut resolved_cell_deps = vec![];
    resolved_cell_deps.push(secp_cell_meta);
    resolved_cell_deps.push(secp_data_cell_meta);
    resolved_cell_deps.push(dao_cell_meta);
    resolved_cell_deps.push(wckb_cell_meta);

    (tx, resolved_cell_deps)
}

#[test]
fn test_wckb_withdraw() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (deposit_header, deposit_epoch) = gen_header(1554, 10000000, 35, 1000, 1000);
    let (withdraw_header, withdraw_epoch) = gen_header(2000610, 10001000, 575, 2000000, 1100);
    let (cell, previous_out_point) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args.clone(),
    );
    let (wckb_cell, wckb_previous_out_point, wckb_cell_data) = gen_wckb_cell(
        &mut data_loader,
        Capacity::shannons(123468105678),
        lock_args,
        0,
    );

    data_loader
        .headers
        .insert(deposit_header.hash(), deposit_header.clone());
    data_loader
        .headers
        .insert(withdraw_header.hash(), withdraw_header.clone());
    data_loader
        .epoches
        .insert(deposit_header.hash(), deposit_epoch.clone());
    data_loader
        .epoches
        .insert(withdraw_header.hash(), withdraw_epoch.clone());

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1554);
    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from(&b[..]))
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: withdraw_header.hash(),
            block_number: withdraw_header.number(),
            block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
            index: 0,
        })
        .build();
    let input_wckb_cell_meta =
        CellMetaBuilder::from_cell_output(wckb_cell, Bytes::from(&wckb_cell_data[..]))
            .out_point(wckb_previous_out_point.clone())
            .transaction_info(TransactionInfo {
                block_hash: deposit_header.hash(),
                block_number: deposit_header.number(),
                block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
                index: 0,
            })
            .build();

    let resolved_inputs = vec![input_cell_meta, input_wckb_cell_meta];
    let mut resolved_cell_deps = vec![];
    let align_target_index: u64 = 0;

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1);
    let witness = WitnessArgs::new_builder()
        .type_(Bytes::from(&b[..]).pack())
        .build();
    let wckb_witness = WitnessArgs::new_builder()
        .type_(Bytes::from(&align_target_index.to_le_bytes()[..]).pack())
        .build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0x2003e8022a0002f3))
        .input(CellInput::new(wckb_previous_out_point, 0))
        .output(cell_output_with_only_capacity(123468105678))
        .output_data(Bytes::new().pack())
        .header_dep(withdraw_header.hash())
        .header_dep(deposit_header.hash())
        .witness(witness.as_bytes().pack())
        .witness(wckb_witness.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let mut verifier = TransactionScriptsVerifier::new(&rtx, &data_loader);
    verifier.set_debug_printer(|_hash, msg| println!("msg {}", msg));
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_wckb_transfer() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (header1, header1_epoch) = gen_header(1554, 10000000, 35, 1000, 1000);
    let (header2, header2_epoch) = gen_header(2000610, 10001000, 575, 2000000, 1100);
    let (wckb_cell1, wckb_previous_out_point1, wckb_cell_data1) = gen_wckb_cell(
        &mut data_loader,
        Capacity::bytes(100000).expect("bytes"),
        lock_args.clone(),
        0,
    );
    let (wckb_cell2, wckb_previous_out_point2, wckb_cell_data2) = gen_wckb_cell(
        &mut data_loader,
        Capacity::bytes(50000).expect("bytes"),
        lock_args,
        0,
    );

    data_loader.headers.insert(header1.hash(), header1.clone());
    data_loader.headers.insert(header2.hash(), header2.clone());
    data_loader
        .epoches
        .insert(header1.hash(), header1_epoch.clone());
    data_loader
        .epoches
        .insert(header2.hash(), header2_epoch.clone());

    let input_cell_meta =
        CellMetaBuilder::from_cell_output(wckb_cell1, Bytes::from(&wckb_cell_data1[..]))
            .out_point(wckb_previous_out_point1.clone())
            .transaction_info(TransactionInfo {
                block_hash: header1.hash(),
                block_number: header1.number(),
                block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
                index: 0,
            })
            .build();
    let input_wckb_cell_meta =
        CellMetaBuilder::from_cell_output(wckb_cell2, Bytes::from(&wckb_cell_data2[..]))
            .out_point(wckb_previous_out_point2.clone())
            .transaction_info(TransactionInfo {
                block_hash: header2.hash(),
                block_number: header2.number(),
                block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
                index: 0,
            })
            .build();

    let resolved_inputs = vec![input_cell_meta, input_wckb_cell_meta];
    let mut resolved_cell_deps = vec![];
    let align_target_index: u64 = 1;

    let wckb_witness = WitnessArgs::new_builder()
        .type_(Bytes::from(&align_target_index.to_le_bytes()[..]).pack())
        .build();
    // transfer 10000 from 1 to 2
    let builder = TransactionBuilder::default()
        .input(CellInput::new(wckb_previous_out_point1, 0))
        .input(CellInput::new(wckb_previous_out_point2, 0))
        .output(wckb_cell_output())
        .output_data(wckb_data(90009_98500000, header2.number()).pack())
        .output(wckb_cell_output())
        .output_data(wckb_data(60000_00000000, header2.number()).pack())
        .header_dep(header1.hash())
        .header_dep(header2.hash())
        .witness(wckb_witness.as_bytes().pack())
        .witness(WitnessArgs::default().as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let mut verifier = TransactionScriptsVerifier::new(&rtx, &data_loader);
    verifier.set_debug_printer(|_hash, msg| println!("msg {}", msg));
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_wckb_deposit() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (deposit_header, deposit_epoch) = gen_header(1554, 10000000, 35, 1000, 1000);
    let (withdraw_header, withdraw_epoch) = gen_header(2000610, 10001000, 575, 2000000, 1100);
    let (cell, previous_out_point) = gen_normal_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        lock_args.clone(),
    );

    data_loader
        .headers
        .insert(deposit_header.hash(), deposit_header.clone());
    data_loader
        .headers
        .insert(withdraw_header.hash(), withdraw_header.clone());
    data_loader
        .epoches
        .insert(deposit_header.hash(), deposit_epoch.clone());
    data_loader
        .epoches
        .insert(withdraw_header.hash(), withdraw_epoch.clone());

    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from(Vec::new()))
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: withdraw_header.hash(),
            block_number: withdraw_header.number(),
            block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
            index: 0,
        })
        .build();

    let resolved_inputs = vec![input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let (output_cell, _) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000 - WCKB_CAPACITY.as_u64()),
        lock_args.clone(),
    );
    let (wckb_output_cell, _, wckb_output_data) = gen_wckb_cell(
        &mut data_loader,
        Capacity::shannons(123456780000 - WCKB_CAPACITY.as_u64()),
        lock_args,
        0,
    );

    let b = [0; 8];
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0))
        .output(output_cell)
        .output_data(Bytes::from(b.to_vec()).pack())
        .output(wckb_output_cell)
        .output_data(wckb_output_data.pack())
        .witness(WitnessArgs::default().as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx(tx, &privkey);
    for dep in resolved_cell_deps2.drain(..) {
        resolved_cell_deps.push(dep);
    }
    let rtx = ResolvedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups: vec![],
    };

    let mut verifier = TransactionScriptsVerifier::new(&rtx, &data_loader);
    verifier.set_debug_printer(|_hash, msg| println!("msg {}", msg));
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}
