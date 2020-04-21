mod dckb;
mod deposit_lock;

use ckb_crypto::secp::Privkey;
use ckb_script::DataLoader;
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMeta, CellMetaBuilder},
        BlockExt, BlockNumber, Capacity, DepType, EpochExt, EpochNumber, HeaderBuilder, HeaderView,
        ScriptHashType, TransactionBuilder, TransactionView,
    },
    packed::{self, Byte32, CellDep, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
    H256,
};
use lazy_static::lazy_static;
use std::collections::HashMap;

use ckb_crypto::secp::Generator;
use ckb_dao_utils::pack_dao_data;
use ckb_system_scripts::BUNDLED_CELL;
use faster_hex::hex_decode;
use rand::{thread_rng, Rng};

pub const MAX_CYCLES: u64 = std::u64::MAX;
pub const SIGNATURE_SIZE: usize = 65;

// errors

lazy_static! {
    static ref DCKB: Bytes = Bytes::from(&include_bytes!("../../specs/cells/dckb")[..]);
    static ref DEPOSIT_LOCK: Bytes =
        Bytes::from(&include_bytes!("../../specs/cells/deposit_lock")[..]);
    static ref ALWAYS_SUCCESS: Bytes =
        Bytes::from(&include_bytes!("../../specs/cells/always_success")[..]);
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
    static ref DCKB_CAPACITY: Capacity = Capacity::bytes(65).expect("bytes");
}

#[derive(Default)]
pub struct DummyDataLoader {
    pub cells: HashMap<OutPoint, (CellOutput, Bytes)>,
    pub headers: HashMap<Byte32, HeaderView>,
    pub epoches: HashMap<Byte32, EpochExt>,
}

impl DummyDataLoader {
    fn new() -> Self {
        Self::default()
    }
}

impl DataLoader for DummyDataLoader {
    // load Cell Data
    fn load_cell_data(&self, cell: &CellMeta) -> Option<(Bytes, Byte32)> {
        cell.mem_cell_data.clone().or_else(|| {
            self.cells
                .get(&cell.out_point)
                .map(|(_, data)| (data.clone(), CellOutput::calc_data_hash(&data)))
        })
    }
    // load BlockExt
    fn get_block_ext(&self, _hash: &Byte32) -> Option<BlockExt> {
        unreachable!()
    }

    // load header
    fn get_header(&self, block_hash: &Byte32) -> Option<HeaderView> {
        self.headers.get(block_hash).cloned()
    }

    // load EpochExt
    fn get_block_epoch(&self, block_hash: &Byte32) -> Option<EpochExt> {
        self.epoches.get(block_hash).cloned()
    }
}

fn sign_tx(tx: TransactionView, key: &Privkey) -> TransactionView {
    let witnesses_len = tx.witnesses().len();
    sign_tx_by_input_group(tx, key, 0, witnesses_len)
}

fn sign_tx_by_input_group(
    tx: TransactionView,
    key: &Privkey,
    begin_index: usize,
    len: usize,
) -> TransactionView {
    let tx_hash = tx.hash();
    let mut signed_witnesses: Vec<packed::Bytes> = tx
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(i, _)| {
            if i == begin_index {
                let mut blake2b = ckb_hash::new_blake2b();
                let mut message = [0u8; 32];
                blake2b.update(&tx_hash.raw_data());
                // digest the first witness
                let witness = WitnessArgs::new_unchecked(tx.witnesses().get(i).unwrap().unpack());
                let zero_lock: Bytes = {
                    let mut buf = Vec::new();
                    buf.resize(SIGNATURE_SIZE, 0);
                    buf.into()
                };
                let witness_for_digest =
                    witness.clone().as_builder().lock(zero_lock.pack()).build();
                let witness_len = witness_for_digest.as_bytes().len() as u64;
                blake2b.update(&witness_len.to_le_bytes());
                blake2b.update(&witness_for_digest.as_bytes());
                ((i + 1)..(i + len)).for_each(|n| {
                    let raw_witness = match tx.witnesses().get(n) {
                        Some(data) => data.raw_data(),
                        None => Bytes::new(),
                    };
                    let witness_len = raw_witness.len() as u64;
                    blake2b.update(&witness_len.to_le_bytes());
                    blake2b.update(&raw_witness);
                });
                blake2b.finalize(&mut message);
                let message = H256::from(message);
                let sig = key.sign_recoverable(&message).expect("sign");
                witness
                    .as_builder()
                    .lock(sig.serialize().pack())
                    .build()
                    .as_bytes()
                    .pack()
            } else {
                tx.witnesses().get(i).unwrap_or_default()
            }
        })
        .collect();
    for i in signed_witnesses.len()..tx.witnesses().len() {
        signed_witnesses.push(tx.witnesses().get(i).unwrap());
    }
    // calculate message
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

fn dckb_script() -> Script {
    let code_hash = CellOutput::calc_data_hash(&DCKB);
    Script::new_builder()
        .code_hash(code_hash)
        .hash_type(ScriptHashType::Data.into())
        .build()
}

fn dckb_data(ckb: u128, block_number: u64) -> Bytes {
    let mut data = [0u8; 24];
    data[..16].copy_from_slice(&ckb.to_le_bytes()[..]);
    data[16..].copy_from_slice(&block_number.to_le_bytes()[..]);
    data.to_vec().into()
}

fn dckb_cell_output() -> CellOutput {
    CellOutput::new_builder()
        .capacity(DCKB_CAPACITY.pack())
        .type_(Some(dckb_script()).pack())
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

fn deposit_lock_code_hash() -> Byte32 {
    CellOutput::calc_data_hash(&DEPOSIT_LOCK)
}

fn dao_type_id_script() -> Script {
    let mut code_hash = [0u8; 32];
    hex_decode(
        b"00000000000000000000000000000000000000000000000000545950455f4944",
        &mut code_hash,
    )
    .expect("dehex");
    let mut args = [0u8; 32];
    hex_decode(
        b"b2a8500929d6a1294bf9bf1bf565f549fa4a5f1316a3306ad3d4783e64bcf626",
        &mut args,
    )
    .expect("dehex");
    Script::new_builder()
        .code_hash(code_hash.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(Bytes::from(args.to_vec()).pack())
        .build()
}

fn dao_type_id() -> Byte32 {
    dao_type_id_script().calc_script_hash()
}

fn gen_normal_cell(
    dummy: &mut DummyDataLoader,
    capacity: Capacity,
    lock_args: Bytes,
) -> (CellOutput, OutPoint) {
    let out_point = generate_random_out_point();

    let lock = gen_secp256k1_lock_script(lock_args);
    let cell = CellOutput::new_builder()
        .capacity(capacity.pack())
        .lock(lock)
        .build();
    dummy
        .cells
        .insert(out_point.clone(), (cell.clone(), Bytes::new()));

    (cell, out_point)
}

fn gen_dckb_cell(
    dummy: &mut DummyDataLoader,
    capacity: Capacity,
    lock_args: Bytes,
    height: BlockNumber,
) -> (CellOutput, OutPoint, Bytes) {
    let out_point = generate_random_out_point();

    let lock = gen_secp256k1_lock_script(lock_args);
    let type_ = dckb_script();
    let cell = CellOutput::new_builder()
        .capacity(DCKB_CAPACITY.pack())
        .lock(lock)
        .type_(Some(type_).pack())
        .build();
    let data = dckb_data(capacity.as_u64().into(), height);
    dummy
        .cells
        .insert(out_point.clone(), (cell.clone(), data.clone()));

    (cell, out_point, data)
}

fn gen_dao_cell(
    dummy: &mut DummyDataLoader,
    capacity: Capacity,
    lock: Script,
) -> (CellOutput, OutPoint) {
    let out_point = generate_random_out_point();

    let type_ = Script::new_builder()
        .code_hash(dao_type_id())
        .hash_type(ScriptHashType::Type.into())
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
fn gen_secp256k1_lock_script(lock_args: Bytes) -> Script {
    Script::new_builder()
        .args(lock_args.pack())
        .code_hash(secp_code_hash())
        .hash_type(ScriptHashType::Data.into())
        .build()
}

fn gen_deposit_lock_lock_script(lock_hash: [u8; 32]) -> Script {
    let args: [u8; 64] = {
        let mut args = [0u8; 64];
        let dckb_type_hash: [u8; 32] = Script::calc_script_hash(&dckb_script()).unpack();
        args[..32].copy_from_slice(&dckb_type_hash);
        args[32..].copy_from_slice(&lock_hash);
        args
    };
    Script::new_builder()
        .args(Bytes::from(args.to_vec()).pack())
        .code_hash(deposit_lock_code_hash())
        .hash_type(ScriptHashType::Data.into())
        .build()
}

fn complete_tx(
    dummy: &mut DummyDataLoader,
    builder: TransactionBuilder,
) -> (TransactionView, Vec<CellMeta>) {
    let (secp_cell, secp_out_point) = script_cell(&SIGHASH_ALL_BIN);
    let (secp_data_cell, secp_data_out_point) = script_cell(&SECP256K1_DATA_BIN);
    let (dao_cell, dao_out_point) = {
        // setup type id for dao_cell
        let (dao_cell, dao_out_point) = script_cell(&DAO_BIN);
        (
            dao_cell
                .as_builder()
                .type_(Some(dao_type_id_script()).pack())
                .build(),
            dao_out_point,
        )
    };
    let (dckb_cell, dckb_out_point) = script_cell(&DCKB);
    let (deposit_lock_cell, deposit_lock_out_point) = script_cell(&DEPOSIT_LOCK);

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
    let dckb_cell_meta = CellMetaBuilder::from_cell_output(dckb_cell.clone(), DCKB.clone())
        .out_point(dckb_out_point.clone())
        .build();
    let deposit_lock_cell_meta =
        CellMetaBuilder::from_cell_output(deposit_lock_cell.clone(), DEPOSIT_LOCK.clone())
            .out_point(deposit_lock_out_point.clone())
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
        .insert(dckb_out_point.clone(), (dckb_cell, DCKB.clone()));
    dummy.cells.insert(
        deposit_lock_out_point.clone(),
        (deposit_lock_cell, DEPOSIT_LOCK.clone()),
    );

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
                .out_point(dckb_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(deposit_lock_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .build();

    let mut resolved_cell_deps = vec![];
    resolved_cell_deps.push(secp_cell_meta);
    resolved_cell_deps.push(secp_data_cell_meta);
    resolved_cell_deps.push(dao_cell_meta);
    resolved_cell_deps.push(dckb_cell_meta);
    resolved_cell_deps.push(deposit_lock_cell_meta);

    (tx, resolved_cell_deps)
}
