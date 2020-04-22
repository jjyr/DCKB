use super::*;
use byteorder::{ByteOrder, LittleEndian};
use ckb_script::TransactionScriptsVerifier;
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMetaBuilder, ResolvedTransaction},
        Capacity, EpochNumberWithFraction, TransactionBuilder, TransactionInfo,
    },
    packed::{CellInput, WitnessArgs},
    prelude::*,
};

#[test]
fn test_deposit_lock_phase1_unlock() {
    // we simulate unlocking via proxy lock cell
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (deposit_header, deposit_epoch) = gen_header(1554, 10000000, 35, 1000, 1000);
    let (withdraw_header, withdraw_epoch) = gen_header(2000610, 10001000, 575, 2000000, 1100);

    // inputs cells
    let deposit_lock_script = gen_deposit_lock_lock_script(
        gen_secp256k1_lock_script(lock_args.clone())
            .calc_script_hash()
            .unpack(),
    );
    let proxy_lock_data: Bytes = {
        let deposit_lock_script_hash: [u8; 32] = deposit_lock_script.calc_script_hash().unpack();
        deposit_lock_script_hash[..8].to_vec().into()
    };
    let (cell, previous_out_point) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        deposit_lock_script,
    );
    let (dckb_cell, dckb_previous_out_point, dckb_cell_data) = gen_dckb_cell(
        &mut data_loader,
        Capacity::shannons(123468105678),
        lock_args.clone(),
        0,
    );
    let (fee_input_cell, fee_input_out_point) = gen_normal_cell(
        &mut data_loader,
        Capacity::bytes(61).unwrap(),
        lock_args.clone(),
    );
    // outputs cells
    let dckb_change_cell = CellOutput::new_builder()
        .capacity(DCKB_CAPACITY.pack())
        .lock(gen_secp256k1_lock_script(lock_args.clone()))
        .type_(Some(dckb_script()).pack())
        .build();
    let dckb_change_data = dckb_data((11325678u64 + DAO_OCCUPIED_CAPACITY).into(), 1554);
    let lock_proxy_cell = CellOutput::new_builder()
        .capacity(Capacity::bytes(61).unwrap().pack())
        .lock(gen_secp256k1_lock_script(lock_args))
        .build();
    let dao_withdraw_cell = cell.clone();
    let dao_withdraw_cell_data: Bytes = 1554u64.to_le_bytes().to_vec().into();

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
    // construct inputs cell meta info
    let b = [0; 8];
    let input_cell_meta = CellMetaBuilder::from_cell_output(cell, Bytes::from(&b[..]))
        .out_point(previous_out_point.clone())
        .transaction_info(TransactionInfo {
            block_hash: deposit_header.hash(),
            block_number: deposit_header.number(),
            block_epoch: deposit_epoch.number_with_fraction(deposit_header.number()),
            index: 0,
        })
        .build();
    let input_dckb_cell_meta =
        CellMetaBuilder::from_cell_output(dckb_cell, Bytes::from(&dckb_cell_data[..]))
            .out_point(dckb_previous_out_point.clone())
            .transaction_info(TransactionInfo {
                block_hash: deposit_header.hash(),
                block_number: deposit_header.number(),
                block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
                index: 0,
            })
            .build();
    let fee_input_cell_meta = CellMetaBuilder::from_cell_output(fee_input_cell, Bytes::new())
        .out_point(fee_input_out_point.clone())
        .build();

    let resolved_inputs = vec![input_cell_meta, input_dckb_cell_meta, fee_input_cell_meta];
    let mut resolved_cell_deps = vec![];

    let lock_proxy_cell_index: u8 = 1;
    let witness = WitnessArgs::new_builder()
        .lock(Bytes::from(vec![lock_proxy_cell_index]).pack())
        .type_(Bytes::from(&0u64.to_le_bytes()[..]).pack())
        .build();
    let dckb_witness = WitnessArgs::new_builder()
        .type_(Bytes::from(&0u64.to_le_bytes()[..]).pack())
        .build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0))
        .input(CellInput::new(dckb_previous_out_point, 0))
        .input(CellInput::new(fee_input_out_point, 0))
        .output(dao_withdraw_cell)
        .output_data(dao_withdraw_cell_data.pack())
        .output(lock_proxy_cell)
        .output_data(proxy_lock_data.pack())
        .output(dckb_change_cell)
        .output_data(dckb_change_data.pack())
        .header_dep(deposit_header.hash())
        .header_dep(withdraw_header.hash())
        .witness(witness.as_bytes().pack())
        .witness(dckb_witness.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx_by_input_group(tx, &privkey, 1, 2);
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
fn test_deposit_lock_phase2_unlock() {
    // in this test we simulate unlocking via proxy lock cell
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (deposit_header, deposit_epoch) = gen_header(1554, 10000000, 35, 1000, 1000);
    let (withdraw_header, withdraw_epoch) = gen_header(2000610, 10001000, 575, 2000000, 1100);
    // inputs
    let deposit_lock_script = gen_deposit_lock_lock_script(
        gen_secp256k1_lock_script(lock_args.clone())
            .calc_script_hash()
            .unpack(),
    );
    let proxy_lock_data: Bytes = {
        let deposit_lock_script_hash: [u8; 32] = deposit_lock_script.calc_script_hash().unpack();
        deposit_lock_script_hash[..8].to_vec().into()
    };
    let (cell, previous_out_point) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        deposit_lock_script,
    );
    let total_dckb = 123468105678;
    let (dckb_cell, dckb_previous_out_point, dckb_cell_data) = gen_dckb_cell(
        &mut data_loader,
        Capacity::shannons(total_dckb),
        lock_args.clone(),
        0,
    );
    let (lock_proxy_cell, lock_proxy_out_point) = gen_normal_cell(
        &mut data_loader,
        Capacity::bytes(61).unwrap(),
        lock_args.clone(),
    );
    // lock proxy cell and dao cell should generated from same tx
    let lock_proxy_out_point = lock_proxy_out_point
        .as_builder()
        .tx_hash(previous_out_point.tx_hash())
        .index(1u32.pack())
        .build();

    // outputs
    let dckb_change_cell = CellOutput::new_builder()
        .capacity(DCKB_CAPACITY.pack())
        .lock(gen_secp256k1_lock_script(lock_args.clone()))
        .type_(Some(dckb_script()).pack())
        .build();
    let dckb_change_data = dckb_data(123457220000u64.into(), 1554);
    let withdraw_cell = cell_output_with_only_capacity(total_dckb - DCKB_CAPACITY.as_u64()).as_builder().lock(
        gen_secp256k1_lock_script(lock_args.clone())
    ).build();

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
    let input_dckb_cell_meta =
        CellMetaBuilder::from_cell_output(dckb_cell, Bytes::from(&dckb_cell_data[..]))
            .out_point(dckb_previous_out_point.clone())
            .transaction_info(TransactionInfo {
                block_hash: deposit_header.hash(),
                block_number: deposit_header.number(),
                block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
                index: 0,
            })
            .build();
    let input_lock_proxy_cell_meta =
        CellMetaBuilder::from_cell_output(lock_proxy_cell, proxy_lock_data)
            .out_point(lock_proxy_out_point.clone())
            .transaction_info(TransactionInfo {
                block_hash: deposit_header.hash(),
                block_number: deposit_header.number(),
                block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
                index: 0,
            })
            .build();

    let resolved_inputs = vec![
        input_cell_meta,
        input_dckb_cell_meta,
        input_lock_proxy_cell_meta,
    ];
    let mut resolved_cell_deps = vec![];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1);
    let lock_proxy_cell_index: u8 = 2;
    let witness = WitnessArgs::new_builder()
        .lock(Bytes::from(vec![lock_proxy_cell_index]).pack())
        .type_(Bytes::from(&b[..]).pack())
        .build();
    let align_target_index: u64 = 1;
    let dckb_witness = WitnessArgs::new_builder()
        .type_(Bytes::from(&align_target_index.to_le_bytes()[..]).pack())
        .build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0x2003e8022a0002f3))
        .input(CellInput::new(dckb_previous_out_point, 0))
        .input(CellInput::new(lock_proxy_out_point, 0))
        .output(withdraw_cell)
        .output_data(Bytes::new().pack())
        .output(dckb_change_cell)
        .output_data(dckb_change_data.pack())
        .header_dep(withdraw_header.hash())
        .header_dep(deposit_header.hash())
        .witness(witness.as_bytes().pack())
        .witness(dckb_witness.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx_by_input_group(tx, &privkey, 1, 2);
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
