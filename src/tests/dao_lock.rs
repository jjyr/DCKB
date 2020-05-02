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
fn test_dao_lock_phase1_unlock() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (deposit_header, deposit_epoch) = gen_header(1554, 10000000, 35, 1000, 1000);
    let (withdraw_header, withdraw_epoch) = gen_header(2000610, 10001000, 575, 2000000, 1100);

    // inputs cells
    let dao_lock_script = gen_dao_lock_lock_script(
        gen_secp256k1_lock_script(lock_args.clone())
            .calc_script_hash()
            .unpack(),
    );
    let original_dao_capacity = 123456780000u64;
    let (cell, previous_out_point) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(original_dao_capacity),
        dao_lock_script,
    );
    let input_dckb_amount = 123468105678u64;
    let (dckb_cell, dckb_previous_out_point, dckb_cell_data) =
        gen_dckb_cell(&mut data_loader, input_dckb_amount, 0, lock_args.clone());
    let (fee_input_cell, fee_input_out_point) = gen_normal_cell(
        &mut data_loader,
        Capacity::shannons(SECP_OCCUPIED_CAPACITY),
        lock_args.clone(),
    );
    // outputs cells
    let custodian_cell = CellOutput::new_builder()
        .capacity(Capacity::shannons(SECP_OCCUPIED_CAPACITY).pack())
        .lock(gen_custodian_lock_script(lock_args.clone()))
        .type_(Some(dckb_script()).pack())
        .build();
    let custodian_dckb_data =
        dckb_data((original_dao_capacity - DAO_OCCUPIED_CAPACITY).into(), 1554);
    let dckb_change_cell = CellOutput::new_builder()
        .capacity(DCKB_CAPACITY.pack())
        .lock(gen_secp256k1_lock_script(lock_args.clone()))
        .type_(Some(dckb_script()).pack())
        .build();
    let dckb_change_data = dckb_data(
        (input_dckb_amount - (original_dao_capacity - DAO_OCCUPIED_CAPACITY)).into(),
        1554,
    );
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

    let custodian_cell_index: u8 = 1;
    let witness = WitnessArgs::new_builder()
        .lock(Bytes::from(vec![custodian_cell_index]).pack())
        .type_(Bytes::from(&0u8.to_le_bytes()[..]).pack())
        .build();
    let dckb_witness = WitnessArgs::new_builder()
        .type_(Bytes::from(vec![0u8, 0u8]).pack())
        .build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0))
        .input(CellInput::new(dckb_previous_out_point, 0))
        .input(CellInput::new(fee_input_out_point, 0))
        .output(dao_withdraw_cell)
        .output_data(dao_withdraw_cell_data.pack())
        .output(custodian_cell)
        .output_data(custodian_dckb_data.pack())
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
fn test_dao_lock_phase2_unlock() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (deposit_header, deposit_epoch) = gen_header(1554, 10000000, 35, 1000, 1000);
    let (withdraw_header, withdraw_epoch) = gen_header(2000610, 10001000, 575, 2000000, 1100);
    // inputs
    let dao_lock_script = gen_dao_lock_lock_script(
        gen_secp256k1_lock_script(lock_args.clone())
            .calc_script_hash()
            .unpack(),
    );
    let original_dao_capacity = 123456780000u64;
    let expected_withdraw_caapcity = calculate_dao_capacity(
        DAO_OCCUPIED_CAPACITY,
        &deposit_header,
        &withdraw_header,
        original_dao_capacity,
    );
    let (cell, previous_out_point) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(original_dao_capacity),
        dao_lock_script,
    );
    let input_dckb_amount = 100000000u64;
    let (dckb_cell, dckb_previous_out_point, dckb_cell_data) =
        gen_dckb_cell(&mut data_loader, input_dckb_amount, 0, lock_args.clone());
    let (custodian_cell, custodian_cell_out_point, custodian_cell_data) = {
        // custodian cell is from same tx
        let out_point = OutPoint::new_builder()
            .tx_hash(previous_out_point.tx_hash())
            .index(1u32.pack())
            .build();
        let (custodian_cell, custodian_cell_data) = gen_custodian_cell(
            &mut data_loader,
            original_dao_capacity,
            withdraw_header.number(),
            lock_args.clone(),
            out_point.clone(),
        );
        (custodian_cell, out_point, custodian_cell_data)
    };

    // outputs
    let dckb_change_cell = CellOutput::new_builder()
        .capacity(DCKB_CAPACITY.pack())
        .lock(gen_secp256k1_lock_script(lock_args.clone()))
        .type_(Some(dckb_script()).pack())
        .build();
    let dckb_change_data = dckb_data(
        (input_dckb_amount + original_dao_capacity - expected_withdraw_caapcity).into(),
        withdraw_header.number(),
    );
    let withdraw_cell =
        cell_output_with_only_capacity(original_dao_capacity - DCKB_CAPACITY.as_u64())
            .as_builder()
            .lock(gen_secp256k1_lock_script(lock_args.clone()))
            .build();

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
                block_hash: withdraw_header.hash(),
                block_number: withdraw_header.number(),
                block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
                index: 0,
            })
            .build();
    let input_custodian_cell_meta =
        CellMetaBuilder::from_cell_output(custodian_cell, custodian_cell_data)
            .out_point(custodian_cell_out_point.clone())
            .transaction_info(TransactionInfo {
                block_hash: withdraw_header.hash(),
                block_number: withdraw_header.number(),
                block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
                index: 0,
            })
            .build();

    let resolved_inputs = vec![
        input_cell_meta,
        input_dckb_cell_meta,
        input_custodian_cell_meta,
    ];
    let mut resolved_cell_deps = vec![];

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1);
    let custodian_cell_index: u8 = 2;
    let witness = WitnessArgs::new_builder()
        .lock(Bytes::from(vec![custodian_cell_index]).pack())
        .type_(Bytes::from(&1u64.to_le_bytes()[..]).pack())
        .build();
    let align_target_index: u8 = 0;
    let dckb_witness = WitnessArgs::new_builder()
        .type_(Bytes::from(vec![0, align_target_index]).pack())
        .build();
    let unlock_input_cell_index: u8 = 1;
    let custodian_cell_witness = WitnessArgs::new_builder()
        .lock(Bytes::from(vec![unlock_input_cell_index]).pack())
        .type_(Bytes::from(vec![0]).pack())
        .build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0x2003e8022a0002f3))
        .input(CellInput::new(dckb_previous_out_point, 0))
        .input(CellInput::new(custodian_cell_out_point, 0))
        .output(withdraw_cell)
        .output_data(Bytes::new().pack())
        .output(dckb_change_cell)
        .output_data(dckb_change_data.pack())
        .header_dep(withdraw_header.hash())
        .header_dep(deposit_header.hash())
        .witness(witness.as_bytes().pack())
        .witness(dckb_witness.as_bytes().pack())
        .witness(custodian_cell_witness.as_bytes().pack());
    let (tx, mut resolved_cell_deps2) = complete_tx(&mut data_loader, builder);
    let tx = sign_tx_by_input_group(tx, &privkey, 1, 1);
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
