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
fn test_dckb_withdraw() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let (deposit_header, deposit_epoch) = gen_header(1554, 10000000, 35, 1000, 1000);
    let (withdraw_header, withdraw_epoch) = gen_header(2000610, 10001000, 575, 2000000, 1100);
    let (cell, previous_out_point) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000),
        gen_secp256k1_lock_script(lock_args.clone()),
    );
    let (dckb_cell, dckb_previous_out_point, dckb_cell_data) = gen_dckb_cell(
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

    let resolved_inputs = vec![input_cell_meta, input_dckb_cell_meta];
    let mut resolved_cell_deps = vec![];
    let align_target_index: u8 = 0;

    let mut b = [0; 8];
    LittleEndian::write_u64(&mut b, 1);
    let witness = WitnessArgs::new_builder()
        .type_(Bytes::from(&b[..]).pack())
        .build();
    let dckb_witness = WitnessArgs::new_builder()
        .type_(Bytes::from(vec![0, align_target_index]).pack())
        .build();
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0x2003e8022a0002f3))
        .input(CellInput::new(dckb_previous_out_point, 0))
        .output(cell_output_with_only_capacity(123468105678))
        .output_data(Bytes::new().pack())
        .header_dep(withdraw_header.hash())
        .header_dep(deposit_header.hash())
        .witness(witness.as_bytes().pack())
        .witness(dckb_witness.as_bytes().pack());
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
fn test_dckb_transfer() {
    let mut data_loader = DummyDataLoader::new();
    let (privkey, lock_args) = gen_lock();

    let ar1 = 10000000;
    let ar2 = 10001000;
    let sender_coin = 100000_00000000;
    let receiver_coin = 50000_00000000;
    let sender_withdraw_coin: u64 = ((sender_coin - DAO_OCCUPIED_CAPACITY) as u128 * ar2 as u128
        / ar1 as u128
        + DAO_OCCUPIED_CAPACITY as u128) as u64;
    let transfer_coin: u64 = 10000_00000000;
    let (header1, header1_epoch) = gen_header(1554, ar1, 35, 1000, 1000);
    let (header2, header2_epoch) = gen_header(2000610, ar2, 575, 2000000, 1100);
    let (dckb_cell1, dckb_previous_out_point1, dckb_cell_data1) = gen_dckb_cell(
        &mut data_loader,
        Capacity::shannons(sender_coin),
        lock_args.clone(),
        0,
    );
    let (dckb_cell2, dckb_previous_out_point2, dckb_cell_data2) = gen_dckb_cell(
        &mut data_loader,
        Capacity::shannons(receiver_coin),
        lock_args,
        1554,
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
        CellMetaBuilder::from_cell_output(dckb_cell1, Bytes::from(&dckb_cell_data1[..]))
            .out_point(dckb_previous_out_point1.clone())
            .transaction_info(TransactionInfo {
                block_hash: header1.hash(),
                block_number: header1.number(),
                block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
                index: 0,
            })
            .build();
    let input_dckb_cell_meta =
        CellMetaBuilder::from_cell_output(dckb_cell2, Bytes::from(&dckb_cell_data2[..]))
            .out_point(dckb_previous_out_point2.clone())
            .transaction_info(TransactionInfo {
                block_hash: header2.hash(),
                block_number: header2.number(),
                block_epoch: EpochNumberWithFraction::new(575, 610, 1100),
                index: 0,
            })
            .build();

    let resolved_inputs = vec![input_cell_meta, input_dckb_cell_meta];
    let mut resolved_cell_deps = vec![];
    let align_target_index: u8 = 1;

    let dckb_witness = WitnessArgs::new_builder()
        .type_(Bytes::from(vec![0, align_target_index]).pack())
        .build();
    let dckb2_witness = WitnessArgs::new_builder()
        .type_(Bytes::from(vec![0]).pack())
        .build();
    // transfer 10000 from 1 to 2
    let builder = TransactionBuilder::default()
        .input(CellInput::new(dckb_previous_out_point1, 0))
        .input(CellInput::new(dckb_previous_out_point2, 0))
        .output(dckb_cell_output())
        .output_data(
            dckb_data(
                (sender_withdraw_coin - transfer_coin).into(),
                header2.number(),
            )
            .pack(),
        )
        .output(dckb_cell_output())
        .output_data(dckb_data((receiver_coin + transfer_coin).into(), header2.number()).pack())
        .header_dep(header1.hash())
        .header_dep(header2.hash())
        .witness(dckb_witness.as_bytes().pack())
        .witness(dckb2_witness.as_bytes().pack());
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
fn test_dckb_deposit() {
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

    let change_coin = 61;
    let (change_output_cell, _) = gen_normal_cell(
        &mut data_loader,
        Capacity::shannons(change_coin),
        lock_args.clone(),
    );

    let (output_cell, _) = gen_dao_cell(
        &mut data_loader,
        Capacity::shannons(123456780000 - DCKB_CAPACITY.as_u64() - change_coin),
        gen_deposit_lock_lock_script(change_output_cell.lock().calc_script_hash().unpack()),
    );
    let (dckb_output_cell, _, dckb_output_data) = gen_dckb_cell(
        &mut data_loader,
        Capacity::shannons(123456780000 - DCKB_CAPACITY.as_u64() - change_coin),
        lock_args,
        0,
    );

    let b = [0; 8];
    let builder = TransactionBuilder::default()
        .input(CellInput::new(previous_out_point, 0))
        .output(output_cell)
        .output_data(Bytes::from(b.to_vec()).pack())
        .output(dckb_output_cell)
        .output_data(dckb_output_data.pack())
        .output(change_output_cell)
        .output_data(Bytes::new().pack())
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
