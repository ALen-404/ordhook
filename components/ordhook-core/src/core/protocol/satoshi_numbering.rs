use chainhook_sdk::types::{BlockIdentifier, OrdinalInscriptionNumber, TransactionIdentifier};
use chainhook_sdk::utils::Context;
use dashmap::DashMap;
use fxhash::FxHasher;
use std::hash::BuildHasherDefault;
use std::path::PathBuf;
use std::sync::Arc;

use crate::db::{
    find_pinned_block_bytes_at_block_height, open_ordhook_db_conn_rocks_db_loop, BlockBytesCursor,
    TransferData,
};

use crate::db::{TransactionBytesCursor, TraversalResult};
use crate::ord::height::Height;

pub fn compute_satoshi_number(
    blocks_db_dir: &PathBuf,
    block_identifier: &BlockIdentifier,
    transaction_identifier: &TransactionIdentifier,
    inscription_input_index: usize,
    traversals_cache: &Arc<
        DashMap<(u32, [u8; 8]), TransactionBytesCursor, BuildHasherDefault<FxHasher>>,
    >,
    _back_tracking: bool,
    ctx: &Context,
) -> Result<(TraversalResult, Vec<(u32, [u8; 8])>), String> {
    let mut inscription_offset_intra_output = 0;
    let mut inscription_output_index: usize = 0;
    let mut ordinal_offset = 0;
    let mut ordinal_block_number = block_identifier.index as u32;
    let txid = transaction_identifier.get_8_hash_bytes();
    // back_track 追踪区块高度和交易id
    let mut back_track = vec![];
    let blocks_db = open_ordhook_db_conn_rocks_db_loop(false, &blocks_db_dir, &ctx);

    // cache key: (block_height, txid)
    // sats_ranges: output sats range
    // inscription_offset_cross_outputs: current inscription sat offset
    let (sats_ranges, inscription_offset_cross_outputs) = match traversals_cache
        .get(&(block_identifier.index as u32, txid.clone()))
    {
        Some(entry) => {
            let tx = entry.value();
            (
                tx.get_sat_ranges(),
                tx.get_cumulated_sats_in_until_input_index(inscription_input_index),
            )
        }
        None => loop {
            match find_pinned_block_bytes_at_block_height(ordinal_block_number, 3, &blocks_db, &ctx)
            {
                None => {
                    return Err(format!("block #{ordinal_block_number} not in database"));
                }
                Some(block_bytes) => {
                    let cursor = BlockBytesCursor::new(&block_bytes.as_ref());
                    // 返回rocksdb中保存的序列化的块数据
                    match cursor.find_and_serialize_transaction_with_txid(&txid) {
                        Some(tx) => {
                            let sats_ranges = tx.get_sat_ranges();
                            let inscription_offset_cross_outputs =
                                tx.get_cumulated_sats_in_until_input_index(inscription_input_index);
                            // 将(block_height, txid)作为key加入cache_l2中
                            traversals_cache.insert((ordinal_block_number, txid.clone()), tx);
                            back_track.push((ordinal_block_number, txid.clone()));
                            break (sats_ranges, inscription_offset_cross_outputs);
                        }
                        None => return Err(format!("txid not in block #{ordinal_block_number}")),
                    }
                }
            }
        },
    };

    for (i, (min, max)) in sats_ranges.into_iter().enumerate() {
        if inscription_offset_cross_outputs >= min && inscription_offset_cross_outputs < max {
            inscription_output_index = i;
            inscription_offset_intra_output = inscription_offset_cross_outputs - min;
        }
    }
    ctx.try_log(|logger| {
        debug!(
            logger,
            "Start ordinal number retrieval for Satpoint {}:{}:0 (block #{})",
            transaction_identifier.hash,
            inscription_input_index,
            block_identifier.index
        )
    });

    let mut tx_cursor: ([u8; 8], usize) = (txid, inscription_input_index);
    let mut hops: u32 = 0;

    loop {
        hops += 1;
        if hops as u64 > block_identifier.index {
            return Err(format!(
                "Unable to process transaction {} detected after {hops} iterations. Manual investigation required",
                transaction_identifier.hash
            ));
        }

        if let Some(cached_tx) = traversals_cache.get(&(ordinal_block_number, tx_cursor.0)) {
            let tx = cached_tx.value();

            let mut next_found_in_cache = false;
            let mut sats_out = 0;
            for (index, output_value) in tx.outputs.iter().enumerate() {
                if index == tx_cursor.1 {
                    break;
                }
                sats_out += output_value;
            }
            sats_out += ordinal_offset;

            let mut sats_in = 0;
            for input in tx.inputs.iter() {
                sats_in += input.txin_value;

                if sats_out < sats_in {
                    ordinal_offset = sats_out - (sats_in - input.txin_value);
                    ordinal_block_number = input.block_height;
                    tx_cursor = (input.txin.clone(), input.vout as usize);
                    next_found_in_cache = true;
                    break;
                }
            }

            if next_found_in_cache {
                continue;
            }

            if sats_in == 0 {
                ctx.try_log(|logger| {
                    error!(
                        logger,
                        "Transaction {} is originating from a non spending transaction",
                        transaction_identifier.hash
                    )
                });
                return Ok((
                    TraversalResult {
                        inscription_number: OrdinalInscriptionNumber::zero(),
                        ordinal_number: 0,
                        transfers: 0,
                        inscription_input_index,
                        transaction_identifier_inscription: transaction_identifier.clone(),
                        transfer_data: TransferData {
                            inscription_offset_intra_output,
                            transaction_identifier_location: transaction_identifier.clone(),
                            output_index: inscription_output_index,
                            tx_index: 0,
                        },
                    },
                    back_track,
                ));
            }
        }

        let pinned_block_bytes = {
            loop {
                match find_pinned_block_bytes_at_block_height(
                    ordinal_block_number,
                    3,
                    &blocks_db,
                    &ctx,
                ) {
                    Some(block) => break block,
                    None => {
                        return Err(format!("block #{ordinal_block_number} not in database (traversing {} / {} in progress)", transaction_identifier.hash, block_identifier.index));
                    }
                }
            }
        };
        let block_cursor = BlockBytesCursor::new(pinned_block_bytes.as_ref());
        let txid = tx_cursor.0;
        let mut block_cursor_tx_iter = block_cursor.iter_tx();
        let coinbase = block_cursor_tx_iter.next().expect("empty block");

        // evaluate exit condition: did we reach the **final** coinbase transaction
        if coinbase.txid.eq(&txid) {
            let mut intra_coinbase_output_offset = 0;
            for (index, output_value) in coinbase.outputs.iter().enumerate() {
                if index == tx_cursor.1 {
                    break;
                }
                intra_coinbase_output_offset += output_value;
            }
            ordinal_offset += intra_coinbase_output_offset;

            let subsidy = Height(ordinal_block_number.into()).subsidy();
            if ordinal_offset < subsidy {
                // Great!
                break;
            }

            // loop over the transaction fees to detect the right range
            let mut accumulated_fees = subsidy;

            for tx in block_cursor_tx_iter {
                let mut total_in = 0;
                for input in tx.inputs.iter() {
                    total_in += input.txin_value;
                }

                let mut total_out = 0;
                for output_value in tx.outputs.iter() {
                    total_out += output_value;
                }

                let fee = total_in - total_out;
                if accumulated_fees + fee > ordinal_offset {
                    // We are looking at the right transaction
                    // Retraverse the inputs to select the index to be picked
                    let offset_within_fee = ordinal_offset - accumulated_fees;
                    total_out += offset_within_fee;
                    let mut sats_in = 0;

                    for input in tx.inputs.into_iter() {
                        sats_in += input.txin_value;

                        if sats_in > total_out {
                            ordinal_offset = total_out - (sats_in - input.txin_value);
                            ordinal_block_number = input.block_height;
                            tx_cursor = (input.txin.clone(), input.vout as usize);
                            break;
                        }
                    }
                    break;
                } else {
                    accumulated_fees += fee;
                }
            }
        } else {
            // isolate the target transaction
            let lazy_tx = match block_cursor.find_and_serialize_transaction_with_txid(&txid) {
                Some(entry) => entry,
                None => {
                    ctx.try_log(|logger| {
                        error!(
                            logger,
                            "fatal: unable to retrieve tx ancestor {} in block {ordinal_block_number} (satpoint {}:{inscription_input_index})",
                            hex::encode(txid),
                            transaction_identifier.get_hash_bytes_str(),
                        )
                    });
                    std::process::exit(1);
                }
            };

            let mut sats_out = 0;
            for (index, output_value) in lazy_tx.outputs.iter().enumerate() {
                if index == tx_cursor.1 {
                    break;
                }
                sats_out += output_value;
            }
            sats_out += ordinal_offset;

            let mut sats_in = 0;
            for input in lazy_tx.inputs.iter() {
                sats_in += input.txin_value;

                if sats_out < sats_in {
                    back_track.push((ordinal_block_number, tx_cursor.0.clone()));
                    traversals_cache.insert((ordinal_block_number, tx_cursor.0), lazy_tx.clone());
                    ordinal_offset = sats_out - (sats_in - input.txin_value);
                    ordinal_block_number = input.block_height;
                    tx_cursor = (input.txin.clone(), input.vout as usize);
                    break;
                }
            }

            if sats_in == 0 {
                ctx.try_log(|logger| {
                    error!(
                        logger,
                        "Transaction {} is originating from a non spending transaction",
                        transaction_identifier.hash
                    )
                });
                return Ok((
                    TraversalResult {
                        inscription_number: OrdinalInscriptionNumber::zero(),
                        ordinal_number: 0,
                        transfers: 0,
                        inscription_input_index,
                        transaction_identifier_inscription: transaction_identifier.clone(),
                        transfer_data: TransferData {
                            inscription_offset_intra_output,
                            transaction_identifier_location: transaction_identifier.clone(),
                            output_index: inscription_output_index,
                            tx_index: 0,
                        },
                    },
                    back_track,
                ));
            }
        }
    }

    let height = Height(ordinal_block_number.into());
    let ordinal_number = height.starting_sat().0 + ordinal_offset + inscription_offset_intra_output;

    Ok((
        TraversalResult {
            inscription_number: OrdinalInscriptionNumber::zero(),
            ordinal_number,
            transfers: hops,
            inscription_input_index,
            transaction_identifier_inscription: transaction_identifier.clone(),
            transfer_data: TransferData {
                inscription_offset_intra_output,
                transaction_identifier_location: transaction_identifier.clone(),
                output_index: inscription_output_index,
                tx_index: 0,
            },
        },
        back_track,
    ))
}
