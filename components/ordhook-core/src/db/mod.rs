use std::{
    io::{Read, Write},
    path::PathBuf,
};

use std::io::Cursor;

use chainhook_sdk::{
    indexer::bitcoin::BitcoinBlockFullBreakdown,
    types::{
        BitcoinBlockData, OrdinalInscriptionNumber, TransactionIdentifier,
    },
    utils::Context,
};

use crate::ord::sat::Sat;

mod rocks;
mod sqlite;

pub use rocks::*;
pub use sqlite::*;

pub fn open_readwrite_ordhook_dbs(
    base_dir: &PathBuf,
    ctx: &Context,
) -> Result<(DB, Connection), String> { 
    let blocks_db = open_ordhook_db_conn_rocks_db_loop(true, &base_dir, &ctx);
    let inscriptions_db = open_readwrite_ordhook_db_conn(&base_dir, &ctx)?;
    Ok((blocks_db, inscriptions_db))
}

pub fn delete_data_in_ordhook_db(
    start_block: u64,
    end_block: u64,
    blocks_db_rw: &DB,
    inscriptions_db_conn_rw: &Connection,
    ctx: &Context,
) -> Result<(), String> {
    ctx.try_log(|logger| {
        info!(
            logger,
            "Deleting entries from block #{start_block} to block #{end_block}"
        )
    });
    delete_blocks_in_block_range(start_block as u32, end_block as u32, blocks_db_rw, &ctx);
    ctx.try_log(|logger| {
        info!(
            logger,
            "Deleting inscriptions and locations from block #{start_block} to block #{end_block}"
        )
    });
    delete_inscriptions_in_block_range(
        start_block as u32,
        end_block as u32,
        inscriptions_db_conn_rw,
        &ctx,
    );
    Ok(())
}

#[derive(Debug, Clone)]
pub struct TransferData {
    pub inscription_offset_intra_output: u64,
    pub transaction_identifier_location: TransactionIdentifier,
    pub output_index: usize,
    pub tx_index: u64,
}

#[derive(Clone, Debug)]
pub struct TraversalResult {
    pub inscription_number: OrdinalInscriptionNumber,
    pub inscription_input_index: usize,
    pub transaction_identifier_inscription: TransactionIdentifier,
    pub ordinal_number: u64,
    pub transfers: u32,
    pub transfer_data: TransferData,
}

impl TraversalResult {
    pub fn get_ordinal_coinbase_height(&self) -> u64 {
        let sat = Sat(self.ordinal_number);
        sat.height().n()
    }

    pub fn get_ordinal_coinbase_offset(&self) -> u64 {
        let sat = Sat(self.ordinal_number);
        self.ordinal_number - sat.height().starting_sat().n()
    }

    pub fn get_inscription_id(&self) -> String {
        format!(
            "{}i{}",
            self.transaction_identifier_inscription.get_hash_bytes_str(),
            self.inscription_input_index
        )
    }
}

pub fn format_satpoint_to_watch(
    transaction_identifier: &TransactionIdentifier,
    output_index: usize,
    offset: u64,
) -> String {
    format!(
        "{}:{}:{}",
        transaction_identifier.get_hash_bytes_str(),
        output_index,
        offset
    )
}

pub fn format_inscription_id(
    transaction_identifier: &TransactionIdentifier,
    inscription_subindex: usize,
) -> String {
    format!(
        "{}i{}",
        transaction_identifier.get_hash_bytes_str(),
        inscription_subindex,
    )
}

pub fn parse_satpoint_to_watch(outpoint_to_watch: &str) -> (TransactionIdentifier, usize, u64) {
    let comps: Vec<&str> = outpoint_to_watch.split(":").collect();
    let tx = TransactionIdentifier::new(comps[0]);
    let output_index = comps[1].to_string().parse::<usize>().expect(&format!(
        "fatal: unable to extract output_index from outpoint {}",
        outpoint_to_watch
    ));
    let offset = comps[2].to_string().parse::<u64>().expect(&format!(
        "fatal: unable to extract offset from outpoint {}",
        outpoint_to_watch
    ));
    (tx, output_index, offset)
}

pub fn format_outpoint_to_watch(
    transaction_identifier: &TransactionIdentifier,
    output_index: usize,
) -> String {
    format!(
        "{}:{}",
        transaction_identifier.get_hash_bytes_str(),
        output_index
    )
}

pub fn parse_inscription_id(inscription_id: &str) -> (TransactionIdentifier, usize) {
    let comps: Vec<&str> = inscription_id.split("i").collect();
    let tx = TransactionIdentifier::new(&comps[0]);
    let output_index = comps[1].to_string().parse::<usize>().expect(&format!(
        "fatal: unable to extract output_index from inscription_id {}",
        inscription_id
    ));
    (tx, output_index)
}

pub fn parse_outpoint_to_watch(outpoint_to_watch: &str) -> (TransactionIdentifier, usize) {
    let comps: Vec<&str> = outpoint_to_watch.split(":").collect();
    let tx = TransactionIdentifier::new(&comps[0]);
    let output_index = comps[1].to_string().parse::<usize>().expect(&format!(
        "fatal: unable to extract output_index from outpoint {}",
        outpoint_to_watch
    ));
    (tx, output_index)
}

#[derive(Debug)]
pub struct BlockBytesCursor<'a> {
    pub bytes: &'a [u8],
    pub tx_len: u16,
}

#[derive(Debug, Clone)]
pub struct TransactionBytesCursor {
    pub txid: [u8; 8],
    pub inputs: Vec<TransactionInputBytesCursor>,
    pub outputs: Vec<u64>,
}

impl TransactionBytesCursor {
    pub fn get_average_bytes_size() -> usize {
        TXID_LEN + 3 * TransactionInputBytesCursor::get_average_bytes_size() + 3 * SATS_LEN
    }

    pub fn get_sat_ranges(&self) -> Vec<(u64, u64)> {
        // output.ordinals
        let mut sats_ranges = vec![];
        let mut bound = 0u64;
        for output_value in self.outputs.iter() {
            sats_ranges.push((bound, bound + output_value));
            bound += output_value;
        }
        sats_ranges
    }

    pub fn get_cumulated_sats_in_until_input_index(&self, input_index: usize) -> u64 {
        let mut cumulated_sats_in: u64 = 0;
        for (i, input) in self.inputs.iter().enumerate() {
            if i == input_index {
                break;
            }
            cumulated_sats_in += input.txin_value;
        }
        cumulated_sats_in
    }
}

#[derive(Debug, Clone)]
pub struct TransactionInputBytesCursor {
    pub txin: [u8; 8],
    pub block_height: u32,
    pub vout: u16,
    pub txin_value: u64,
}

impl TransactionInputBytesCursor {
    pub fn get_average_bytes_size() -> usize {
        TXID_LEN + SATS_LEN + 4 + 2
    }
}

const TXID_LEN: usize = 8;
const SATS_LEN: usize = 8;
const INPUT_SIZE: usize = TXID_LEN + 4 + 2 + SATS_LEN;
const OUTPUT_SIZE: usize = 8;

impl<'a> BlockBytesCursor<'a> {
    pub fn new(bytes: &[u8]) -> BlockBytesCursor {
        let tx_len = u16::from_be_bytes([bytes[0], bytes[1]]);
        BlockBytesCursor { bytes, tx_len }
    }

    pub fn get_coinbase_data_pos(&self) -> usize {
        // 跳过了交易长度和交易输入输出数量
        (2 + self.tx_len * 2 * 2) as usize
    }

    pub fn get_coinbase_outputs_len(&self) -> usize {
        u16::from_be_bytes([self.bytes[4], self.bytes[5]]) as usize
    }

    pub fn get_u64_at_pos(&self, pos: usize) -> u64 {
        u64::from_be_bytes([
            self.bytes[pos],
            self.bytes[pos + 1],
            self.bytes[pos + 2],
            self.bytes[pos + 3],
            self.bytes[pos + 4],
            self.bytes[pos + 5],
            self.bytes[pos + 6],
            self.bytes[pos + 7],
        ])
    }

    pub fn get_coinbase_txid(&self) -> &[u8] {
        let pos = self.get_coinbase_data_pos();
        &self.bytes[pos..pos + TXID_LEN]
    }

    pub fn get_transactions_data_pos(&self) -> usize {
        self.get_coinbase_data_pos()
    }

    pub fn get_transaction_format(&self, index: u16) -> (u16, u16, usize) {
        // 第i个交易的偏移量
        let inputs_len_pos = (2 + index * 2 * 2) as usize;
        let inputs =
            u16::from_be_bytes([self.bytes[inputs_len_pos], self.bytes[inputs_len_pos + 1]]);
        let outputs = u16::from_be_bytes([
            self.bytes[inputs_len_pos + 2],
            self.bytes[inputs_len_pos + 3],
        ]);
        let size = TXID_LEN + (inputs as usize * INPUT_SIZE) + (outputs as usize * OUTPUT_SIZE);
        (inputs, outputs, size)
    }

    pub fn get_transaction_bytes_cursor_at_pos(
        &self,
        cursor: &mut Cursor<&[u8]>,
        txid: [u8; 8],
        inputs_len: u16,
        outputs_len: u16,
    ) -> TransactionBytesCursor {
        let mut inputs = Vec::with_capacity(inputs_len as usize);
        for _ in 0..inputs_len {
            let mut txin = [0u8; 8];
            cursor.read_exact(&mut txin).expect("data corrupted");
            let mut block_height = [0u8; 4];
            cursor
                .read_exact(&mut block_height)
                .expect("data corrupted");
            let mut vout = [0u8; 2];
            cursor.read_exact(&mut vout).expect("data corrupted");
            let mut txin_value = [0u8; 8];
            cursor.read_exact(&mut txin_value).expect("data corrupted");
            inputs.push(TransactionInputBytesCursor {
                txin: txin,
                block_height: u32::from_be_bytes(block_height),
                vout: u16::from_be_bytes(vout),
                txin_value: u64::from_be_bytes(txin_value),
            });
        }
        let mut outputs = Vec::with_capacity(outputs_len as usize);
        for _ in 0..outputs_len {
            let mut value = [0u8; 8];
            cursor.read_exact(&mut value).expect("data corrupted");
            outputs.push(u64::from_be_bytes(value))
        }
        TransactionBytesCursor {
            txid,
            inputs,
            outputs,
        }
    }

    pub fn find_and_serialize_transaction_with_txid(
        &self,
        searched_txid: &[u8],
    ) -> Option<TransactionBytesCursor> {
        // println!("{:?}", hex::encode(searched_txid));
        let mut entry = None;
        let mut cursor = Cursor::new(self.bytes);
        let mut cumulated_offset = 0;
        let mut i = 0;
        while entry.is_none() {
            let pos = self.get_transactions_data_pos() + cumulated_offset;
            let (inputs_len, outputs_len, size) = self.get_transaction_format(i);
            // println!("{inputs_len} / {outputs_len} / {size}");
            cursor.set_position(pos as u64);
            let mut txid = [0u8; 8]; // todo 20 bytes
            let _ = cursor.read_exact(&mut txid);
            // println!("-> {}", hex::encode(txid));
            if searched_txid.eq(&txid) {
                entry = Some(self.get_transaction_bytes_cursor_at_pos(
                    &mut cursor,
                    txid,
                    inputs_len,
                    outputs_len,
                ));
            } else {
                cumulated_offset += size;
                i += 1;
                if i >= self.tx_len {
                    break;
                }
            }
        }
        entry
    }

    pub fn iter_tx(&self) -> TransactionBytesCursorIterator {
        TransactionBytesCursorIterator::new(&self)
    }

    // Q: 返回的已压缩区块二进制格式是如何定义的?
    // A: 1. 区块中交易的数量(不包括coinbase交易) - 2个字节
    //    2. 每个交易的输入数量 - 2个字节
    //    3. 每个交易的输出数量 - 2个字节
    //    4. 每个交易的输入部分：
    //       1. 交易id - 8个字节
    //       2. prevout的交易id - 8个字节
    //       3. prevout所在区块的高度 - 4个字节
    //       4. 交易的vout索引 - 2个字节
    //       5. prevout的sats值 - 8个字节
    //    5. 每个交易的输出部分：
    //       1. 输出的sats值 - 8个字节
    pub fn from_full_block<'b>(block: &BitcoinBlockFullBreakdown) -> std::io::Result<Vec<u8>> {
        let mut buffer = vec![];
        // Number of transactions in the block (not including coinbase)
        let tx_len = block.tx.len() as u16;
        buffer.write(&tx_len.to_be_bytes())?;
        // For each transaction:
        let u16_max = u16::MAX as usize;
        for (i, tx) in block.tx.iter().enumerate() {
            let mut inputs_len = if tx.vin.len() > u16_max {
                0
            } else {
                tx.vin.len() as u16
            };
            let outputs_len = if tx.vout.len() > u16_max {
                0
            } else {
                tx.vout.len() as u16
            };
            if i == 0 {
                inputs_len = 0;
            }
            // Number of inputs
            buffer.write(&inputs_len.to_be_bytes())?;
            // Number of outputs
            buffer.write(&outputs_len.to_be_bytes())?;
        }
        // For each transaction:
        for tx in block.tx.iter() {
            // txid - 8 first bytes
            let txid = {
                let txid = hex::decode(tx.txid.to_string()).unwrap();
                [
                    txid[0], txid[1], txid[2], txid[3], txid[4], txid[5], txid[6], txid[7],
                ]
            };
            buffer.write_all(&txid)?;

            let inputs_len = if tx.vin.len() > u16_max {
                0
            } else {
                tx.vin.len() as usize
            };
            let outputs_len = if tx.vout.len() > u16_max {
                0
            } else {
                tx.vout.len() as usize
            };

            // For each transaction input:
            for i in 0..inputs_len {
                let input = &tx.vin[i];
                // txin - 8 first bytes
                let Some(input_txid) = input.txid.as_ref() else {
                    continue;
                };
                let txin = {
                    let txid = hex::decode(input_txid).unwrap();
                    [
                        txid[0], txid[1], txid[2], txid[3], txid[4], txid[5], txid[6], txid[7],
                    ]
                };
                buffer.write_all(&txin)?;
                // txin's block height
                let block_height = input.prevout.as_ref().unwrap().height as u32;
                buffer.write(&block_height.to_be_bytes())?;
                // txin's vout index
                let vout = input.vout.unwrap() as u16;
                buffer.write(&vout.to_be_bytes())?;
                // txin's sats value
                let sats = input.prevout.as_ref().unwrap().value.to_sat();
                buffer.write(&sats.to_be_bytes())?;
            }
            // For each transaction output:
            for i in 0..outputs_len {
                let output = &tx.vout[i];
                let sats = output.value.to_sat();
                buffer.write(&sats.to_be_bytes())?;
            }
        }
        Ok(buffer)
    }

    pub fn from_standardized_block<'b>(block: &BitcoinBlockData) -> std::io::Result<Vec<u8>> {
        let mut buffer = vec![];
        // Number of transactions in the block (not including coinbase)
        let tx_len = block.transactions.len() as u16;
        buffer.write(&tx_len.to_be_bytes())?;
        // For each transaction:
        for (i, tx) in block.transactions.iter().enumerate() {
            let inputs_len = if i > 0 {
                tx.metadata.inputs.len() as u16
            } else {
                0
            };
            let outputs_len = tx.metadata.outputs.len() as u16;
            // Number of inputs
            buffer.write(&inputs_len.to_be_bytes())?;
            // Number of outputs
            buffer.write(&outputs_len.to_be_bytes())?;
        }
        // For each transaction:
        for (i, tx) in block.transactions.iter().enumerate() {
            // txid - 8 first bytes
            let txid = tx.transaction_identifier.get_8_hash_bytes();
            buffer.write_all(&txid)?;
            // For each non coinbase transaction input:
            if i > 0 {
                for input in tx.metadata.inputs.iter() {
                    // txin - 8 first bytes
                    let txin = input.previous_output.txid.get_8_hash_bytes();
                    buffer.write_all(&txin)?;
                    // txin's block height
                    let block_height = input.previous_output.block_height as u32;
                    buffer.write(&block_height.to_be_bytes())?;
                    // txin's vout index
                    let vout = input.previous_output.vout as u16;
                    buffer.write(&vout.to_be_bytes())?;
                    // txin's sats value
                    let sats = input.previous_output.value;
                    buffer.write(&sats.to_be_bytes())?;
                }
            }
            // For each transaction output:
            for output in tx.metadata.outputs.iter() {
                let sats = output.value;
                buffer.write(&sats.to_be_bytes())?;
            }
        }
        Ok(buffer)
    }
}

pub struct TransactionBytesCursorIterator<'a> {
    block_bytes_cursor: &'a BlockBytesCursor<'a>,
    tx_index: u16,
    cumulated_offset: usize,
}

impl<'a> TransactionBytesCursorIterator<'a> {
    pub fn new(block_bytes_cursor: &'a BlockBytesCursor) -> TransactionBytesCursorIterator<'a> {
        TransactionBytesCursorIterator {
            block_bytes_cursor,
            tx_index: 0,
            cumulated_offset: 0,
        }
    }
}

impl<'a> Iterator for TransactionBytesCursorIterator<'a> {
    type Item = TransactionBytesCursor;

    fn next(&mut self) -> Option<TransactionBytesCursor> {
        if self.tx_index >= self.block_bytes_cursor.tx_len {
            return None;
        }
        let pos = self.block_bytes_cursor.get_transactions_data_pos() + self.cumulated_offset;
        let (inputs_len, outputs_len, size) = self
            .block_bytes_cursor
            .get_transaction_format(self.tx_index);
        // println!("{inputs_len} / {outputs_len} / {size}");
        let mut cursor = Cursor::new(self.block_bytes_cursor.bytes);
        cursor.set_position(pos as u64);
        let mut txid = [0u8; 8];
        let _ = cursor.read_exact(&mut txid);
        self.cumulated_offset += size;
        self.tx_index += 1;
        Some(self.block_bytes_cursor.get_transaction_bytes_cursor_at_pos(
            &mut cursor,
            txid,
            inputs_len,
            outputs_len,
        ))
    }
}

#[derive(Clone, Debug)]
pub struct WatchedSatpoint {
    pub inscription_id: String,
    pub offset: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chainhook_sdk::{
        indexer::bitcoin::{parse_downloaded_block, standardize_bitcoin_block},
        types::BitcoinNetwork,
    };

    #[test]
    fn test_block_cursor_roundtrip() {
        let ctx = Context::empty();
        let block = include_str!("./fixtures/blocks_json/279671.json");
        let decoded_block =
            parse_downloaded_block(block.as_bytes().to_vec()).expect("unable to decode block");
        let standardized_block =
            standardize_bitcoin_block(decoded_block.clone(), &BitcoinNetwork::Mainnet, &ctx)
                .expect("unable to standardize block");

        for (index, (tx_in, tx_out)) in decoded_block
            .tx
            .iter()
            .zip(standardized_block.transactions.iter())
            .enumerate()
        {
            // Test outputs
            assert_eq!(tx_in.vout.len(), tx_out.metadata.outputs.len());
            for (output, src) in tx_out.metadata.outputs.iter().zip(tx_in.vout.iter()) {
                assert_eq!(output.value, src.value.to_sat());
            }
            // Test inputs (non-coinbase transactions only)
            if index == 0 {
                continue;
            }
            assert_eq!(tx_in.vin.len(), tx_out.metadata.inputs.len());
            for (input, src) in tx_out.metadata.inputs.iter().zip(tx_in.vin.iter()) {
                assert_eq!(
                    input.previous_output.block_height,
                    src.prevout.as_ref().unwrap().height
                );
                assert_eq!(
                    input.previous_output.value,
                    src.prevout.as_ref().unwrap().value.to_sat()
                );
                let txin = hex::decode(src.txid.as_ref().unwrap()).unwrap();
                assert_eq!(input.previous_output.txid.get_hash_bytes(), txin);
                assert_eq!(input.previous_output.vout, src.vout.unwrap());
            }
        }

        let bytes = BlockBytesCursor::from_full_block(&decoded_block).expect("unable to serialize");
        let bytes_via_standardized = BlockBytesCursor::from_standardized_block(&standardized_block)
            .expect("unable to serialize");
        assert_eq!(bytes, bytes_via_standardized);

        let block_bytes_cursor = BlockBytesCursor::new(&bytes);
        assert_eq!(decoded_block.tx.len(), block_bytes_cursor.tx_len as usize);

        // Test helpers
        let coinbase_txid = block_bytes_cursor.get_coinbase_txid();
        assert_eq!(
            coinbase_txid,
            standardized_block.transactions[0]
                .transaction_identifier
                .get_8_hash_bytes()
        );

        // Test transactions
        for (index, (tx_in, tx_out)) in decoded_block
            .tx
            .iter()
            .zip(block_bytes_cursor.iter_tx())
            .enumerate()
        {
            // Test outputs
            assert_eq!(tx_in.vout.len(), tx_out.outputs.len());
            for (sats, src) in tx_out.outputs.iter().zip(tx_in.vout.iter()) {
                assert_eq!(*sats, src.value.to_sat());
            }
            // Test inputs (non-coinbase transactions only)
            if index == 0 {
                continue;
            }
            assert_eq!(tx_in.vin.len(), tx_out.inputs.len());
            for (tx_bytes_cursor, src) in tx_out.inputs.iter().zip(tx_in.vin.iter()) {
                assert_eq!(
                    tx_bytes_cursor.block_height as u64,
                    src.prevout.as_ref().unwrap().height
                );
                assert_eq!(
                    tx_bytes_cursor.txin_value,
                    src.prevout.as_ref().unwrap().value.to_sat()
                );
                let txin = hex::decode(src.txid.as_ref().unwrap()).unwrap();
                assert_eq!(tx_bytes_cursor.txin, txin[0..tx_bytes_cursor.txin.len()]);
                assert_eq!(tx_bytes_cursor.vout as u32, src.vout.unwrap());
            }
        }
    }
}
