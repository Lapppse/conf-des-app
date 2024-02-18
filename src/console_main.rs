use bitvec::prelude::*;
use des_ndtp::{Block, FromHexStr, MainKey, ToHexString};
use miette::{IntoDiagnostic, Result};
use std::io;

fn main() -> Result<()> {
    let main_key = MainKey::from_hex_str("AAAABBBBCCCCDDDD").into_diagnostic()?;
    let iv = Block::from_hex_str("FFFFFFFFFFFFFFFF").into_diagnostic()?;
    let iv = iv.encode(&main_key).into_diagnostic()?;

    println!("Input data in hex format (as one hex string): ");
    let input = get_input_string().into_diagnostic()?;
    let input = BitVec::from_hex_str(input.as_str()).into_diagnostic()?;

    let output = encode(input, iv).to_upper_hex();
    println!("\n{}", output);

    Ok(())
}

fn encode(input: BitVec, encoded_iv: Block) -> BitVec {
    let iv = encoded_iv.into_bitvec();
    let mut output: BitVec<usize, bitvec::order::LocalBits> = BitVec::with_capacity(input.len());
    let input = input.chunks(64);
    for chunk in input {
        let mut new_chunk = chunk.to_bitvec();
        new_chunk ^= iv.clone();
        output.extend(new_chunk);
    }
    output
}

fn get_input_string() -> io::Result<String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input
        .trim()
        .to_lowercase()
        .trim_start_matches("0x")
        .to_owned())
}
