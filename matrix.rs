use indicatif::ProgressBar;
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use clap::{Arg, Command, ValueEnum};
use strum_macros::EnumString;
use rand::thread_rng;
use rand::prelude::SliceRandom;

const HEX_ARRAY: [&str; 256] = [
    "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0A", "0B", "0C", "0D", "0E", "0F",
    "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1A", "1B", "1C", "1D", "1E", "1F",
    "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2A", "2B", "2C", "2D", "2E", "2F",
    "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3A", "3B", "3C", "3D", "3E", "3F",
    "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4A", "4B", "4C", "4D", "4E", "4F",
    "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5A", "5B", "5C", "5D", "5E", "5F",
    "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6A", "6B", "6C", "6D", "6E", "6F",
    "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7A", "7B", "7C", "7D", "7E", "7F",
    "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8A", "8B", "8C", "8D", "8E", "8F",
    "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9A", "9B", "9C", "9D", "9E", "9F",
    "A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "AA", "AB", "AC", "AD", "AE", "AF",
    "B0", "B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8", "B9", "BA", "BB", "BC", "BD", "BE", "BF",
    "C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "CA", "CB", "CC", "CD", "CE", "CF",
    "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF",
    "E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8", "E9", "EA", "EB", "EC", "ED", "EE", "EF",
    "F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "FA", "FB", "FC", "FD", "FE", "FF",
];

fn random_indexes() -> (HashMap<String, i16>, Vec<u8>){
    let mut random_indexes = HashMap::new();
    let mut indexes = Vec::new();
    let mut rng = thread_rng();
    let mut all_i16: Vec<i16> = (256..=32767).collect();
    all_i16.shuffle(&mut rng);
    let mut count = 0;
    for key in HEX_ARRAY{
        indexes.push(all_i16[count]);
        random_indexes.insert(key.to_string(), all_i16[count]);
        count += 1;

    }
    let bytes: Vec<u8> = indexes.iter().flat_map(|x| x.to_le_bytes()).collect();
    (random_indexes, bytes)
}

fn byte_to_hex(byte: &u8) -> String {
    format!("{:02X}", byte).to_uppercase()
}

fn hex_to_byte(hex: &str) -> Option<u8> {
    u8::from_str_radix(hex, 16).ok()
}

fn seek_avail(filename: &str, first_index: HashMap<String, i16>) -> Vec<u8> {
    let mut indexes = Vec::new();
    let mut file_data = Vec::new();

    let mut file = File::open(filename).unwrap();
    let _ = file.read_to_end(&mut file_data);

    let length_data = file_data.len();
    let bar = ProgressBar::new(length_data as u64);

    for index in 0..length_data {
        indexes.push(first_index[&byte_to_hex(&file_data[index])]);
        bar.inc(1);
    }

    let bytes: Vec<u8> = indexes.iter().flat_map(|x| x.to_le_bytes()).collect();
    bar.finish();
    return bytes;
}


fn rebuild(cryptic_data: Vec<u8>, inverted_first_index: HashMap<i16, String>) -> Vec<u8> {
    let mut bytes = Vec::new();
    let size = std::mem::size_of::<i16>();
    let recovered_indexes: Vec<i16> = cryptic_data
        .chunks(size)
        .map(|chunk| i16::from_le_bytes(chunk.try_into().unwrap()))
        .collect();

    for indexes in recovered_indexes {
        bytes.push(hex_to_byte(&inverted_first_index[&indexes]).unwrap());
    }
    bytes
}

#[derive(Debug, PartialEq, Eq, Clone, EnumString, ValueEnum)]
enum Mode {
    Encrypt,
    Decrypt,
}

fn main() -> io::Result<()> {
    let matches = Command::new("File Encryptor/Decryptor")
        .version("1.0")
        .author("Mycoearthdome")
        .about("Encrypts or decrypts a file")
        .arg(
            Arg::new("mode")
                .required(true)
                .long("mode")
                .value_parser(clap::value_parser!(Mode))
                .help("Mode of operation (encrypt or decrypt)"),
        )
        .arg(
            Arg::new("input_file")
                .required(true)
                .long("input")
                .help("Input file to encrypt or decrypt"),
        )
        .arg(
            Arg::new("output_file")
                .required(false)
                .long("output")
                .help("Output file (optional)"),
        )
        .get_matches();

    let mode = matches.get_one::<Mode>("mode").unwrap();
    let input_file = matches.get_one::<String>("input_file").unwrap();
    let default_output_file = match mode {
        Mode::Encrypt => format!("{}.enc", input_file),
        Mode::Decrypt => format!("{}.dec", input_file),
    };
    let output_file = matches.get_one::<String>("output_file").unwrap_or(&default_output_file);

    match mode {
        Mode::Encrypt => {
            println!("Encrypting {} to {}", input_file, output_file);

            let (random_indexes, indexes_bytes) = random_indexes();
            let mut cryptic_data = seek_avail(input_file, random_indexes.clone());

            //println!("indexes_bytes={}", indexes_bytes.len()); //TEST OK - 512 bytes

            for seek in (0..indexes_bytes.len()).step_by(2){
                let index = i16::from_le_bytes([cryptic_data[seek], cryptic_data[seek + 1]]);
                println!("indexes_bytes={}", index);
                let _ = io::stdout().flush();
            }

            cryptic_data.extend(indexes_bytes); //our new index.
            

            let mut outfile = File::create(output_file)?;
            outfile.write_all(&cryptic_data)?;
        }
        Mode::Decrypt => {
            println!("Decrypting {} to {}", input_file, output_file);

            let mut cryptic_data = Vec::new();
            let mut cryptic_data_file = File::open(input_file)?;
            cryptic_data_file.read_to_end(&mut cryptic_data)?;


            //let inverted_first_index = invert_hashmap(hardcoded_index); 
            let (recoded_indexes, cryptic_data) = recode_indexes(cryptic_data);


            let rebuilt_bytes = rebuild(cryptic_data, recoded_indexes);
            let mut outfile = File::create(output_file)?;
            outfile.write_all(&rebuilt_bytes)?;
        }
    }

    Ok(())
}


fn recode_indexes(cryptic_data: Vec<u8>) -> (HashMap<i16, String>, Vec<u8>){
    let mut indexes = Vec::new();
    let mut recoded_indexes = HashMap::new();
    let start_index = cryptic_data.len()-512;
    for seek in (start_index..cryptic_data.len()).step_by(2){
        let index = i16::from_le_bytes([cryptic_data[seek], cryptic_data[seek + 1]]);
        indexes.push(index);
        println!("recoded_indexes={}", index);
        let _ = io::stdout().flush();
    }

    //println!("indexes={}", indexes.len()); //256 TEST OK.
    //let _ = io::stdout().flush();

    let mut count = 0;
    for key in HEX_ARRAY{ //TODO: CHANGE THAT NOW!.
        recoded_indexes.insert(indexes[count], key.to_string());
        count += 1;
    }
    


    (recoded_indexes, cryptic_data[..cryptic_data.len()-512].to_vec())
}