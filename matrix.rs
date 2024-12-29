use indicatif::ProgressBar;
use regex::Regex;
use std::collections::HashMap;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::{BufWriter, Read, Write};
use clap::{Arg, Command, ValueEnum};
use strum_macros::{EnumString, EnumIter};

fn hardcoded_indexes() -> HashMap<String, usize> {
    let mut indexes = HashMap::new();

    indexes.insert("00".to_string(), 0 as usize);
    indexes.insert("01".to_string(), 1 as usize);
    indexes.insert("02".to_string(), 36 as usize);
    indexes.insert("03".to_string(), 38 as usize);
    indexes.insert("04".to_string(), 40 as usize);
    indexes.insert("05".to_string(), 42 as usize);
    indexes.insert("06".to_string(), 44 as usize);
    indexes.insert("07".to_string(), 46 as usize);
    indexes.insert("08".to_string(), 48 as usize);
    indexes.insert("09".to_string(), 50 as usize);
    indexes.insert("0A".to_string(), 251 as usize);
    indexes.insert("0B".to_string(), 1410877691 as usize);
    indexes.insert("0C".to_string(), 2821755131 as usize);
    indexes.insert("0D".to_string(), 4232632571 as usize);
    indexes.insert("0E".to_string(), 5643510011 as usize);
    indexes.insert("0F".to_string(), 7054387451 as usize);
    indexes.insert("10".to_string(), 35 as usize);
    indexes.insert("11".to_string(), 2 as usize);
    indexes.insert("12".to_string(), 3 as usize);
    indexes.insert("13".to_string(), 58 as usize);
    indexes.insert("14".to_string(), 60 as usize);
    indexes.insert("15".to_string(), 62 as usize);
    indexes.insert("16".to_string(), 64 as usize);
    indexes.insert("17".to_string(), 66 as usize);
    indexes.insert("18".to_string(), 68 as usize);
    indexes.insert("19".to_string(), 70 as usize);
    indexes.insert("1A".to_string(), 249 as usize);
    indexes.insert("1B".to_string(), 389 as usize);
    indexes.insert("1C".to_string(), 529 as usize);
    indexes.insert("1D".to_string(), 669 as usize);
    indexes.insert("1E".to_string(), 809 as usize);
    indexes.insert("1F".to_string(), 949 as usize);
    indexes.insert("20".to_string(), 37 as usize);
    indexes.insert("21".to_string(), 57 as usize);
    indexes.insert("22".to_string(), 4 as usize);
    indexes.insert("23".to_string(), 5 as usize);
    indexes.insert("24".to_string(), 80 as usize);
    indexes.insert("25".to_string(), 82 as usize);
    indexes.insert("26".to_string(), 84 as usize);
    indexes.insert("27".to_string(), 86 as usize);
    indexes.insert("28".to_string(), 88 as usize);
    indexes.insert("29".to_string(), 90 as usize);
    indexes.insert("2A".to_string(), 247 as usize);
    indexes.insert("2B".to_string(), 1087 as usize);
    indexes.insert("2C".to_string(), 1927 as usize);
    indexes.insert("2D".to_string(), 2767 as usize);
    indexes.insert("2E".to_string(), 3607 as usize);
    indexes.insert("2F".to_string(), 4447 as usize);
    indexes.insert("30".to_string(), 39 as usize);
    indexes.insert("31".to_string(), 59 as usize);
    indexes.insert("32".to_string(), 79 as usize);
    indexes.insert("33".to_string(), 6 as usize);
    indexes.insert("34".to_string(), 7 as usize);
    indexes.insert("35".to_string(), 102 as usize);
    indexes.insert("36".to_string(), 104 as usize);
    indexes.insert("37".to_string(), 106 as usize);
    indexes.insert("38".to_string(), 108 as usize);
    indexes.insert("39".to_string(), 110 as usize);
    indexes.insert("3A".to_string(), 245 as usize);
    indexes.insert("3B".to_string(), 5285 as usize);
    indexes.insert("3C".to_string(), 10325 as usize);
    indexes.insert("3D".to_string(), 15365 as usize);
    indexes.insert("3E".to_string(), 20405 as usize);
    indexes.insert("3F".to_string(), 25445 as usize);
    indexes.insert("40".to_string(), 41 as usize);
    indexes.insert("41".to_string(), 61 as usize);
    indexes.insert("42".to_string(), 81 as usize);
    indexes.insert("43".to_string(), 101 as usize);
    indexes.insert("44".to_string(), 8 as usize);
    indexes.insert("45".to_string(), 9 as usize);
    indexes.insert("46".to_string(), 124 as usize);
    indexes.insert("47".to_string(), 126 as usize);
    indexes.insert("48".to_string(), 128 as usize);
    indexes.insert("49".to_string(), 130 as usize);
    indexes.insert("4A".to_string(), 243 as usize);
    indexes.insert("4B".to_string(), 30483 as usize);
    indexes.insert("4C".to_string(), 60723 as usize);
    indexes.insert("4D".to_string(), 90963 as usize);
    indexes.insert("4E".to_string(), 121203 as usize);
    indexes.insert("4F".to_string(), 151443 as usize);
    indexes.insert("50".to_string(), 43 as usize);
    indexes.insert("51".to_string(), 63 as usize);
    indexes.insert("52".to_string(), 83 as usize);
    indexes.insert("53".to_string(), 103 as usize);
    indexes.insert("54".to_string(), 123 as usize);
    indexes.insert("55".to_string(), 10 as usize);
    indexes.insert("56".to_string(), 11 as usize);
    indexes.insert("57".to_string(), 146 as usize);
    indexes.insert("58".to_string(), 148 as usize);
    indexes.insert("59".to_string(), 150 as usize);
    indexes.insert("5A".to_string(), 241 as usize);
    indexes.insert("5B".to_string(), 181681 as usize);
    indexes.insert("5C".to_string(), 363121 as usize);
    indexes.insert("5D".to_string(), 544561 as usize);
    indexes.insert("5E".to_string(), 726001 as usize);
    indexes.insert("5F".to_string(), 907441 as usize);
    indexes.insert("60".to_string(), 45 as usize);
    indexes.insert("61".to_string(), 65 as usize);
    indexes.insert("62".to_string(), 85 as usize);
    indexes.insert("63".to_string(), 105 as usize);
    indexes.insert("64".to_string(), 125 as usize);
    indexes.insert("65".to_string(), 145 as usize);
    indexes.insert("66".to_string(), 12 as usize);
    indexes.insert("67".to_string(), 13 as usize);
    indexes.insert("68".to_string(), 168 as usize);
    indexes.insert("69".to_string(), 170 as usize);
    indexes.insert("6A".to_string(), 239 as usize);
    indexes.insert("6B".to_string(), 1088879 as usize);
    indexes.insert("6C".to_string(), 2177519 as usize);
    indexes.insert("6D".to_string(), 3266159 as usize);
    indexes.insert("6E".to_string(), 4354799 as usize);
    indexes.insert("6F".to_string(), 5443439 as usize);
    indexes.insert("70".to_string(), 47 as usize);
    indexes.insert("71".to_string(), 67 as usize);
    indexes.insert("72".to_string(), 87 as usize);
    indexes.insert("73".to_string(), 107 as usize);
    indexes.insert("74".to_string(), 127 as usize);
    indexes.insert("75".to_string(), 147 as usize);
    indexes.insert("76".to_string(), 167 as usize);
    indexes.insert("77".to_string(), 14 as usize);
    indexes.insert("78".to_string(), 15 as usize);
    indexes.insert("79".to_string(), 190 as usize);
    indexes.insert("7A".to_string(), 237 as usize);
    indexes.insert("7B".to_string(), 6532077 as usize);
    indexes.insert("7C".to_string(), 13063917 as usize);
    indexes.insert("7D".to_string(), 19595757 as usize);
    indexes.insert("7E".to_string(), 26127597 as usize);
    indexes.insert("7F".to_string(), 32659437 as usize);
    indexes.insert("80".to_string(), 49 as usize);
    indexes.insert("81".to_string(), 69 as usize);
    indexes.insert("82".to_string(), 89 as usize);
    indexes.insert("83".to_string(), 109 as usize);
    indexes.insert("84".to_string(), 129 as usize);
    indexes.insert("85".to_string(), 149 as usize);
    indexes.insert("86".to_string(), 169 as usize);
    indexes.insert("87".to_string(), 189 as usize);
    indexes.insert("88".to_string(), 16 as usize);
    indexes.insert("89".to_string(), 17 as usize);
    indexes.insert("8A".to_string(), 235 as usize);
    indexes.insert("8B".to_string(), 39191275 as usize);
    indexes.insert("8C".to_string(), 78382315 as usize);
    indexes.insert("8D".to_string(), 117573355 as usize);
    indexes.insert("8E".to_string(), 156764395 as usize);
    indexes.insert("8F".to_string(), 195955435 as usize);
    indexes.insert("90".to_string(), 212 as usize);
    indexes.insert("91".to_string(), 51 as usize);
    indexes.insert("92".to_string(), 71 as usize);
    indexes.insert("93".to_string(), 91 as usize);
    indexes.insert("94".to_string(), 111 as usize);
    indexes.insert("95".to_string(), 131 as usize);
    indexes.insert("96".to_string(), 151 as usize);
    indexes.insert("97".to_string(), 171 as usize);
    indexes.insert("98".to_string(), 191 as usize);
    indexes.insert("99".to_string(), 18 as usize);
    indexes.insert("9A".to_string(), 19 as usize);
    indexes.insert("9B".to_string(), 235146473 as usize);
    indexes.insert("9C".to_string(), 470292713 as usize);
    indexes.insert("9D".to_string(), 705438953 as usize);
    indexes.insert("9E".to_string(), 940585193 as usize);
    indexes.insert("9F".to_string(), 1175731433 as usize);
    indexes.insert("A0".to_string(), 250 as usize);
    indexes.insert("A1".to_string(), 248 as usize);
    indexes.insert("A2".to_string(), 246 as usize);
    indexes.insert("A3".to_string(), 244 as usize);
    indexes.insert("A4".to_string(), 242 as usize);
    indexes.insert("A5".to_string(), 240 as usize);
    indexes.insert("A6".to_string(), 238 as usize);
    indexes.insert("A7".to_string(), 236 as usize);
    indexes.insert("A8".to_string(), 234 as usize);
    indexes.insert("A9".to_string(), 232 as usize);
    indexes.insert("AA".to_string(), 20 as usize);
    indexes.insert("AB".to_string(), 21 as usize);
    indexes.insert("AC".to_string(), 330 as usize);
    indexes.insert("AD".to_string(), 310 as usize);
    indexes.insert("AE".to_string(), 290 as usize);
    indexes.insert("AF".to_string(), 270 as usize);
    indexes.insert("B0".to_string(), 390 as usize);
    indexes.insert("B1".to_string(), 1088 as usize);
    indexes.insert("B2".to_string(), 5286 as usize);
    indexes.insert("B3".to_string(), 30484 as usize);
    indexes.insert("B4".to_string(), 181682 as usize);
    indexes.insert("B5".to_string(), 1088880 as usize);
    indexes.insert("B6".to_string(), 6532078 as usize);
    indexes.insert("B7".to_string(), 39191276 as usize);
    indexes.insert("B8".to_string(), 235146474 as usize);
    indexes.insert("B9".to_string(), 1410877672 as usize);
    indexes.insert("BA".to_string(), 351 as usize);
    indexes.insert("BB".to_string(), 22 as usize);
    indexes.insert("BC".to_string(), 23 as usize);
    indexes.insert("BD".to_string(), 450 as usize);
    indexes.insert("BE".to_string(), 430 as usize);
    indexes.insert("BF".to_string(), 410 as usize);
    indexes.insert("C0".to_string(), 530 as usize);
    indexes.insert("C1".to_string(), 1928 as usize);
    indexes.insert("C2".to_string(), 10326 as usize);
    indexes.insert("C3".to_string(), 60724 as usize);
    indexes.insert("C4".to_string(), 363122 as usize);
    indexes.insert("C5".to_string(), 2177520 as usize);
    indexes.insert("C6".to_string(), 13063918 as usize);
    indexes.insert("C7".to_string(), 78382316 as usize);
    indexes.insert("C8".to_string(), 470292714 as usize);
    indexes.insert("C9".to_string(), 2821755112 as usize);
    indexes.insert("CA".to_string(), 331 as usize);
    indexes.insert("CB".to_string(), 630 as usize);
    indexes.insert("CC".to_string(), 24 as usize);
    indexes.insert("CD".to_string(), 25 as usize);
    indexes.insert("CE".to_string(), 570 as usize);
    indexes.insert("CF".to_string(), 550 as usize);
    indexes.insert("D0".to_string(), 670 as usize);
    indexes.insert("D1".to_string(), 2768 as usize);
    indexes.insert("D2".to_string(), 15366 as usize);
    indexes.insert("D3".to_string(), 90964 as usize);
    indexes.insert("D4".to_string(), 544562 as usize);
    indexes.insert("D5".to_string(), 3266160 as usize);
    indexes.insert("D6".to_string(), 19595758 as usize);
    indexes.insert("D7".to_string(), 117573356 as usize);
    indexes.insert("D8".to_string(), 705438954 as usize);
    indexes.insert("D9".to_string(), 4232632552 as usize);
    indexes.insert("DA".to_string(), 311 as usize);
    indexes.insert("DB".to_string(), 770 as usize);
    indexes.insert("DC".to_string(), 750 as usize);
    indexes.insert("DD".to_string(), 26 as usize);
    indexes.insert("DE".to_string(), 27 as usize);
    indexes.insert("DF".to_string(), 690 as usize);
    indexes.insert("E0".to_string(), 810 as usize);
    indexes.insert("E1".to_string(), 3608 as usize);
    indexes.insert("E2".to_string(), 20406 as usize);
    indexes.insert("E3".to_string(), 121204 as usize);
    indexes.insert("E4".to_string(), 726002 as usize);
    indexes.insert("E5".to_string(), 4354800 as usize);
    indexes.insert("E6".to_string(), 26127598 as usize);
    indexes.insert("E7".to_string(), 156764396 as usize);
    indexes.insert("E8".to_string(), 940585194 as usize);
    indexes.insert("E9".to_string(), 5643509992 as usize);
    indexes.insert("EA".to_string(), 291 as usize);
    indexes.insert("EB".to_string(), 910 as usize);
    indexes.insert("EC".to_string(), 890 as usize);
    indexes.insert("ED".to_string(), 870 as usize);
    indexes.insert("EE".to_string(), 28 as usize);
    indexes.insert("EF".to_string(), 29 as usize);
    indexes.insert("F0".to_string(), 31 as usize);
    indexes.insert("F1".to_string(), 4448 as usize);
    indexes.insert("F2".to_string(), 25446 as usize);
    indexes.insert("F3".to_string(), 151444 as usize);
    indexes.insert("F4".to_string(), 907442 as usize);
    indexes.insert("F5".to_string(), 5443440 as usize);
    indexes.insert("F6".to_string(), 32659438 as usize);
    indexes.insert("F7".to_string(), 195955436 as usize);
    indexes.insert("F8".to_string(), 1175731434 as usize);
    indexes.insert("F9".to_string(), 7054387432 as usize);
    indexes.insert("FA".to_string(), 271 as usize);
    indexes.insert("FB".to_string(), 1050 as usize);
    indexes.insert("FC".to_string(), 1030 as usize);
    indexes.insert("FD".to_string(), 1010 as usize);
    indexes.insert("FE".to_string(), 990 as usize);
    indexes.insert("FF".to_string(), 30 as usize);

    indexes
}

fn write_reset(hex_table: &mut Vec<String>) {
    let file_path = "matrix.txt";
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_path)
        .unwrap();

    let mut file = BufWriter::new(file);
    for hex in hex_table.drain(..) {
        file.write_all(hex.as_bytes()).unwrap();
        //file.write_all(b"\n").unwrap();
    }
}

fn seek_indexes(joined_hex_table: &String) {
    for i in 0..256 {
        let hex_byte = format!("{:02x}", i).to_uppercase();
        if let Some(index) = joined_hex_table.find(&hex_byte) {
            println!(
                "indexes.insert(\"{}\".to_string(),{} as usize);",
                hex_byte, index
            );
        }
    }
}

fn build_first_index(joined_hex_table: &String) -> HashMap<String, usize> {
    let mut first_index = HashMap::new();
    for i in 0..256 {
        let hex_byte = format!("{:02x}", i).to_uppercase();
        if let Some(index) = joined_hex_table.find(&hex_byte) {
            first_index.insert(hex_byte, index);
        }
    }
    first_index
}

fn byte_to_hex(byte: &u8) -> String {
    format!("{:02X}", byte).to_uppercase()
}

fn hex_to_byte(hex: &str) -> Option<u8> {
    u8::from_str_radix(hex, 16).ok()
}

fn seek_avail(filename: &str, first_index: HashMap<String, usize>) -> Vec<u8> {
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

fn invert_hashmap(map: HashMap<String, usize>) -> HashMap<usize, String> {
    let mut inverted_map = HashMap::new();
    for (key, value) in map {
        inverted_map.insert(value, key);
    }
    inverted_map
}

fn rebuild(cryptic_data: Vec<u8>, inverted_first_index: HashMap<usize, String>) -> Vec<u8> {
    let mut bytes = Vec::new();
    let size = std::mem::size_of::<usize>();
    let recovered_indexes: Vec<usize> = cryptic_data
        .chunks(size)
        .map(|chunk| usize::from_le_bytes(chunk.try_into().unwrap()))
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

            let hardcoded_index = hardcoded_indexes();
            let cryptic_data = seek_avail(input_file, hardcoded_index.clone()); 

            let mut outfile = File::create(output_file)?;
            outfile.write_all(&cryptic_data)?;
        }
        Mode::Decrypt => {
            println!("Decrypting {} to {}", input_file, output_file);

            let hardcoded_index = hardcoded_indexes(); 
            let mut cryptic_data = Vec::new();
            let mut cryptic_data_file = File::open(input_file)?;
            cryptic_data_file.read_to_end(&mut cryptic_data)?;

            let inverted_first_index = invert_hashmap(hardcoded_index); 
            let rebuilt_bytes = rebuild(cryptic_data, inverted_first_index);
            let mut outfile = File::create(output_file)?;
            outfile.write_all(&rebuilt_bytes)?;
        }
    }

    Ok(())
}
////THE HOW!

    //let against_filename = "10M_file";

    /*
    let mut hex_table = Vec::new();

    let hexadecimal_dbl_0 = "00".to_string();
    let hexadecimal_dbl_1 = "11".to_string();
    let hexadecimal_dbl_2 = "22".to_string();
    let hexadecimal_dbl_3 = "33".to_string();
    let hexadecimal_dbl_4 = "44".to_string();
    let hexadecimal_dbl_5 = "55".to_string();
    let hexadecimal_dbl_6 = "66".to_string();
    let hexadecimal_dbl_7 = "77".to_string();
    let hexadecimal_dbl_8 = "88".to_string();
    let hexadecimal_dbl_9 = "99".to_string();
    let hexadecimal_dbl_10 = "AA".to_string();
    let hexadecimal_dbl_11 = "BB".to_string();
    let hexadecimal_dbl_12 = "CC".to_string();
    let hexadecimal_dbl_13 = "DD".to_string();
    let hexadecimal_dbl_14 = "EE".to_string();
    let hexadecimal_dbl_15 = "FF".to_string();

    //Double values
    hex_table.push(hexadecimal_dbl_0);
    hex_table.push(hexadecimal_dbl_1);
    hex_table.push(hexadecimal_dbl_2);
    hex_table.push(hexadecimal_dbl_3);
    hex_table.push(hexadecimal_dbl_4);
    hex_table.push(hexadecimal_dbl_5);
    hex_table.push(hexadecimal_dbl_6);
    hex_table.push(hexadecimal_dbl_7);
    hex_table.push(hexadecimal_dbl_8);
    hex_table.push(hexadecimal_dbl_9);
    hex_table.push(hexadecimal_dbl_10);
    hex_table.push(hexadecimal_dbl_11);
    hex_table.push(hexadecimal_dbl_12);
    hex_table.push(hexadecimal_dbl_13);
    hex_table.push(hexadecimal_dbl_14);
    hex_table.push(hexadecimal_dbl_15);

    //Double numeric values
    for i in 0..10 {
        for j in 0..10 {
            hex_table.push(format!("{}{}", i, j));
        }
    }

    //Unique values
    let hex_letters = "ABCDEF";
    let hexadecimal_10 = "9";
    let hexadecimal_9 = "8";
    let hexadecimal_8 = "7";
    let hexadecimal_7 = "6";
    let hexadecimal_6 = "5";
    let hexadecimal_5 = "4";
    let hexadecimal_4 = "3";
    let hexadecimal_3 = "2";
    let hexadecimal_2 = "1";
    let hexadecimal_1 = "0FEDCBA";

    //DESCENDING...

    for char_16_0 in hex_letters.chars() {
        for char_10 in hexadecimal_10.chars() {
            for char_16_1 in hex_letters.chars() {
                for char_9 in hexadecimal_9.chars() {
                    for char_16_2 in hex_letters.chars() {
                        for char_8 in hexadecimal_8.chars() {
                            for char_16_3 in hex_letters.chars() {
                                for char_7 in hexadecimal_7.chars() {
                                    for char_16_4 in hex_letters.chars() {
                                        for char_6 in hexadecimal_6.chars() {
                                            for char_16_5 in hex_letters.chars() {
                                                for char_5 in hexadecimal_5.chars() {
                                                    for char_16_6 in hex_letters.chars() {
                                                        for char_4 in hexadecimal_4.chars() {
                                                            for char_16_7 in hex_letters.chars() {
                                                                for char_3 in hexadecimal_3.chars()
                                                                {
                                                                    for char_16_8 in
                                                                        hex_letters.chars()
                                                                    {
                                                                        for char_2 in
                                                                            hexadecimal_2.chars()
                                                                        {
                                                                            for char_16_9 in
                                                                                hex_letters.chars()
                                                                            {
                                                                                for char_1 in
                                                                                    hexadecimal_1
                                                                                        .chars()
                                                                                {
                                                                                    hex_table.push(format!("{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}", char_16_0,char_10,char_16_1,char_9,char_16_2,char_8,char_16_3,char_7,char_16_4,char_6,char_16_5, char_5, char_16_6,char_4, char_16_7,char_3,char_16_8, char_2,char_16_9, char_1));
                                                                                    //println!("{}", format!("{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}", char_16, char_15, char_14, char_13, char_12, char_11, char_10, char_9, char_8, char_7, char_6, char_5, char_4, char_3, char_2, char_1));
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // ASCENDING ...

    for char_16_0 in hex_letters.chars() {
        for char_10 in hexadecimal_1.chars() {
            for char_16_1 in hex_letters.chars() {
                for char_9 in hexadecimal_2.chars() {
                    for char_16_2 in hex_letters.chars() {
                        for char_8 in hexadecimal_3.chars() {
                            for char_16_3 in hex_letters.chars() {
                                for char_7 in hexadecimal_4.chars() {
                                    for char_16_4 in hex_letters.chars() {
                                        for char_6 in hexadecimal_5.chars() {
                                            for char_16_5 in hex_letters.chars() {
                                                for char_5 in hexadecimal_6.chars() {
                                                    for char_16_6 in hex_letters.chars() {
                                                        for char_4 in hexadecimal_7.chars() {
                                                            for char_16_7 in hex_letters.chars() {
                                                                for char_3 in hexadecimal_8.chars()
                                                                {
                                                                    for char_16_8 in
                                                                        hex_letters.chars()
                                                                    {
                                                                        for char_2 in
                                                                            hexadecimal_9.chars()
                                                                        {
                                                                            for char_16_9 in
                                                                                hex_letters.chars()
                                                                            {
                                                                                for char_1 in
                                                                                    hexadecimal_10
                                                                                        .chars()
                                                                                {
                                                                                    hex_table.push(format!("{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}", char_16_0,char_10,char_16_1,char_9,char_16_2,char_8,char_16_3,char_7,char_16_4,char_6,char_16_5, char_5, char_16_6,char_4, char_16_7,char_3,char_16_8, char_2,char_16_9, char_1));
                                                                                    //println!("{}", format!("{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}", char_16, char_15, char_14, char_13, char_12, char_11, char_10, char_9, char_8, char_7, char_6, char_5, char_4, char_3, char_2, char_1));
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    //write_reset(&mut hex_table);
    let joined_hex_table = &mut hex_table.join("");

    println!("indexes #{}-->Start at {}", "0", "0");

    seek_indexes(joined_hex_table);

    let first_index = build_first_index(joined_hex_table);

    drop(hex_table);

    joined_hex_table.clear(); */


    

