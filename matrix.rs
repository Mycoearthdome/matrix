use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufWriter, Read, Write};
use std::io;
use regex::Regex;
use std::fs::File;
use indicatif::ProgressBar;


fn write_reset(hex_table: &mut Vec<String>) {
    let file_path = "matrix.txt";
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_path).unwrap();

    let mut file = BufWriter::new(file);
    for hex in hex_table.drain(..) {
        file.write_all(hex.as_bytes()).unwrap();
        //file.write_all(b"\n").unwrap();
    }

}


fn build_first_index(joined_hex_table: &String) -> HashMap<String, usize>{
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

fn seek_avail(filename: &str, first_index:HashMap<String, usize>) -> Vec<u8> {
    let mut indexes = Vec::new();
    let mut file_data = Vec::new();

    let mut file = File::open(filename).unwrap();
    let _ = file.read_to_end(&mut file_data);

    let length_data = file_data.len();
    let bar = ProgressBar::new(length_data as u64);

    for index in 0..length_data{
        indexes.push(first_index[&byte_to_hex(&file_data[index])]);
        bar.inc(1);
    }
    

    let bytes: Vec<u8> = indexes.iter().flat_map(|x| x.to_le_bytes()).collect();
    bar.finish();
    return bytes
}



fn main(){

    let against_filename = "10M_file";

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
    for i in 0..10{
        for j in 0..10{
            hex_table.push(format!("{}{}", i,j));
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

                        for char_16_0 in hex_letters.chars(){
                            for char_10 in hexadecimal_10.chars(){
                                for char_16_1 in hex_letters.chars(){
                                    for char_9 in hexadecimal_9.chars(){
                                        for char_16_2 in hex_letters.chars(){
                                            for char_8 in hexadecimal_8.chars(){
                                                for char_16_3 in hex_letters.chars(){
                                                    for char_7 in hexadecimal_7.chars(){
                                                        for char_16_4 in hex_letters.chars(){
                                                            for char_6 in hexadecimal_6.chars(){
                                                                for char_16_5 in hex_letters.chars(){
                                                                    for char_5 in hexadecimal_5.chars(){
                                                                        for char_16_6 in hex_letters.chars(){
                                                                            for char_4 in hexadecimal_4.chars(){
                                                                                for char_16_7 in hex_letters.chars(){
                                                                                    for char_3 in hexadecimal_3.chars(){
                                                                                        for char_16_8 in hex_letters.chars(){
                                                                                            for char_2 in hexadecimal_2.chars(){
                                                                                                for char_16_9 in hex_letters.chars(){
                                                                                                    for char_1 in hexadecimal_1.chars(){
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

                        for char_16_0 in hex_letters.chars(){
                            for char_10 in hexadecimal_1.chars(){
                                for char_16_1 in hex_letters.chars(){
                                    for char_9 in hexadecimal_2.chars(){
                                        for char_16_2 in hex_letters.chars(){
                                            for char_8 in hexadecimal_3.chars(){
                                                for char_16_3 in hex_letters.chars(){
                                                    for char_7 in hexadecimal_4.chars(){
                                                        for char_16_4 in hex_letters.chars(){
                                                            for char_6 in hexadecimal_5.chars(){
                                                                for char_16_5 in hex_letters.chars(){
                                                                    for char_5 in hexadecimal_6.chars(){
                                                                        for char_16_6 in hex_letters.chars(){
                                                                            for char_4 in hexadecimal_7.chars(){
                                                                                for char_16_7 in hex_letters.chars(){
                                                                                    for char_3 in hexadecimal_8.chars(){
                                                                                        for char_16_8 in hex_letters.chars(){
                                                                                            for char_2 in hexadecimal_9.chars(){
                                                                                                for char_16_9 in hex_letters.chars(){
                                                                                                    for char_1 in hexadecimal_10.chars(){
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
    drop(hex_table);

    let first_index = build_first_index(joined_hex_table);
    
    joined_hex_table.clear();

    let cryptic_data = seek_avail(&against_filename, first_index.clone());

    let mut outfile = File::create("cryptic.data").unwrap();

    let _ = outfile.write_all(&cryptic_data);

    drop(cryptic_data);

    let mut cryptic_data_file = File::open("cryptic.data").unwrap();

    let mut cryptic_data = Vec::new();

    let _ = cryptic_data_file.read_to_end(&mut cryptic_data);

    let inverted_first_index = invert_hashmap(first_index);

    let rebuilt_bytes = rebuild(cryptic_data, inverted_first_index);

    let mut outfile = File::create("outfile.out").unwrap();

    let _ = outfile.write_all(&rebuilt_bytes);


}

fn invert_hashmap(map: HashMap<String, usize>) -> HashMap<usize, String> {
    let mut inverted_map = HashMap::new();
    for (key, value) in map {
        inverted_map.insert(value, key);
    }
    inverted_map
}


fn rebuild(cryptic_data: Vec<u8>, inverted_first_index:HashMap<usize, String>) -> Vec<u8>{
    let mut bytes = Vec::new();
    let size = std::mem::size_of::<usize>();
    let recovered_indexes: Vec<usize> = cryptic_data
        .chunks(size)
        .map(|chunk| usize::from_le_bytes(chunk.try_into().unwrap()))
        .collect();
    
    for indexes in recovered_indexes{
        bytes.push(hex_to_byte(&inverted_first_index[&indexes]).unwrap());

    }
    bytes
}