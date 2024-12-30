use indicatif::ProgressBar;
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use clap::{Arg, Command, ValueEnum};
use strum_macros::EnumString;
use rand::thread_rng;
use rand::prelude::SliceRandom;

use std::sync::{Arc, Mutex};
use std::thread;

use std::net::{TcpListener, TcpStream};
use tun_tap::{Iface, Mode as TunMode};

use std::time::Duration;

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


#[repr(C)]
#[derive(Debug)]
struct EthernetHeader {
    destination: [u8; 6],
    source: [u8; 6],
    ethertype: u16,
}


#[repr(C)]
#[derive(Debug)]
struct IpHeader {
    version_ihl: u8, // Version and IHL
    tos: u8,         // Type of Service
    total_length: u16,
    identification: u16,
    flags_offset: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    source: [u8; 4],
    destination: [u8; 4],
}


#[repr(C)]
#[derive(Debug)]
struct TcpHeader {
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
    data_offset_flags: u16, // Data offset and flags
    window: u16,
    checksum: u16,
    urgent_pointer: u16,
}

// Implement conversion methods for headers to bytes
impl EthernetHeader {
    fn to_bytes(&self) -> [u8; std::mem::size_of::<EthernetHeader>()] {
        let mut bytes = [0u8; std::mem::size_of::<EthernetHeader>()];
        bytes[..6].copy_from_slice(&self.destination);
        bytes[6..12].copy_from_slice(&self.source);
        bytes[12..14].copy_from_slice(&self.ethertype.to_be_bytes());
        bytes
    }
}

impl IpHeader {
    fn to_bytes(&self) -> [u8; std::mem::size_of::<IpHeader>()] {
        let mut bytes = [0u8; std::mem::size_of::<IpHeader>()];
        bytes[0] = self.version_ihl;
        bytes[1] = self.tos;
        bytes[2..4].copy_from_slice(&self.total_length.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.identification.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.flags_offset.to_be_bytes());
        bytes[8] = self.ttl;
        bytes[9] = self.protocol;
        bytes[10..12].copy_from_slice(&self.checksum.to_be_bytes());
        bytes[12..16].copy_from_slice(&self.source);
        bytes[16..20].copy_from_slice(&self.destination);
        bytes
    }
}

impl TcpHeader {
    fn to_bytes(&self) -> [u8; std::mem::size_of::<TcpHeader>()] {
        let mut bytes = [0u8; std::mem::size_of::<TcpHeader>()];
        bytes[0..2].copy_from_slice(&self.source_port.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.destination_port.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.sequence_number.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.acknowledgment_number.to_be_bytes());
        bytes[12..14].copy_from_slice(&self.data_offset_flags.to_be_bytes());
        bytes[14..16].copy_from_slice(&self.window.to_be_bytes());
        bytes[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        bytes[18..20].copy_from_slice(&self.urgent_pointer.to_be_bytes());
        bytes
    }
}


fn extract_tcp_payload(packet: &[u8]) -> Option<(&[u8], usize)> {
    // Check if the packet is long enough to contain an Ethernet header
    if packet.len() < std::mem::size_of::<EthernetHeader>() {
        return None;
    }

    // Parse Ethernet header
    let eth_header: &EthernetHeader = unsafe { &*(packet.as_ptr() as *const EthernetHeader) };

    // Check if the ethertype indicates an IPv4 packet (0x0800)
    if eth_header.ethertype != 0x0800 {
        return None;
    }

    // Check if the packet is long enough to contain an IP header
    let ip_header_offset = std::mem::size_of::<EthernetHeader>();
    if packet.len() < ip_header_offset + std::mem::size_of::<IpHeader>() {
        return None;
    }

    // Parse IP header
    let ip_header: &IpHeader = unsafe { &*(packet[ip_header_offset..].as_ptr() as *const IpHeader) };

    // Check if the protocol is TCP (6)
    if ip_header.protocol != 6 {
        return None;
    }

    // Check if the packet is long enough to contain a TCP header
    let ip_header_length = (ip_header.version_ihl & 0x0F) as usize * 4; // IHL is in 32-bit words
    let tcp_header_offset = ip_header_offset + ip_header_length;
    if packet.len() < tcp_header_offset + std::mem::size_of::<TcpHeader>() {
        return None;
    }

    // Parse TCP header
    let tcp_header: &TcpHeader = unsafe { &*(packet[tcp_header_offset..].as_ptr() as *const TcpHeader) };

    // Calculate the TCP header length
    let tcp_header_length = ((tcp_header.data_offset_flags >> 12) & 0x0F) as usize * 4; // Data offset is in 32-bit words

    // The payload starts after the TCP header
    let payload_start = tcp_header_offset + tcp_header_length;
    if payload_start < packet.len() {
        Some((&packet[payload_start..], payload_start)) // Return the TCP payload and payload offset
    } else {
        None
    }
}

fn start_tunnel(local_ip: &str, local_port: u16, remote_ip: &str, remote_port: u16) {
    // Create a new TUN device
    let iface = Arc::new(Mutex::new(Iface::new("tun0", TunMode::Tun).unwrap()));

    // Create a TCP listener for incoming connections
    let listener = TcpListener::bind(format!("{}:{}", local_ip, local_port)).expect("Could not bind TCP listener");

    // Accept incoming connections in a separate thread
    let iface_clone = Arc::clone(&iface);
    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    // Handle the connection in a new thread
                    let iface_clone = Arc::clone(&iface_clone);
                    let stream = Arc::new(Mutex::new(stream)); // Wrap the stream in Arc<Mutex>
                    thread::spawn(move || handle_incoming_connection(stream, iface_clone));
                }
                Err(e) => eprintln!("Failed to accept connection: {}", e),
            }
        }
    });

    // Sleep for 1 minute (60 seconds)
    let duration = Duration::new(60, 0);
    println!("Wait for 1 minute...");
    thread::sleep(duration);
    println!("Connecting!");

    // Connect to the remote peer
    let stream = Arc::new(Mutex::new(TcpStream::connect(format!("{}:{}", remote_ip, remote_port)).expect("Could not connect to remote peer")));

    // Thread to read from TUN and send to remote peer(tx)
    let iface_clone = Arc::clone(&iface);
    let stream_clone = Arc::clone(&stream); // Clone the Arc for the thread
    //thread::spawn(move || {
    //    let mut buf = [0u8; 2048]; // Buffer for reading packets
    //    loop {
    //        let len = iface_clone.lock().unwrap().recv(&mut buf).expect("Failed to read from TUN");

    //        let mut stream = stream_clone.lock().unwrap(); // Lock the stream for writing
    //        stream.write_all(&buf[..len]).expect("Failed to send packet to remote peer");
    //    }
    //});
    handle_outgoing_connection(stream_clone, iface_clone);

    // Keep the main thread alive
    loop {
        thread::park();
    }
}

fn handle_incoming_connection(stream: Arc<Mutex<TcpStream>>, iface: Arc<Mutex<Iface>>) { //decrypts on the fly.
    let mut buf = [0u8; 2048]; // Buffer for reading packets
    loop {
        match stream.lock().unwrap().read(&mut buf) {
            Ok(0) => break, // Connection closed
            Ok(nbytes) => {
                // Ensure the packet is long enough to contain the headers
                if nbytes < std::mem::size_of::<EthernetHeader>() + std::mem::size_of::<IpHeader>() + std::mem::size_of::<TcpHeader>() {
                    eprintln!("Received packet is too small.");
                    continue;
                }

                // Parse the headers
                let eth_header: &EthernetHeader = unsafe { &*(buf.as_ptr() as *const EthernetHeader) };
                let ip_header: &IpHeader = unsafe { &*(buf[std::mem::size_of::<EthernetHeader>()..].as_ptr() as *const IpHeader) };
                let tcp_header: &TcpHeader = unsafe { &*(buf[(std::mem::size_of::<EthernetHeader>() + std::mem::size_of::<IpHeader>())..].as_ptr() as *const TcpHeader) };

                // Extract the TCP payload
                let ip_header_length = (ip_header.version_ihl & 0x0F) as usize * 4; // IHL is in 32-bit words
                let tcp_header_length = ((tcp_header.data_offset_flags >> 12) & 0x0F) as usize * 4; // Data offset is in 32-bit words
                let payload_start = std::mem::size_of::<EthernetHeader>() + std::mem::size_of::<IpHeader>() + tcp_header_length;
                let old_payload = &buf[payload_start..nbytes];

                // Modify the payload.
                let old_payload = old_payload.to_vec();
                let (recoded_indexes, cryptic_data) = recode_indexes(old_payload.clone());
                let decrypted_payload = rebuild(cryptic_data, recoded_indexes);
                let decrypted_payload_length = decrypted_payload.len();

                // Construct the new packet
                let total_length = (std::mem::size_of::<IpHeader>() + std::mem::size_of::<TcpHeader>() + decrypted_payload_length) as u16;

                // Create new headers
                let new_ip_header = IpHeader {
                    version_ihl: 0x45, // Version 4, IHL 5 (20 bytes)
                    tos: 0,
                    total_length,
                    identification: 0,
                    flags_offset: 0,
                    ttl: 64,
                    protocol: 6, // TCP
                    checksum: 0, // Calculate checksum later
                    source: ip_header.source, // Use the original source IP
                    destination: ip_header.destination, // Use the original destination IP
                };

                let new_tcp_header = TcpHeader {
                    source_port: tcp_header.source_port, // Use the original source port
                    destination_port: tcp_header.destination_port, // Use the original destination port
                    sequence_number: tcp_header.sequence_number + decrypted_payload_length as u32, // Update sequence number
                    acknowledgment_number: tcp_header.acknowledgment_number, // Use the original acknowledgment number
                    data_offset_flags: (5 << 12) | 0, // Data offset (5 for 20 bytes) and flags
                    window: tcp_header.window, // Use the original window size
                    checksum: 0, // Calculate checksum later
                    urgent_pointer: 0,
                };

                // Create a buffer to hold the full packet
                let mut new_packet = Vec::new();
                new_packet.extend_from_slice(&eth_header.to_bytes());
                new_packet.extend_from_slice(&new_ip_header.to_bytes());
                new_packet.extend_from_slice(&new_tcp_header.to_bytes());
                new_packet.extend_from_slice(&decrypted_payload); // Append the decrypted TCP payload

                // Send the new packet to the TUN interface
                let iface = iface.lock().unwrap();
                iface.send(&new_packet).expect("Failed to write to TUN");
            }
            Err(e) => {
                eprintln!("Failed to read from stream: {}", e);
                break;
            }
        }
    }
}


fn handle_outgoing_connection(stream: Arc<Mutex<TcpStream>>, iface: Arc<Mutex<Iface>>) { //encrypts on the fly.
    let mut buf = [0u8; 2048]; // Buffer for reading packets
    loop {
        match stream.lock().unwrap().read(&mut buf) {
            Ok(0) => break, // Connection closed
            Ok(nbytes) => {
                // Ensure the packet is long enough to contain the headers
                if nbytes < std::mem::size_of::<EthernetHeader>() + std::mem::size_of::<IpHeader>() + std::mem::size_of::<TcpHeader>() {
                    eprintln!("Received packet is too small.");
                    continue;
                }

                // Parse the headers
                let eth_header: &EthernetHeader = unsafe { &*(buf.as_ptr() as *const EthernetHeader) };
                let ip_header: &IpHeader = unsafe { &*(buf[std::mem::size_of::<EthernetHeader>()..].as_ptr() as *const IpHeader) };
                let tcp_header: &TcpHeader = unsafe { &*(buf[(std::mem::size_of::<EthernetHeader>() + std::mem::size_of::<IpHeader>())..].as_ptr() as *const TcpHeader) };

                // Extract the TCP payload
                let ip_header_length = (ip_header.version_ihl & 0x0F) as usize * 4; // IHL is in 32-bit words
                let tcp_header_length = ((tcp_header.data_offset_flags >> 12) & 0x0F) as usize * 4; // Data offset is in 32-bit words
                let payload_start = std::mem::size_of::<EthernetHeader>() + std::mem::size_of::<IpHeader>() + tcp_header_length;
                let old_payload = &buf[payload_start..nbytes];

                // Modify the payload.
                let old_payload = old_payload.to_vec();
                let (random_indexes, indexes_bytes) = random_indexes();
                let mut new_payload = modify_packet_payload(&old_payload, random_indexes);
                new_payload.extend(indexes_bytes); //indexed at the end of the payload.
                let new_payload_length = new_payload.len();

                // Construct the new packet
                let total_length = (std::mem::size_of::<IpHeader>() + std::mem::size_of::<TcpHeader>() + new_payload_length) as u16;

                // Create new headers
                let new_ip_header = IpHeader {
                    version_ihl: 0x45, // Version 4, IHL 5 (20 bytes)
                    tos: 0,
                    total_length,
                    identification: 0,
                    flags_offset: 0,
                    ttl: 64,
                    protocol: 6, // TCP
                    checksum: 0, // Calculate checksum later
                    source: ip_header.source, // Use the original source IP
                    destination: ip_header.destination, // Use the original destination IP
                };

                let new_tcp_header = TcpHeader {
                    source_port: tcp_header.source_port, // Use the original source port
                    destination_port: tcp_header.destination_port, // Use the original destination port
                    sequence_number: tcp_header.sequence_number + new_payload.len() as u32, // Update sequence number
                    acknowledgment_number: tcp_header.acknowledgment_number, // Use the original acknowledgment number
                    data_offset_flags: (5 << 12) | 0, // Data offset (5 for 20 bytes) and flags
                    window: tcp_header.window, // Use the original window size
                    checksum: 0, // Calculate checksum later
                    urgent_pointer: 0,
                };

                // Create a buffer to hold the full packet
                let mut new_packet = Vec::new();
                new_packet.extend_from_slice(&eth_header.to_bytes());
                new_packet.extend_from_slice(&new_ip_header.to_bytes());
                new_packet.extend_from_slice(&new_tcp_header.to_bytes());
                new_packet.extend_from_slice(&new_payload); // Append the new TCP payload


                //TODO: ADJUST CHECKSUMS.(IP-TCP)

                // Send the new packet to the remote peer.
                stream.lock().unwrap().write_all(&new_packet).expect("Failed to send mofified packet to remote peer");
            }
            Err(e) => {
                eprintln!("Failed to read from stream: {}", e);
                break;
            }
        }
    }
}
               

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


fn modify_packet_payload(payload: &Vec<u8>,first_index: HashMap<String, i16>) -> Vec<u8> {
    let mut indexes = Vec::new();

    for byte in payload {
        indexes.push(first_index[&byte_to_hex(&byte)]);
    }

    let bytes: Vec<u8> = indexes.iter().flat_map(|x| x.to_le_bytes()).collect();
    return bytes;
}

fn decrypt_packet_payload(payload: Vec<u8>,first_index: HashMap<String, i16>) -> Vec<u8> {
    let mut indexes = Vec::new();

    for byte in payload {
        indexes.push(first_index[&byte_to_hex(&byte)]);
    }

    let bytes: Vec<u8> = indexes.iter().flat_map(|x| x.to_le_bytes()).collect();
    return bytes;
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
    Tun,
}

fn main() -> io::Result<()> {
    let matches = Command::new("File Encryptor/Decryptor")
        .version("1.0")
        .author("Mycoearthdome")
        .about("Encrypts or decrypts a file or sets up a tunnel")
        .arg(
            Arg::new("mode")
                .required(true)
                .long("mode")
                .value_parser(clap::value_parser!(Mode))
                .help("Mode of operation (encrypt, decrypt, or tun)"),
        )
        .arg(
            Arg::new("input_file")
                .long("input")
                .value_parser(clap::value_parser!(String))
                .help("Input file to encrypt or decrypt"),
        )
        .arg(
            Arg::new("output_file")
                .long("output")
                .value_parser(clap::value_parser!(String))
                .help("Output file (optional)"),
        )
        .arg(
            Arg::new("local_ip")
                .required_if_eq("mode", "tun")
                .long("local-ip")
                .value_parser(clap::value_parser!(String))
                .help("Local IP address for the tunnel"),
        )
        .arg(
            Arg::new("local_port")
                .required_if_eq("mode", "tun")
                .long("local-port")
                .value_parser(clap::value_parser!(u16)) // Assuming port is a number
                .help("Local port for the tunnel"),
        )
        .arg(
            Arg::new("remote_ip")
                .required_if_eq("mode", "tun")
                .long("remote-ip")
                .value_parser(clap::value_parser!(String))
                .help("Remote IP address for the tunnel"),
        )
        .arg(
            Arg::new("remote_port")
                .required_if_eq("mode", "tun")
                .long("remote-port")
                .value_parser(clap::value_parser!(u16)) // Assuming port is a number
                .help("Remote port for the tunnel"),
        )
        .get_matches();

    let cli_mode = matches.get_one::<Mode>("mode").unwrap();

    match cli_mode {
        Mode::Encrypt => {
            let input_file = matches.get_one::<String>("input_file").unwrap_or_else(|| {
                eprintln!("Error: --input is required in encrypt mode.");
                std::process::exit(1);
            });
            let default_output_file = format!("{}.enc", input_file);
            let output_file = matches.get_one::<String>("output_file").unwrap_or(&default_output_file);
            println!("Encrypting {} to {}", input_file, output_file);

            let (random_indexes, indexes_bytes) = random_indexes();
            let mut cryptic_data = seek_avail(input_file, random_indexes.clone());

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
            let input_file = matches.get_one::<String>("input_file").unwrap_or_else(|| {
                eprintln!("Error: --input is required in decrypt mode.");
                std::process::exit(1);
            });
            let default_output_file = format!("{}.dec", input_file);
            let output_file = matches.get_one::<String>("output_file").unwrap_or(&default_output_file);

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
        Mode::Tun => {
            let local_ip = matches.get_one::<String>("local_ip").unwrap();
            let local_port = matches.get_one::<u16>("local_port").unwrap();
            let remote_ip = matches.get_one::<String>("remote_ip").unwrap();
            let remote_port = matches.get_one::<u16>("remote_port").unwrap();
            println!("Setting up tunnel from {}:{} to {}:{}", local_ip, local_port, remote_ip, remote_port);
            start_tunnel(&*local_ip, *local_port, &*remote_ip, *remote_port);
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