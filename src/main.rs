use std::{
    any::type_name,
    io,
    io::Write
};
use openssl::{
    rsa::{Rsa},
    symm::Cipher,
};

macro_rules! read {
    ($statement:literal, $return_type:ty) => {{
        print!("{}: ", $statement);
        io::stdout().flush().expect("flush failed!");
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read line");
        input.trim().parse::<$return_type>().unwrap()
    }};
}

fn type_of<T>(_: &T) -> &str {
    type_name::<T>()
}

fn generate_rsa_key(passphrase: Option<String>) -> String {
    let rsa = Rsa::generate(2048).unwrap();
    let passphrase = passphrase.unwrap_or("shevy".to_string());
    let buffer = rsa
        .private_key_to_pem_passphrase(Cipher::des_ede3_cbc(), passphrase.as_bytes())
        .unwrap();
    let m_str = match String::from_utf8(buffer) {
        Ok(v) => v,
        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    };
    println!("{:?}", m_str);
    m_str
}

fn main() {
    let passphrase = read!("Enter a Passphrase", String);
    println!("Generated: {}", generate_rsa_key(Some(passphrase)));
}
