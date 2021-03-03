use openssl::{rsa::Rsa, symm::Cipher};
use std::{any::type_name, io::{self, Write}, fs};

macro_rules! read {
    ($statement:literal, $return_type:ty) => {{
        print!("{}: ", $statement);
        io::stdout().flush().expect("flush failed!");
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line");
        input.trim().parse::<$return_type>().unwrap()
    }};
}

fn type_of<T>(_: &T) -> &str {
    type_name::<T>()
}

fn generate_rsa_private_key(passphrase: Option<String>) -> String {
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

fn write_to_file(filename: String, data: String) -> io::Result<()> {
    let mut is_ok = true;
    let root_dir = "./out";
    if let Err(err) = fs::create_dir(root_dir) {
        if !err.kind().eq(&io::ErrorKind::AlreadyExists) {
            is_ok = false;
            println!("Directory Create Failed: {:?}", err);
        }
    }
    if is_ok {
        let mut file = fs::File::create(format!("{}/{}", root_dir, filename))?;
        file.write_all(data.as_bytes())?;
        file.sync_data()?;
    }
    Ok(())
}

fn main() {
    let filename = read!("Enter file basename", String);
    let passphrase = read!("Enter a Passphrase", String);
    let private_key = generate_rsa_private_key(Some(passphrase));
    match write_to_file(format!("{}{}", filename, ".key"), private_key) {
        Ok(_) => {},
        Err(err) => {
            println!("Writing to File Failed: {:?}", err);
        }
    }

}
