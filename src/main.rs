use openssl::{asn1, bn, hash, nid, pkey, rsa::Rsa, symm::Cipher, x509};
use std::{
    any::type_name,
    fs,
    io::{self, Write},
    process,
};

mod macros;

struct SslData {
    private_key: String,
    cert: String,
}

#[allow(dead_code)]
fn type_of<T>(_: &T) -> &str {
    type_name::<T>()
}

fn generate_certificate(pem: &[u8], passphrase: &[u8]) -> io::Result<Vec<u8>> {
    let private_key = pkey::PKey::private_key_from_pem_passphrase(pem, passphrase)?;
    let mut subject_name = x509::X509NameBuilder::new().unwrap();
    let expiry_days = asn1::Asn1Time::days_from_now(read!("Expiry Days", u32))?;
    subject_name.append_entry_by_nid(
        nid::Nid::COUNTRYNAME,
        &read!("Country Name (2 letter code)", String),
    )?;
    subject_name.append_entry_by_nid(
        nid::Nid::STATEORPROVINCENAME,
        &read!("State or Province Name (full name)", String),
    )?;
    subject_name.append_entry_by_nid(
        nid::Nid::LOCALITYNAME,
        &read!("Locality Name (eg, city)", String),
    )?;
    subject_name.append_entry_by_nid(
        nid::Nid::ORGANIZATIONNAME,
        &read!("Organization Name (eg, company)", String),
    )?;
    subject_name.append_entry_by_nid(
        nid::Nid::ORGANIZATIONALUNITNAME,
        &read!("Organization Uni Name (eg, section)", String),
    )?;
    subject_name.append_entry_by_nid(
        nid::Nid::COMMONNAME,
        &read!("Common Name (eg, fully qualified host name)", String),
    )?;
    subject_name.append_entry_by_nid(
        nid::Nid::PKCS9_EMAILADDRESS,
        &read!("Email Address", String),
    )?;
    let subject_name = subject_name.build();
    let mut cert = x509::X509Builder::new().unwrap();
    cert.set_version(2)?;
    cert.set_serial_number(
        &asn1::Asn1Integer::from_bn(&bn::BigNum::from_u32(1).unwrap()).unwrap(),
    )?;
    cert.set_not_before(&asn1::Asn1Time::days_from_now(0).unwrap())?;
    cert.set_not_after(&expiry_days)?;
    cert.set_subject_name(&subject_name)?;
    cert.set_issuer_name(&subject_name)?;
    cert.set_pubkey(&private_key)?;
    cert.sign(&private_key, hash::MessageDigest::sha256())?;
    let cert_bytes = cert.build().to_pem()?;
    Ok(cert_bytes)
}

fn generate_rsa_private_key(passphrase: Option<String>) -> SslData {
    let rsa = Rsa::generate(2048).unwrap();
    let passphrase = passphrase.unwrap_or("shevy".to_string());
    let buffer = rsa
        .private_key_to_pem_passphrase(Cipher::des_ede3_cbc(), passphrase.as_bytes())
        .unwrap();
    let cert = match generate_certificate(&buffer, passphrase.as_bytes()) {
        Ok(cert_bytes) => String::from_utf8(cert_bytes).unwrap(),
        Err(_) => String::default()
    };
    let private_key = match String::from_utf8(buffer.clone()) {
        Ok(v) => v,
        Err(_) => String::default(),
    };
    SslData { private_key, cert }
}

fn write_to_file(filename: &String, data: &str) -> io::Result<()> {
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

#[cfg(target_os = "macos")]
fn add_certificate(filename: String) -> process::Output {
    let command = "sudo security add-trusted-cert -d -k /Library/Keychains/System.keychain";
    let command = format!("{} $(echo \"$(pwd)/out/{}\")", command, filename);
    process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .output()
            .expect("failed to execute process")
}

#[cfg(target_os = "linux")]
fn add_certificate() {
    std::todo!();
}

#[cfg(target_os = "windows")]
fn add_certificate() {
    std::todo!();
}

fn main() {
    let filename = read!("Enter file basename", String);
    let passphrase = read!("Enter a Passphrase", String);
    let ssl_data = generate_rsa_private_key(Some(passphrase));
    match write_to_file(&format!("{}{}", filename, ".key"), &ssl_data.private_key) {
        Ok(_) => println!("Private Key: {}", ssl_data.private_key),
        Err(err) => {
            println!("Writing Private Key Failed: {:?}", err);
        }
    }
    let certificate_filename = {
        let _filename = format!("{}{}", filename, ".cert.pem");
        match write_to_file(&_filename, &ssl_data.cert) {
            Ok(_) => _filename,
            Err(err) => {
                println!("Writing Certificate Failed: {:?}", err);
                String::default()
            }
        }
    };

    if !certificate_filename.is_empty() && add_certificate(certificate_filename).status.success() {
        println!("Successfully Added Certificate to Keychain");
    }
}
