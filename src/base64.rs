use anyhow::Error;
use base64::{Engine, prelude::BASE64_STANDARD};
use num::traits::FromBytes;
use num_bigint::BigUint;
use std::fs;

struct SSHKeyReader {}

impl SSHKeyReader {
    fn parse_pubkey<'a>(&self, bytes: &'a [u8]) -> Vec<&'a [u8]> {
        let mut result = Vec::new();
        let n = bytes.len();
        let mut idx = 0;
        while idx < bytes.len() {
            let l = u32::from_be_bytes(bytes[idx..(idx + 4)].try_into().unwrap()) as usize;
            idx += 4;
            let item: &[u8] = &bytes[idx..(idx + l)];
            result.push(item);
            idx += l;
        }

        result
    }

    fn read_pubkey(&self, fname: &str) -> Result<BigUint, Error> {
        let s = fs::read_to_string(fname)?;

        let bytes = BASE64_STANDARD.decode(s)?;

        let res = self.parse_pubkey(&bytes);
        assert!(res.len() == 3); // OpenSSH RSA pubkeys have three items
        let n = BigUint::from_be_bytes(res[2]);

        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::SSHKeyReader;

    #[test]
    fn read_file_works() {
        let sshkr = SSHKeyReader {};
        let n = sshkr.read_pubkey("keys/tgpub").unwrap();
        println!("n = {}", n);
    }
}
