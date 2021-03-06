#![forbid(deprecated, unsafe_code)]

pub use base64;
pub const DFL_DHC: yz_glue_dhchoice::DHChoice = yz_glue_dhchoice::DHChoice::Ed25519;

pub fn get_private_key(inp: Option<&str>) -> yz_encsess::SecretKey {
    yz_encsess::new_key(match inp {
        None => {
            let kp = yz_encsess::generate_keypair(DFL_DHC).expect("unable to generate keypair");
            println!("generated keypair:");
            let mut tmp = base64::encode(&kp.private);
            println!("\tprivkey = \"{}\"", tmp);
            tmp.clear();
            base64::encode_config_buf(&kp.public, base64::STANDARD, &mut tmp);
            println!("\tpubkey  = \"{}\"", tmp);
            kp.private
        }
        Some(x) => base64::decode(x).expect("got invalid private key"),
    })
}
