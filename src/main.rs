use dialoguer::{theme::ColorfulTheme, Input, Password};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

#[derive(Debug, Default, Serialize, Deserialize)]
struct Config {
    username: String,
    hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Item {
    host: String,
    address: String,
    url: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Afraid {
    item: Vec<Item>,
}

const SLEEP_MINUTES: u64 = 5;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut ip = get_ip()?;
    twink::info!("Your IP is: {}", ip);

    if !confy::get_configuration_file_path("afraid", "afraid")?.exists() {
        let username = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Username")
            .interact_text()?;
        let password = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Password")
            .interact()?;
        let secret = format!("{username}|{password}");
        let mut hasher = Sha1::new();
        hasher.update(secret.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        confy::store("afraid", "afraid", Config { username, hash })?;
    }

    let cfg = confy::load::<Config>("afraid", "afraid")?;
    twink::info!("Logged in as: {}", cfg.username);

    let api = format!(
        "https://freedns.afraid.org/api/?action=getdyndns&v=2&sha={}&style=xml",
        cfg.hash
    );

    twink::info!("Found domains:-");
    for domain in get_domains(&api)? {
        twink::info!("{} | {}", domain.host, domain.address);
    }

    loop {
        ip = update_ip(&ip)?;
        for domain in get_domains(&api)? {
            if ip != domain.address {
                twink::info!("Updating {}: {} -> {}", domain.host, domain.address, ip);
                let res = ureq::get(&domain.url).call()?.into_string()?;
                twink::info!("{res}");
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(SLEEP_MINUTES * 60));
    }
}

fn get_ip() -> Result<String, Box<dyn std::error::Error>> {
    Ok(ureq::get("http://ipinfo.io/ip").call()?.into_string()?)
}

fn update_ip(old_ip: &str) -> Result<String, Box<dyn std::error::Error>> {
    let new_ip = ureq::get("http://ipinfo.io/ip").call()?.into_string()?;
    if old_ip != new_ip {
        twink::info!("IP changed: {old_ip} -> {new_ip}, updating domains...");
    }
    Ok(new_ip)
}

fn get_domains(api: &str) -> Result<Vec<Item>, Box<dyn std::error::Error>> {
    let xml = ureq::get(api).call()?.into_string()?;
    Ok(serde_xml_rs::from_str::<Afraid>(&xml)?.item)
}
