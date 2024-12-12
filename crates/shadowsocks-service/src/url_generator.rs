use base64::Engine;
use std::fmt::Write;
use shadowsocks::config::URL_PASSWORD_BASE64_ENGINE;
use shadowsocks::{ServerAddr, ServerConfig};

#[derive(Debug)]
pub enum SsUrlError {
    Base64Error(base64::DecodeError),
    EncodingError(std::string::FromUtf8Error),
    UrlGenerationError(String)
}

impl std::fmt::Display for SsUrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SsUrlError::Base64Error(e) => write!(f, "Base64 encoding error: {}", e),
            SsUrlError::EncodingError(e) => write!(f, "UTF-8 encoding error: {}", e),
            SsUrlError::UrlGenerationError(e) => write!(f, "URL generation error: {}", e)
        }
    }
}

impl std::error::Error for SsUrlError {}

/// Generate an SS URL from server configuration components
pub fn generate_ssurl(
    server_address: &str,
    server_port: u16,
    method: &str,
    password: &str,
    name: Option<&str>
) -> Result<String, SsUrlError> {
    // Non 2022 cypher
    let encoded_user_info =  if !method.contains("2022") {
        let user_info = format!("{}:{}", method, password);
        URL_PASSWORD_BASE64_ENGINE.encode(user_info)
    } else {
        format!("{}:{}", method, percent_encoding::utf8_percent_encode(password, percent_encoding::NON_ALPHANUMERIC))
    };

    // Build the base SS URL
    let mut ss_url = format!(
        "ss://{}@{}:{}",
        encoded_user_info,
        server_address,
        server_port
    );

    // Add the name as a fragment if provided
    if let Some(name) = name {
        // URL encode the name
        let encoded_name = urlencoding::encode(name);
        write!(ss_url, "#{}", encoded_name)
            .map_err(|e| SsUrlError::UrlGenerationError(e.to_string()))?;
    }

    Ok(ss_url)
}

pub fn generate_ssurl_from_config(config: &ServerConfig, name: Option<&str>) -> Result<String, SsUrlError> {
    let (address, port) = match config.addr() {
        ServerAddr::SocketAddr(addr) => (addr.ip().to_string(), addr.port()),
        ServerAddr::DomainName(domain, port) => (domain.to_string(), *port),
    };

    generate_ssurl(
        &address,
        port,
        &config.method().to_string(),
        config.password(),
        name
    )
}


#[cfg(test)]
mod tests {
    use crate::config::{Config, ConfigType};
    use super::*;

    #[test]
    fn test_generate_ssurl() {
        let url = generate_ssurl(
            "127.0.0.1",
            8387,
            "2022-blake3-aes-256-gcm",
            "0X7im12oWeEc1kpA6JKS9ATf4SNZl/cObLgicta1T+o=",
            Some("My Server")
        ).unwrap();

        println!("{url}");

        assert!(url.starts_with("ss://"));
        assert!(url.contains("@127.0.0.1:8387"));
        assert!(url.contains("#My%20Server"));
    }

    #[test]
    fn test_generate_url() {
        let config_str = r#"
            {
            "server": "127.0.0.1",
            "server_port": 8387,
            "ipv6_first": false,
            "ipv6_only": false,
            "mode": "tcp_and_udp",
            "password": "xXsEZIlaGPEtkuDZ4ZKM2lcFqtY74WcuUeLo+1384Gc=:0X7im12oWeEc1kpA6JKS9ATf4SNZl/cObLgicta1T+o=",
            "method": "2022-blake3-aes-256-gcm",
            "timeout": 300,
            "udp_timeout": 300,
            "udp_max_associations": 512,
            "nameserver": "1.1.1.1",
            "local_address": "127.0.0.1",
            "local_port": 1080,
            "outbound_bind_interface": "en0",
            "old_tun_interface_name": "utun123",
            "tun_interface_address": "10.255.0.1/24"
            }
        "#;

        let config = Config::load_from_str(config_str, ConfigType::Server).unwrap();

        for svr in config.server {
            let encoded = svr.config.to_url();

            println!("{encoded}");
        }
    }
}
