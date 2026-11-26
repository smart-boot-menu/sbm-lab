use crate::error::{Error, Result};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Accepts one TCP connection, delays, then records the bytes.
/// Used as a QEMU socket netdev peer for the slow-network fault.
pub struct DelayProxy {
    pub addr: String,
    log: Arc<Mutex<Vec<u8>>>,
}

impl DelayProxy {
    pub fn start(delay: Duration) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?.to_string();
        let log = Arc::new(Mutex::new(Vec::new()));
        let log_thread = Arc::clone(&log);
        thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buf = [0u8; 2048];
            if let Ok(n) = stream.read(&mut buf) {
                thread::sleep(delay);
                if let Ok(mut guard) = log_thread.lock() {
                    guard.extend_from_slice(&buf[..n]);
                }
                let _ = stream.write_all(&buf[..n]);
            }
        });
        Ok(Self { addr, log })
    }

    pub fn received(&self) -> Vec<u8> {
        self.log.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

pub fn ppm_has_variance(bytes: &[u8]) -> Result<bool> {
    if !bytes.starts_with(b"P6") {
        return Err(Error::message("screenshot is not a P6 PPM"));
    }
    let header_end = bytes
        .windows(2)
        .position(|w| w == b"\n\n")
        .or_else(|| find_third_newline(bytes).ok())
        .ok_or_else(|| Error::message("ppm header is truncated"))?;
    let pixels = &bytes[header_end + 1..];
    if pixels.len() < 6 {
        return Ok(false);
    }
    let first = &pixels[0..3];
    let last = &pixels[pixels.len() - 3..];
    let black = [0, 0, 0];
    let varied = first != last || pixels.chunks(3).take(64).any(|px| px != first);
    let painted = first != black || last != black;
    Ok(varied || painted)
}

fn find_third_newline(bytes: &[u8]) -> Result<usize> {
    let mut seen = 0;
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'\n' {
            seen += 1;
            if seen == 3 {
                return Ok(i);
            }
        }
    }
    Err(Error::message("ppm header is truncated"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;
    use std::time::Instant;

    #[test]
    fn delay_proxy_holds_bytes() {
        let proxy = DelayProxy::start(Duration::from_millis(40)).unwrap();
        let start = Instant::now();
        let mut stream = TcpStream::connect(&proxy.addr).unwrap();
        stream.write_all(b"abc").unwrap();
        let _ = stream.flush();
        for _ in 0..50 {
            if proxy.received() == b"abc" {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(proxy.received(), b"abc");
        assert!(start.elapsed() >= Duration::from_millis(30));
    }

    #[test]
    fn ppm_variance_detects_a_colored_pixel() {
        let mut ppm = b"P6\n2 1\n255\n".to_vec();
        ppm.extend_from_slice(&[0, 0, 0, 10, 20, 30]);
        assert!(ppm_has_variance(&ppm).unwrap());
        let mut blank = b"P6\n2 1\n255\n".to_vec();
        blank.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        assert!(!ppm_has_variance(&blank).unwrap());
        let mut solid = b"P6\n2 1\n255\n".to_vec();
        solid.extend_from_slice(&[0x14, b'Z', 0xdc, 0x14, b'Z', 0xdc]);
        assert!(ppm_has_variance(&solid).unwrap());
    }
}
