use crate::error::{Error, Result};
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

pub struct Qmp {
    stream: UnixStream,
}

impl Qmp {
    pub fn connect(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut qmp = Self { stream };
        let _greeting = qmp.read_message()?;
        qmp.execute("qmp_capabilities", None)?;
        Ok(qmp)
    }

    pub fn execute(&mut self, command: &str, arguments: Option<Value>) -> Result<Value> {
        let mut message = json!({ "execute": command });
        if let Some(arguments) = arguments {
            message["arguments"] = arguments;
        }
        serde_json::to_writer(&mut self.stream, &message)?;
        self.stream.write_all(b"\n")?;
        self.stream.flush()?;
        loop {
            let value = self.read_message()?;
            if value.get("return").is_some() || value.get("error").is_some() {
                if value.get("error").is_some() {
                    return Err(Error::message(format!("qmp {command}: {value}")));
                }
                return Ok(value);
            }
        }
    }

    pub fn screendump(&mut self, path: &Path) -> Result<()> {
        self.execute(
            "screendump",
            Some(json!({
                "filename": path,
                "format": "ppm"
            })),
        )?;
        Ok(())
    }

    pub fn send_key(&mut self, qcode: &str) -> Result<()> {
        self.execute(
            "send-key",
            Some(json!({
                "keys": [{ "type": "qcode", "data": qcode }]
            })),
        )?;
        Ok(())
    }

    pub fn set_link(&mut self, name: &str, up: bool) -> Result<()> {
        self.execute("set_link", Some(json!({ "name": name, "up": up })))?;
        Ok(())
    }

    pub fn quit(&mut self) -> Result<()> {
        self.execute("quit", None)?;
        Ok(())
    }

    pub fn system_reset(&mut self) -> Result<()> {
        self.execute("system_reset", None)?;
        Ok(())
    }

    fn read_message(&mut self) -> Result<Value> {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match self.stream.read(&mut byte) {
                Ok(0) => {
                    return Err(Error::message(format!(
                        "qmp closed: {}",
                        String::from_utf8_lossy(&buf)
                    )));
                }
                Ok(_) => {
                    if byte[0] == b'\n' {
                        break;
                    }
                    buf.push(byte[0]);
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    return Err(Error::message("qmp read timed out"));
                }
                Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {
                    return Err(Error::message("qmp read timed out"));
                }
                Err(err) => return Err(err.into()),
            }
        }
        Ok(serde_json::from_slice(&buf)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::thread;

    #[test]
    fn client_negotiates_and_skips_events() {
        let dir = crate::util::test_scratch("qmp");
        let path = dir.join("qmp.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;
            writeln!(
                writer,
                r#"{{"QMP": {{"version": {{"qemu": {{"major": 11, "minor": 1, "micro": 3}}}}, "capabilities": []}}}}"#
            )
            .unwrap();
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            writeln!(writer, r#"{{"return": {{}}}}"#).unwrap();
            line.clear();
            reader.read_line(&mut line).unwrap();
            writeln!(
                writer,
                r#"{{"event": "STOP", "data": {{}}, "timestamp": {{"seconds": 0, "microseconds": 0}}}}"#
            )
            .unwrap();
            writeln!(writer, r#"{{"return": {{"status": "running"}}}}"#).unwrap();
        });
        let mut qmp = Qmp::connect(&path).unwrap();
        let status = qmp.execute("query-status", None).unwrap();
        assert_eq!(status["return"]["status"], "running");
        server.join().unwrap();
    }
}
