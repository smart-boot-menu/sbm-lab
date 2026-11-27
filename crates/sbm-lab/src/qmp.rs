use crate::error::{Error, Result};
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread;
use std::time::Duration;

pub struct Qmp {
    stream: UnixStream,
    events: Vec<Value>,
}

impl Qmp {
    pub fn connect(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut qmp = Self {
            stream,
            events: Vec::new(),
        };
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
            if value.get("event").is_some() {
                self.events.push(value);
                continue;
            }
            if value.get("return").is_some() || value.get("error").is_some() {
                if value.get("error").is_some() {
                    return Err(Error::message(format!("qmp {command}: {value}")));
                }
                return Ok(value);
            }
        }
    }

    /// Poll for any queued asynchronous QMP events (such as `RESET`) without
    /// blocking for long.
    pub fn poll_events(&mut self) -> Vec<Value> {
        let prev = self.stream.read_timeout().ok().flatten();
        let _ = self
            .stream
            .set_read_timeout(Some(Duration::from_millis(50)));
        while let Ok(value) = self.read_message() {
            if value.get("event").is_some() {
                self.events.push(value);
            }
        }
        let _ = self.stream.set_read_timeout(prev);
        self.events.clone()
    }

    pub fn has_event(&mut self, name: &str) -> bool {
        self.poll_events()
            .iter()
            .any(|ev| ev.get("event").and_then(|v| v.as_str()) == Some(name))
    }

    pub fn events(&self) -> &[Value] {
        &self.events
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
        self.send_keys(&[qcode])
    }

    pub fn send_keys(&mut self, qcodes: &[&str]) -> Result<()> {
        let keys: Vec<Value> = qcodes
            .iter()
            .map(|code| json!({ "type": "qcode", "data": code }))
            .collect();
        self.execute("send-key", Some(json!({ "keys": keys })))?;
        Ok(())
    }

    /// Move the absolute USB tablet pointer to `(x, y)` in a `width x height`
    /// framebuffer and click the left button.
    pub fn click_abs(&mut self, x: u32, y: u32, width: u32, height: u32) -> Result<()> {
        let ax = ((x as u64).saturating_mul(32767) / (width.max(1) as u64)).min(32767);
        let ay = ((y as u64).saturating_mul(32767) / (height.max(1) as u64)).min(32767);
        self.execute(
            "input-send-event",
            Some(json!({
                "events": [
                    { "type": "abs", "data": { "axis": "x", "value": ax } },
                    { "type": "abs", "data": { "axis": "y", "value": ay } }
                ]
            })),
        )?;
        thread::sleep(Duration::from_millis(120));
        self.execute(
            "input-send-event",
            Some(json!({
                "events": [
                    { "type": "btn", "data": { "down": true, "button": "left" } }
                ]
            })),
        )?;
        thread::sleep(Duration::from_millis(90));
        self.execute(
            "input-send-event",
            Some(json!({
                "events": [
                    { "type": "btn", "data": { "down": false, "button": "left" } }
                ]
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
    fn client_negotiates_and_records_events() {
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
                r#"{{"event": "RESET", "data": {{"guest": true}}, "timestamp": {{"seconds": 1, "microseconds": 0}}}}"#
            )
            .unwrap();
            writeln!(writer, r#"{{"return": {{"status": "running"}}}}"#).unwrap();
        });
        let mut qmp = Qmp::connect(&path).unwrap();
        let status = qmp.execute("query-status", None).unwrap();
        assert_eq!(status["return"]["status"], "running");
        assert!(qmp.has_event("RESET"));
        server.join().unwrap();
    }
}
