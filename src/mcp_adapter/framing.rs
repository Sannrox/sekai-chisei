use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum accepted MCP frame, including JSON-RPC envelope.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Read one newline-delimited JSON-RPC message (MCP stdio).
pub async fn read_frame<R>(reader: &mut R) -> Result<serde_json::Value, String>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let read = reader
            .read(&mut byte)
            .await
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return if buf.is_empty() {
                Err("eof".into())
            } else {
                Err("unterminated mcp frame".into())
            };
        }
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] == b'\r' {
            continue;
        }
        if buf.len() >= MAX_FRAME_BYTES {
            return Err("mcp frame exceeds size limit".into());
        }
        buf.push(byte[0]);
    }
    if buf.is_empty() {
        return Err("mcp frame is empty".into());
    }
    serde_json::from_slice(&buf).map_err(|error| format!("mcp frame is not JSON: {error}"))
}

/// Write one newline-delimited JSON-RPC message (MCP stdio).
pub async fn write_frame<W>(writer: &mut W, value: &serde_json::Value) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    let body = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    if body.len() > MAX_FRAME_BYTES || body.contains(&b'\n') {
        return Err("mcp frame exceeds size limit".into());
    }
    writer
        .write_all(&body)
        .await
        .map_err(|error| error.to_string())?;
    writer
        .write_all(b"\n")
        .await
        .map_err(|error| error.to_string())?;
    writer.flush().await.map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn newline_delimited_json_round_trips() {
        let mut sink = Vec::new();
        write_frame(&mut sink, &json!({"jsonrpc":"2.0","id":1}))
            .await
            .unwrap();
        assert!(sink.ends_with(b"\n"));
        assert!(!sink.starts_with(b"Content-Length"));
        let value = read_frame(&mut sink.as_slice()).await.unwrap();
        assert_eq!(value["id"], 1);
    }

    #[tokio::test]
    async fn oversized_unterminated_frames_fail_closed() {
        let oversize = vec![b'x'; MAX_FRAME_BYTES + 8];
        let error = read_frame(&mut oversize.as_slice()).await.unwrap_err();
        assert!(error.contains("size limit"));
    }
}
