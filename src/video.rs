use tokio::fs::File;
use tokio::io::AsyncWriteExt;

pub async fn save_video(data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    validate_magic_string(data)?;
    let path = format!("assets/video-{}",chrono::Local::now());
    let mut file = File::create(&path).await?;
    file.write_all(data).await?;
    Ok(path)
}

fn validate_magic_string(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let magic_strings = [b"ftypisom", b"ftypMSNV"];
    if data.len() < 12 {
        return Err("Invalid video".into());
    }
    for magic in &magic_strings {
        if &data[4..12] == *magic {
            return Ok(());
        }
    }
    return Err("Invalid video".into());
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    #[tokio::test]
    async fn test_validate_magic_string() -> Result<(), Box<dyn std::error::Error>> {
        let mut file = File::open("assets/test-2023-11-21_17.58.46.mp4").await?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).await?;
        assert!(validate_magic_string(&buffer).is_ok());
        Ok(())
    }
    #[tokio::test]
    async fn test_save_video() -> Result<(), Box<dyn std::error::Error>> {
        let mut file = File::open("assets/test-2023-11-21_17.58.46.mp4").await?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).await?;

        let path = save_video(&buffer).await;
        assert!(&path.is_ok());
        let mut file = File::open(path.as_ref().unwrap()).await?;
        let mut new_buffer = Vec::new();
        file.read_to_end(&mut new_buffer).await?;
        assert_eq!(buffer, new_buffer);
        tokio::fs::remove_file(&path.unwrap()).await?;
        Ok(())
    }
}
