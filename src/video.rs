use shuttle_runtime::tokio::fs;
use shuttle_runtime::tokio::fs::{File, OpenOptions};
use shuttle_runtime::tokio::io::AsyncWriteExt;

/// returns a list of all the saved mp4 files in security-cam-viewer/assets
pub async fn get_video_paths() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir("assets")? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().unwrap() == "mp4" {
            paths.push(path.to_str().unwrap().to_string());
        }
    }
    Ok(paths)
}

pub async fn append_chunk_to_file(chunk: &[u8],file_handle: &mut File) -> Result<(), Box<dyn std::error::Error>> {
    file_handle.write_all(chunk).await?;
    Ok(())
}

#[deprecated]
pub async fn make_new_video_file() -> Result<File, Box<dyn std::error::Error>> {
    let path = format!("assets/video-{}.mp4",chrono::Local::now());
    let file = OpenOptions::new().read(true).write(true).create(true).append(true).open(path).await?;
    Ok(file)
}

pub fn get_next_video_path() -> String {
    format!("assets/video-{}.mp4",chrono::Local::now())
}

pub async fn delete_video_file(filepath: &String) -> Result<(), Box<dyn std::error::Error>> {
    fs::remove_file(filepath).await?;
    Ok(())
}

/// validates that the data is a valid video file
pub fn validate_magic_string(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let magic_strings = [b"ftypisom", b"ftypMSNV",b"ftypmp42"];
    if data.len() < 12 {
        return Err("Invalid video".into());
    }
    for magic in &magic_strings {
        if &data[4..12] == *magic {
            return Ok(());
        }
    }
    Err("Invalid video".into())
}

#[cfg(test)]
mod tests {
    use shuttle_runtime::tokio;
    use shuttle_runtime::tokio::fs::OpenOptions;
    use super::*;
    use tokio::io::AsyncReadExt;
    #[tokio::test]
    async fn test_save_video() -> Result<(), Box<dyn std::error::Error>> {
        tokio::fs::remove_file("test.mp4").await;

        let mut file = File::options().read(true).open("test-unencrypted.mp4").await?;
        eprintln!("got here");
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).await?;
        let mut file_handle = OpenOptions::new().read(true).write(true).create(true).append(true).open("test.mp4").await?;
        for chunk in buffer.chunks(50) {
            append_chunk_to_file(chunk, &mut file_handle).await?;
        }

        let mut new_buffer = Vec::new();
        File::open("test.mp4").await?.read_to_end(&mut new_buffer).await?;
        assert_eq!(buffer.len(),new_buffer.len());
        for (byte, expected_byte) in new_buffer.iter().zip(buffer) {
            assert_eq!(*byte,expected_byte);
        }
        Ok(())
    }
    #[tokio::test]
    async fn test_validate_magic_string() -> Result<(), Box<dyn std::error::Error>> {
        let mut file = File::open("test-unencrypted.mp4").await?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).await?;
        assert!(validate_magic_string(&buffer).is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_get_video_paths() {
        tokio::fs::remove_file("assets/test.mp4").await;
        tokio::fs::remove_file("assets/test.notmp4").await;
        tokio::fs::File::create("assets/test.mp4").await.unwrap();

        let vid_paths = get_video_paths().await.expect("getvideopaths failed");
        assert!(vid_paths.contains(&"assets/test.mp4".to_string()));
        assert!(!vid_paths.contains(&"assets/test.notmp4".to_string()));

    }
}
