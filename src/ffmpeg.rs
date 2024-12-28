use std::fs;
use std::io::Result;
use std::process::Command;

use chrono::{Local, NaiveDateTime};

/// executes ffmpeg -r 5 -f image2 -s 720x480 -start_number 0 -i video_num.%d.jpg -vframes frame_num -vcodec libx264 -crf 25  -pix_fmt yuv420p video_num.mp4
/// then deletes all the unneeded jpg files
pub fn execute_ffmpeg(video_num: usize, frame_num: u64, fps: usize) -> Result<String> {
    let input = format!("video_frames/{}.{}.jpg", video_num, "%d");
    let output = format!("assets/{}.{}.unencrypted.mp4", Local::now(), video_num);

    Command::new("ffmpeg")
        .arg("-r")
        .arg(fps.to_string())
        .arg("-f")
        .arg("image2")
        .arg("-s")
        .arg("720x480")
        .arg("-start_number")
        .arg("0")
        .arg("-i")
        .arg(&input)
        .arg("-vframes")
        .arg(frame_num.to_string())
        .arg("-vcodec")
        .arg("libx264")
        .arg("-crf")
        .arg("25")
        .arg("-pix_fmt")
        .arg("yuv420p")
        .arg(&output)
        .status()?;

    // Remove the .jpg files
    for i in 0.. {
        let file_name = format!("video_frames/{}.{}.jpg", video_num, i);
        match fs::remove_file(&file_name) {
            Ok(_) => (),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    break; // No more files to delete
                } else {
                    return Err(e); // Propagate the error
                }
            }
        }
    }

    Ok(output)
}
