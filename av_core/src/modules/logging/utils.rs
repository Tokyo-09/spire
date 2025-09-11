use users::{get_current_uid, get_user_by_uid};
use windows::{Win32::System::WindowsProgramming::GetUserNameW, core::PWSTR};

pub fn get_logged_in_username() -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        let mut buffer: [u16; 256] = [0; 256];
        let mut size = buffer.len() as u32;

        let result = unsafe { GetUserNameW(Some(PWSTR(buffer.as_mut_ptr())), &mut size) };

        if let Err(e) = result {
            return Err(format!("Error getting UserName: {e}"));
        }

        Ok(String::from_utf16_lossy(&buffer[..size as usize - 1]))
    }

    #[cfg(target_os = "linux")]
    {
        let uid = get_current_uid();
        if let Some(user) = get_user_by_uid(uid) {
            println!("Logged‑in user: {}", user.name().to_string_lossy());
        } else {
            eprintln!("No user entry found for UID {}", uid);
        }
    }
}
