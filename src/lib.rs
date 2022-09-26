use crate::generator::CharacterSet;
use anyhow::anyhow;
use directories::ProjectDirs;
use std::{io::Write, path::Path};
use uuid::Uuid;

pub static MASTER_JSON_NAME: &str = "master.json";
pub static CHARSET_JSON_NAME: &str = "charset.json";

pub mod encryption;
pub mod generator;
pub mod manager;

pub fn get_data_path() -> Result<String, anyhow::Error> {
    if let Some(proj_dirs) = ProjectDirs::from("com", "pwd", "pwd_m") {
        let local_data_path = proj_dirs.data_local_dir();

        if !local_data_path.exists() {
            std::fs::create_dir_all(local_data_path)?;

            return Ok(local_data_path.to_str().unwrap().to_owned());
        }

        return Ok(local_data_path.to_str().unwrap().to_owned());
    }

    Err(anyhow!("Could not create local data path."))
}

pub fn get_master_json_path() -> Result<String, anyhow::Error> {
    let local_data_path = get_data_path()?;
    let local_data_path = Path::new(&local_data_path);

    let json_path = local_data_path.join(MASTER_JSON_NAME);

    Ok(json_path.to_str().unwrap().to_owned())
}

pub fn get_password_data_path(id: &Uuid) -> Result<String, anyhow::Error> {
    let local_data_path = get_data_path()?;
    let local_data_path = Path::new(&local_data_path);

    let json_path = local_data_path.join(id.to_string());

    Ok(json_path.to_str().unwrap().to_owned())
}

pub fn get_charset_path() -> Result<String, anyhow::Error> {
    let local_data_path = get_data_path()?;
    let local_data_path = Path::new(&local_data_path);

    let json_path = local_data_path.join(CHARSET_JSON_NAME);

    Ok(json_path.to_str().unwrap().to_owned())
}

pub fn load_charset() -> Result<CharacterSet, anyhow::Error> {
    let charset_path = get_charset_path()?;

    if !Path::new(&charset_path).exists() {
        let default = generate_default_charset()?;
        return Ok(default);
    }

    let json = std::fs::read_to_string(charset_path)?;

    let charset = serde_json::from_str(&json)?;

    Ok(charset)
}

pub fn generate_default_charset() -> Result<CharacterSet, anyhow::Error> {
    let charset = CharacterSet::new(
        "abcdefghijklmnopqrstuvw1234567890",
        "ABCDEFGHIJKLMNOPQRSTUVW",
        "!\"§$%&/()=?`.,;:_/*-+#*",
    );
    let json = serde_json::to_string(&charset)?;

    let mut file = std::fs::File::create(get_charset_path()?)?;
    file.write_all(json.as_bytes())?;

    Ok(charset)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::generate_default_charset;
    use crate::generator::CharacterSet;
    use crate::get_charset_path;
    use crate::get_data_path;
    use crate::get_master_json_path;
    use crate::get_password_data_path;
    use crate::load_charset;
    use crate::CHARSET_JSON_NAME;

    #[test]
    fn test_get_data_path() {
        let data_path = get_data_path().expect("Local data path could not be created.");

        assert!(Path::new(&data_path).exists());
    }

    #[test]
    fn test_get_master_json_path() {
        get_master_json_path().expect("Master json path could not be created.");

        assert!(true);
    }

    #[test]
    fn test_get_password_data_path() {
        let data_path = get_data_path().expect("Local data path could not be created.");
        let uuid = uuid::Uuid::new_v4();

        assert_eq!(
            Path::new(&data_path)
                .join(uuid.to_string())
                .to_str()
                .unwrap(),
            get_password_data_path(&uuid).expect("Password path could not be created.")
        )
    }

    #[test]
    fn test_get_charset_path() {
        let data_path = get_data_path().expect("Local data path could not be created.");

        assert_eq!(
            Path::new(&data_path)
                .join(CHARSET_JSON_NAME)
                .to_str()
                .unwrap(),
            get_charset_path().expect("Password path could not be created.")
        )
    }

    #[test]
    fn test_generate_default_charset() {
        let default = CharacterSet::new(
            "abcdefghijklmnopqrstuvw1234567890",
            "ABCDEFGHIJKLMNOPQRSTUVW",
            "!\"§$%&/()=?`.,;:_/*-+#*",
        );
        let generated = generate_default_charset().unwrap();

        assert_eq!(default, generated);
    }

    #[test]
    fn test_load_charset() {
        let default = generate_default_charset().unwrap();
        let loaded = load_charset().expect("Charset not found.");

        assert_eq!(default, loaded);
    }
}
