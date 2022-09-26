use crate::encryption::Chacha20poly1305Provider;
use crate::encryption::CryptoProvider;
use crate::get_master_json_path;
use crate::get_password_data_path;
use chrono::prelude::*;
use secstr::SecStr;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::Display;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone)]
pub struct PasswordProfile {
    id: Uuid,
    name: String,
    website: Option<String>,
    username: Option<String>,
    create_date: DateTime<Utc>,
    modify_date: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize)]
pub struct PasswordManager {
    profiles: Vec<PasswordProfile>,
    #[serde(skip)]
    master_pwd: Option<SecStr>,
}

#[derive(Debug)]
pub enum ManagerError {
    PasswordFileNotFound,
    ProfileNotFound,
    Unknown(String),
}

impl Display for ManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PasswordFileNotFound => write!(f, "The password file could not be found!"),
            Self::ProfileNotFound => write!(f, "The profile could not be found!"),
            Self::Unknown(err) => {
                write!(f, "Manager operation yielded the following error {}!", err)
            }
        }
    }
}

impl std::error::Error for ManagerError {}

impl Drop for PasswordManager {
    fn drop(&mut self) {
        if let Some(pwd) = self.master_pwd.as_mut() {
            pwd.zero_out();
        }
    }
}

impl PasswordProfile {
    pub fn new(id: Uuid, name: &str, create_date: DateTime<Utc>) -> Self {
        PasswordProfile {
            id,
            name: String::from(name),
            website: None,
            username: None,
            create_date,
            modify_date: None,
        }
    }

    pub fn set_name(&mut self, name: &str) {
        self.name = String::from(name);
    }

    pub fn set_website(&mut self, website: &str) {
        self.website = Some(String::from(website));
    }

    pub fn set_username(&mut self, username: &str) {
        self.username = Some(String::from(username));
    }

    pub fn set_modify_date(&mut self, modify_date: DateTime<Utc>) {
        self.modify_date = Some(modify_date);
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn website(&self) -> Option<String> {
        self.website.clone()
    }

    pub fn username(&self) -> Option<String> {
        self.username.clone()
    }

    pub fn modify_date(&self) -> Option<DateTime<Utc>> {
        self.modify_date
    }

    pub fn create_date(&self) -> DateTime<Utc> {
        self.create_date
    }
}

impl PasswordManager {
    pub fn new() -> Self {
        PasswordManager {
            profiles: Vec::new(),
            master_pwd: None,
        }
    }

    pub fn set_master_pwd(&mut self, master_pwd: SecStr) {
        self.master_pwd = Some(master_pwd);
    }

    pub fn unset_master_pwd(&mut self) {
        if let Some(pwd) = self.master_pwd.as_mut() {
            pwd.zero_out();
        }
    }

    pub fn add_profile(
        &mut self,
        profile: PasswordProfile,
        profile_password: SecStr,
    ) -> Result<(), anyhow::Error> {
        let mut pwd_file = File::create(get_password_data_path(&profile.id)?)?;
        let crypto_provider = Chacha20poly1305Provider;

        let mut encrypted_password =
            crypto_provider.encrypt_string(profile_password, self.master_pwd.as_ref().unwrap())?;
        pwd_file.write_all(encrypted_password.unsecure())?;
        encrypted_password.zero_out();

        self.profiles.push(profile);

        self.save(&get_master_json_path()?)?;

        Ok(())
    }

    pub fn update_profile(
        &mut self,
        old_profile_name: &str,
        new_profile: PasswordProfile,
        new_password: Option<SecStr>,
    ) -> Result<(), ManagerError> {
        let old_profile = match self.get_profile_by_name(old_profile_name) {
            Some(p) => p,
            None => return Err(ManagerError::ProfileNotFound),
        };

        if let Some(pwd) = new_password {
            let data_path = match get_password_data_path(&old_profile.id) {
                Ok(path) => path,
                Err(err) => return Err(ManagerError::Unknown(err.to_string())),
            };

            if Path::new(&data_path).exists() {
                match std::fs::remove_file(&data_path) {
                    Ok(_) => (),
                    Err(err) => return Err(ManagerError::Unknown(err.kind().to_string())),
                };
            }

            let mut pwd_file = match File::create(&data_path) {
                Ok(f) => f,
                Err(err) => return Err(ManagerError::Unknown(err.kind().to_string())),
            };

            let crypto_provider = Chacha20poly1305Provider;

            let mut encrypted_password =
                match crypto_provider.encrypt_string(pwd, self.master_pwd.as_ref().unwrap()) {
                    Ok(e) => e,
                    Err(err) => return Err(ManagerError::Unknown(err.to_string())),
                };

            match pwd_file.write_all(encrypted_password.unsecure()) {
                Ok(_) => (),
                Err(err) => return Err(ManagerError::Unknown(err.kind().to_string())),
            };

            encrypted_password.zero_out();
        }

        for i in 0..self.profiles.len() {
            if self.profiles[i].name == old_profile_name {
                self.profiles[i] = new_profile;
                break;
            }
        }

        let file_path = match get_master_json_path() {
            Ok(path) => path,
            Err(err) => return Err(ManagerError::Unknown(err.to_string())),
        };

        match self.save(&file_path) {
            Ok(_) => Ok(()),
            Err(err) => return Err(ManagerError::Unknown(err.to_string())),
        }
    }

    pub fn get_password_for_profile(
        &self,
        profile_name: &str,
    ) -> Result<Option<SecStr>, ManagerError> {
        let profile = match self.get_profile_by_name(profile_name) {
            Some(p) => p,
            None => return Ok(None),
        };

        match get_password_data_path(&profile.id) {
            Ok(data_path) => {
                if !Path::new(&data_path).exists() {
                    return Err(ManagerError::PasswordFileNotFound);
                }

                let crypto_provider = Chacha20poly1305Provider;
                let password = crypto_provider
                    .decrypt_string_from_file(&data_path, self.master_pwd.as_ref().unwrap());

                match password {
                    Ok(p) => Ok(Some(p)),
                    Err(_) => Err(ManagerError::PasswordFileNotFound),
                }
            }
            Err(err) => Err(ManagerError::Unknown(err.to_string())),
        }
    }

    pub fn delete_profile(&mut self, profile_name: &str) -> Result<(), anyhow::Error> {
        let mut profile_id = None;

        for i in 0..self.profiles.len() {
            if self.profiles[i].name() == profile_name {
                profile_id = Some(self.profiles[i].id().clone());
                self.profiles.remove(i);
                break;
            }
        }

        if let Some(p) = profile_id {
            let password_path = get_password_data_path(&p)?;
            std::fs::remove_file(password_path)?;
        }

        self.save(&get_master_json_path()?)?;

        Ok(())
    }

    pub fn get_profiles(&self) -> &[PasswordProfile] {
        &self.profiles
    }

    pub fn get_profiles_vec(&self) -> Vec<PasswordProfile> {
        self.profiles.clone()
    }

    pub fn get_profile_by_name_mut(&mut self, profile_name: &str) -> Option<&mut PasswordProfile> {
        let profile = self
            .profiles
            .iter_mut()
            .filter(|x| x.name == profile_name)
            .next();

        if let Some(p) = profile {
            return Some(p);
        }

        None
    }

    pub fn get_profile_by_name(&self, profile_name: &str) -> Option<PasswordProfile> {
        let profile = self
            .profiles
            .iter()
            .filter(|x| x.name == profile_name)
            .next();

        if let Some(p) = profile {
            return Some(p.clone());
        }

        None
    }

    pub fn save(&self, file_path: &str) -> Result<(), anyhow::Error> {
        let mut master_json_file = File::create(file_path)?;
        let json = serde_json::to_string(&self)?;
        master_json_file.write_all(json.as_bytes())?;

        Ok(())
    }
}
