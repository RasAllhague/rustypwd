use arboard::Clipboard;
use chrono::Utc;
use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};
use crossterm::QueueableCommand;
use inquire::{required, Confirm, CustomType, MultiSelect, Password, Select, Text};
use rustypwd::encryption::{Chacha20poly1305Provider, CryptoProvider};
use rustypwd::generator::{GeneratorSettings, PasswordGenerator};
use rustypwd::manager::{PasswordManager, PasswordProfile};
use rustypwd::{get_data_path, get_master_json_path, load_charset};
use secstr::SecStr;
use std::fs::File;
use std::io::{stdout, Stdout, Write};
use std::path::Path;
use uuid::Uuid;

static MASTER_PWD_CHECK_FILE: &str = ".chk";
static CHECK_UUID: &str = "82117911-4944-43e3-adb6-49e3c84c1746";

pub fn check_master_password(
    pwd_manager: &mut PasswordManager,
    password: SecStr,
) -> Result<bool, anyhow::Error> {
    let data_dir = get_data_path()?;
    let master_pwd_file_path = Path::new(&data_dir).join(MASTER_PWD_CHECK_FILE);

    let crypto = Chacha20poly1305Provider {};

    let result = crypto.decrypt_string_from_file(master_pwd_file_path.to_str().unwrap(), &password);

    match result {
        Ok(_) => {
            pwd_manager.set_master_pwd(password);

            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

fn create_master_pwd(data_path: &str, password: &SecStr) -> Result<(), anyhow::Error> {
    let master_pwd_file_path = Path::new(data_path).join(MASTER_PWD_CHECK_FILE);
    let crypto = Chacha20poly1305Provider {};

    let data = crypto.encrypt_string(SecStr::from(CHECK_UUID), &password)?;

    let mut file = File::create(master_pwd_file_path)?;
    file.write_all(data.unsecure())?;

    Ok(())
}

fn main() -> Result<(), anyhow::Error> {
    println!("{} v.{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    run()?;

    Ok(())
}

fn run() -> Result<(), anyhow::Error> {
    let json_path = get_master_json_path()?;
    let data_dir = get_data_path()?;

    if !Path::new(&json_path).exists() {
        let tmp_manager = PasswordManager::new();
        tmp_manager.save(&json_path)?;
    }

    let master_pwd_file_path = Path::new(&data_dir).join(MASTER_PWD_CHECK_FILE);

    if !master_pwd_file_path.exists() {
        stdout()
            .queue(SetForegroundColor(Color::Yellow))?
            .queue(Print("The master password has not been set yet!\n"))?
            .queue(ResetColor)?
            .flush()?;
    }

    let master_pwd = Password::new("Master password:").prompt()?;
    let master_pwd = SecStr::from(master_pwd);

    if !master_pwd_file_path.exists() {
        let master_pwd2 = Password::new("Master password repeated:").prompt()?;
        let mut master_pwd2 = SecStr::from(master_pwd2);

        if master_pwd == master_pwd2 {
            create_master_pwd(&data_dir, &master_pwd)?;
            master_pwd2.zero_out();

            stdout()
                .queue(SetForegroundColor(Color::Yellow))?
                .queue(Print("The master password has been set!\n"))?
                .queue(ResetColor)?
                .flush()?;
        } else {
            master_pwd2.zero_out();

            stdout()
                .queue(SetForegroundColor(Color::Red))?
                .queue(Print("The passwords did not match!\n"))?
                .queue(ResetColor)?
                .flush()?;

            return Ok(());
        }
    }

    let contents = std::fs::read_to_string(json_path)?;
    let mut pwd_manager: PasswordManager = serde_json::from_str(&contents)?;

    if check_master_password(&mut pwd_manager, master_pwd)? {
        main_menu(&mut pwd_manager)?;

        pwd_manager.unset_master_pwd();
    } else {
        println!("Password was wrong!");
    }

    Ok(())
}

fn main_menu(pwd_manager: &mut PasswordManager) -> Result<(), anyhow::Error> {
    let options: Vec<&str> = vec!["Generate password", "Profiles", "Settings", "Quit"];

    let ans = Select::new("Main menu:", options).prompt()?;

    match ans {
        "Generate password" => {
            let options = vec!["Display password", "Copy to clipboard"];

            let password = generate_password_dialog()?;
            let ans =
                MultiSelect::new("What should be done with the password?", options).prompt()?;

            if ans.contains(&"Display password") {
                let pwd_str = std::str::from_utf8(password.unsecure())?;
                stdout()
                    .queue(Print("Password: "))?
                    .queue(SetForegroundColor(Color::Cyan))?
                    .queue(Print(format!("{}\n", pwd_str)))?
                    .queue(ResetColor)?
                    .flush()?;
            }

            if ans.contains(&"Copy to clipboard") {
                let pwd_str = std::str::from_utf8(password.unsecure())?;
                let mut clipboard = Clipboard::new()?;

                clipboard.set_text::<&str>(pwd_str.into())?;
            }

            main_menu(pwd_manager)?;
        }
        "Profiles" => profiles_menu(pwd_manager)?,
        "Settings" => main_menu(pwd_manager)?,
        _ => (),
    };

    Ok(())
}

fn profiles_menu(pwd_manager: &mut PasswordManager) -> Result<(), anyhow::Error> {
    let options: Vec<&str> = vec!["New profile", "Show profiles", "Back"];

    let ans = Select::new("Profiles menu:", options).prompt()?;

    match ans {
        "New profile" => new_profile_menu(pwd_manager)?,
        "Show profiles" => show_profiles_menu(pwd_manager)?,
        _ => main_menu(pwd_manager)?,
    };

    Ok(())
}

fn new_profile_menu(pwd_manager: &mut PasswordManager) -> Result<(), anyhow::Error> {
    let profile_name = Text::new("What is the profile name?")
        .with_validator(required!())
        .prompt()?;
    let website_name = Text::new("For what website/account is this profile?")
        .with_validator(required!())
        .prompt_skippable()?;
    let username = Text::new("Whats the username for this profile?").prompt_skippable()?;

    let id = Uuid::new_v4();
    let mut profile = PasswordProfile::new(id.clone(), &profile_name.trim_end(), Utc::now());

    if let Some(w) = website_name {
        profile.set_website(&w);
    }
    if let Some(u) = username {
        profile.set_username(&u);
    }

    let should_gen_pwd = Confirm::new("Do you want to generate a new password?")
        .with_default(true)
        .prompt()?;

    if should_gen_pwd {
        let p = generate_password_dialog()?;

        pwd_manager.add_profile(profile.clone(), p)?;
        display_profile(pwd_manager, profile.name())?;
        profile_menu(pwd_manager, profile.name())?;
    } else {
        let password = Password::new("Password:").prompt()?;
        let password = SecStr::from(password);

        pwd_manager.add_profile(profile.clone(), password)?;
        display_profile(pwd_manager, profile.name())?;
        profile_menu(pwd_manager, profile.name())?;
    }

    profiles_menu(pwd_manager)?;

    Ok(())
}

fn display_profile_line(
    stdout: &mut Stdout,
    text1: &str,
    text2: &str,
    color: Color,
) -> Result<(), anyhow::Error> {
    stdout
        .queue(Print(text1))?
        .queue(SetForegroundColor(color))?
        .queue(Print(format!("{}\n", text2)))?
        .queue(ResetColor)?;

    Ok(())
}

fn profile_menu(
    pwd_manager: &mut PasswordManager,
    profile_name: &str,
) -> Result<(), anyhow::Error> {
    let options = vec![
        "Edit",
        "Display password",
        "Copy password to clipboard",
        "Delete",
        "Back",
    ];
    let ans = Select::new("Please select a profile action:", options).prompt()?;

    match ans {
        "Edit" => edit_profile(pwd_manager, profile_name)?,
        "Display password" => {
            let mut password = match pwd_manager.get_password_for_profile(profile_name)? {
                Some(p) => p,
                None => {
                    return Err(anyhow::anyhow!(
                        "Password could not be found for this profile!"
                    ))
                }
            };

            let pwd_str = std::str::from_utf8(password.unsecure())?;
            stdout()
                .queue(Print("Password: "))?
                .queue(SetForegroundColor(Color::Cyan))?
                .queue(Print(format!("{}\n", pwd_str)))?
                .queue(ResetColor)?
                .flush()?;

            password.zero_out();
        }
        "Copy password to clipboard" => {
            let mut password = match pwd_manager.get_password_for_profile(profile_name)? {
                Some(p) => p,
                None => {
                    return Err(anyhow::anyhow!(
                        "Password could not be found for this profile!"
                    ))
                }
            };

            let pwd_str = std::str::from_utf8(password.unsecure())?;
            let mut clipboard = Clipboard::new()?;
            clipboard.set_text::<&str>(pwd_str.into())?;

            password.zero_out();
        }
        "Delete" => {
            delete_profile(pwd_manager, profile_name)?;
            return Ok(());
        }
        _ => return Ok(()),
    }

    profile_menu(pwd_manager, profile_name)?;

    // done to clear the clipboard after finishing using the pwd.
    let mut clipboard = Clipboard::new()?;
    clipboard.set_text(String::from("Empty"))?;

    Ok(())
}

fn edit_profile(
    pwd_manager: &mut PasswordManager,
    old_profile_name: &str,
) -> Result<(), anyhow::Error> {
    let profile = match pwd_manager.get_profile_by_name(old_profile_name) {
        Some(p) => p,
        None => {
            profiles_menu(pwd_manager)?;
            return Ok(());
        }
    };

    let profile_name = Text::new("What is the profile name?")
        .with_validator(required!())
        .prompt_skippable()?;
    let website_name = Text::new("For what website/account is this profile?")
        .with_validator(required!())
        .prompt_skippable()?;
    let username = Text::new("Whats the username for this profile?").prompt_skippable()?;

    let mut new_profile = PasswordProfile::new(profile.id(), old_profile_name, Utc::now());

    if let Some(n) = profile_name {
        new_profile.set_name(&n);
    }
    if let Some(w) = website_name {
        new_profile.set_website(&w);
    }
    if let Some(u) = username {
        new_profile.set_username(&u);
    }

    let should_gen_pwd = Confirm::new("Do you want to generate a new password?")
        .with_default(true)
        .prompt_skippable()?;

    if let Some(should_gen_pwd) = should_gen_pwd {
        if should_gen_pwd {
            let p = generate_password_dialog()?;

            pwd_manager.update_profile(old_profile_name, new_profile, Some(p))?;
            display_profile(pwd_manager, profile.name())?;
            profile_menu(pwd_manager, profile.name())?;
        } else {
            let password = Password::new("Password:").prompt()?;
            let password = SecStr::from(password);

            pwd_manager.update_profile(old_profile_name, new_profile, Some(password))?;
            display_profile(pwd_manager, profile.name())?;
            profile_menu(pwd_manager, profile.name())?;
        }
    } else {
        pwd_manager.update_profile(old_profile_name, new_profile, None)?;
    }

    profiles_menu(pwd_manager)?;

    Ok(())
}

fn delete_profile(
    pwd_manager: &mut PasswordManager,
    profile_name: &str,
) -> Result<(), anyhow::Error> {
    let should_delete = Confirm::new("Are you sure you want to delete this password?")
        .with_default(false)
        .prompt()?;

    if should_delete {
        pwd_manager.delete_profile(profile_name)?;
    }

    Ok(())
}

fn display_profile(
    pwd_manager: &mut PasswordManager,
    profile_name: &str,
) -> Result<(), anyhow::Error> {
    let mut stdout = stdout();

    if let Some(p) = pwd_manager.get_profile_by_name(profile_name) {
        display_profile_line(&mut stdout, "Profile: ", p.name(), Color::Cyan)?;

        if let Some(website) = p.website() {
            display_profile_line(&mut stdout, "Account/website: ", &website, Color::Cyan)?;
        } else {
            display_profile_line(&mut stdout, "Account/website: ", "none", Color::Cyan)?;
        }

        if let Some(username) = p.username() {
            display_profile_line(&mut stdout, "Username: ", &username, Color::Cyan)?;
        } else {
            display_profile_line(&mut stdout, "Username: ", "none", Color::Cyan)?;
        }

        display_profile_line(
            &mut stdout,
            "Created: ",
            &p.create_date().to_string(),
            Color::Cyan,
        )?;

        if let Some(modify_date) = p.modify_date() {
            display_profile_line(
                &mut stdout,
                "Last modified: ",
                &modify_date.to_string(),
                Color::Cyan,
            )?;
        } else {
            display_profile_line(&mut stdout, "Last modified: ", "none", Color::Cyan)?;
        }
    } else {
        stdout.queue(Print("No profile found with this name!\n"))?;
    }

    stdout.flush()?;

    Ok(())
}

fn show_profiles_menu(pwd_manager: &mut PasswordManager) -> Result<(), anyhow::Error> {
    let profiles = pwd_manager.get_profiles_vec();

    let profile_names: Vec<&str> = profiles.iter().map(|x| x.name()).collect();

    if profile_names.len() < 1 {
        stdout()
            .queue(SetForegroundColor(Color::Yellow))?
            .queue(Print("No profiles have been created yet!\n"))?
            .queue(ResetColor)?
            .flush()?;

        profiles_menu(pwd_manager)?;
        return Ok(());
    }

    let profile_name = Select::new("Which profile do you want to see?", profile_names).prompt()?;

    display_profile(pwd_manager, profile_name)?;
    profile_menu(pwd_manager, profile_name)?;

    let show_more = Confirm::new("Show more profiles?")
        .with_default(false)
        .prompt()?;

    if show_more {
        show_profiles_menu(pwd_manager)?;
    } else {
        profiles_menu(pwd_manager)?;
    }

    Ok(())
}

fn generate_password_dialog() -> Result<SecStr, anyhow::Error> {
    let mut config = GeneratorSettings::new();

    let uppercase = Confirm::new("Should uppercase be allowed?")
        .with_default(true)
        .prompt()?;
    let special = Confirm::new("Should special chars be allowed?")
        .with_default(true)
        .prompt()?;
    let spaces = Confirm::new("Should spaces be allowed?")
        .with_default(true)
        .prompt()?;
    let length = CustomType::<u32>::new("How long should the password be?")
        .with_formatter(&|i| format!("{}", i))
        .with_error_message("Please type a valid number")
        .with_default((16, &|i| format!("{}", i)))
        .with_help_message("The length must be bigger or equal to 8.")
        .prompt()?;

    let iterations = CustomType::<u64>::new("How many iterations should be used at creation?")
        .with_formatter(&|i| format!("{}", i))
        .with_error_message("Please type a valid number")
        .with_default((1000, &|i| format!("{}", i)))
        .with_help_message("The amount of times the password will be randomised, standard is 1000.")
        .prompt()?;

    if uppercase {
        config.allow_uppercase();
    }
    if special {
        config.allow_special();
    }
    if spaces {
        config.allow_spaces();
    }
    config.set_length(length);
    config.set_iterations(iterations);

    let generator = PasswordGenerator::new(config);
    let charset = load_charset()?;

    let password = generator.generate(&charset);

    Ok(password)
}
