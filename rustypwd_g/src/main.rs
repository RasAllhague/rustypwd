use arboard::Clipboard;
use rustypwd::generator::CharacterSet;
use rustypwd::generator::GeneratorSettings;
use rustypwd::generator::PasswordGenerator;
use std::error::Error;
use structopt::StructOpt;

#[derive(StructOpt)]
struct Config {
    #[structopt(short = "c", long = "chars-file", help = "Path to chars config file.")]
    chars_file: String,
    #[structopt(
        short = "w",
        long = "write-to-console",
        help = "Sets whether the pwd should be written to console."
    )]
    write_to_console: bool,
    #[structopt(
        short = "C",
        long = "copy-to-clipboard",
        help = "Sets whether the password should be copied to clipboard."
    )]
    copy_to_clipboard: bool,
    #[structopt(long = "allow-spaces", help = "Enables spaces in password generation.")]
    allow_spaces: bool,
    #[structopt(
        long = "allow-special-chars",
        help = "Enables special characters in password generation."
    )]
    allow_special_chars: bool,
    #[structopt(
        long = "allow-uppercase-chars",
        help = "Enables uppercase characters in password generation."
    )]
    allow_uppercase_chars: bool,
    #[structopt(
        short = "l",
        long = "length",
        help = "The length of the password.",
        default_value = "16"
    )]
    length: u32,
    #[structopt(
        short = "i",
        long = "iterations",
        help = "Amount of iterations the password should be changed.",
        default_value = "1000"
    )]
    iterations: u64,
}

fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::from_args();

    println!("{} v.{}", env!("CARGO_PKG_Name"), env!("CARGO_PKG_VERSION"));

    let chars_data = std::fs::read_to_string(config.chars_file.clone())?;
    let char_set = serde_json::from_str(&chars_data)?;

    if !config.write_to_console && !config.copy_to_clipboard {
        println!("You have to either enable clipboard pasting or writing to console.");
        return Ok(());
    }

    run(config, char_set)?;

    Ok(())
}

fn run(config: Config, char_set: CharacterSet) -> Result<(), Box<dyn Error>> {
    let settings = build_settings(&config);

    let generator = PasswordGenerator::new(settings);
    let password = generator.generate(&char_set);

    println!("Password generated.");

    if config.write_to_console {
        let pwd_str = std::str::from_utf8(password.unsecure())?;
        println!("Password: {}", pwd_str);
    }

    if config.copy_to_clipboard {
        let pwd_str = std::str::from_utf8(password.unsecure())?;
        let mut clipboard = Clipboard::new()?;

        clipboard.set_text::<&str>(pwd_str.into())?;
    }

    Ok(())
}

fn build_settings(config: &Config) -> GeneratorSettings {
    let mut settings = GeneratorSettings::new();

    if config.allow_spaces {
        settings.allow_spaces();
    }

    if config.allow_special_chars {
        settings.allow_special();
    }

    if config.allow_uppercase_chars {
        settings.allow_uppercase();
    }

    settings.set_length(config.length);
    settings.set_iterations(config.iterations);

    settings
}
