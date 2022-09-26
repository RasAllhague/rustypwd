use rand::rngs::ThreadRng;
use rand::Rng;
use secstr::SecStr;
use serde::{Deserialize, Serialize};

pub struct PasswordGenerator {
    settings: GeneratorSettings,
}

pub struct GeneratorSettings {
    allow_special_chars: bool,
    allow_uppercase_chars: bool,
    allow_spaces: bool,
    length: u32,
    iterations: u64,
}

#[derive(Deserialize, Serialize, PartialEq, Debug)]
pub struct CharacterSet {
    #[serde(rename = "lowercase")]
    lowercase_chars: String,
    #[serde(rename = "uppercase")]
    uppercase_chars: String,
    #[serde(rename = "special")]
    special_chars: String,
}

impl PasswordGenerator {
    pub fn new(settings: GeneratorSettings) -> PasswordGenerator {
        PasswordGenerator { settings }
    }

    pub fn generate(&self, char_set: &CharacterSet) -> SecStr {
        let mut rng = rand::thread_rng();
        let characters = self.build_characters(char_set);

        let password = self.generate_password(&mut rng, &characters);

        SecStr::from(password)
    }

    fn generate_password(&self, rng: &mut ThreadRng, characters: &str) -> String {
        let mut password: Vec<char> = self.init_password().chars().collect();

        for _ in 0..self.settings.iterations {
            for i in 0..self.settings.length {
                let index = rng.gen_range(0..characters.len() - 1);
                let character = characters
                    .chars()
                    .nth(index)
                    .expect("There was a character expected at the index.");

                password[i as usize] = character;
            }
        }

        password.iter().collect()
    }

    fn init_password(&self) -> String {
        let mut password = String::new();

        for _ in 0..self.settings.length {
            password.push('0');
        }

        password
    }

    fn build_characters(&self, char_set: &CharacterSet) -> String {
        let mut password_data = char_set.lowercase_chars();

        if self.settings.allow_uppercase_chars {
            password_data.push_str(&char_set.uppercase_chars());
        }
        if self.settings.allow_special_chars {
            password_data.push_str(&char_set.special_chars());
        }
        if self.settings.allow_spaces {
            password_data.push(' ');
        }

        password_data
    }
}

impl GeneratorSettings {
    pub fn new() -> Self {
        GeneratorSettings {
            allow_spaces: false,
            allow_uppercase_chars: false,
            allow_special_chars: false,
            length: 16,
            iterations: 1000,
        }
    }

    pub fn set_length(&mut self, length: u32) {
        self.length = length;
    }

    pub fn set_iterations(&mut self, iterations: u64) {
        self.iterations = iterations;
    }

    pub fn allow_spaces(&mut self) {
        self.allow_spaces = true;
    }

    pub fn allow_uppercase(&mut self) {
        self.allow_uppercase_chars = true;
    }

    pub fn allow_special(&mut self) {
        self.allow_special_chars = true;
    }

    pub fn deny_spaces(&mut self) {
        self.allow_spaces = false;
    }

    pub fn deny_uppercase(&mut self) {
        self.allow_uppercase_chars = false;
    }

    pub fn deny_special(&mut self) {
        self.allow_special_chars = false;
    }
}

impl CharacterSet {
    pub fn new(lowercase_chars: &str, uppercase_chars: &str, special_chars: &str) -> CharacterSet {
        CharacterSet {
            lowercase_chars: String::from(lowercase_chars),
            uppercase_chars: String::from(uppercase_chars),
            special_chars: String::from(special_chars),
        }
    }

    pub fn lowercase_chars(&self) -> String {
        self.lowercase_chars.clone()
    }

    pub fn uppercase_chars(&self) -> String {
        self.uppercase_chars.clone()
    }

    pub fn special_chars(&self) -> String {
        self.special_chars.clone()
    }
}
