use lazy_static::lazy_static;
use fancy_regex::Regex;

/// Validate swiss phone number in the following format: 0xxxxxxxxx
pub fn validate_phone(phone: &str) -> bool {
    lazy_static! {
        static ref SWISS_PHONE_REGEX : Regex = Regex::new(r"^([0])([0-9]{2})([0-9]{3})([0-9]{2})([0-9]{2})$").unwrap();
    }
    SWISS_PHONE_REGEX.is_match(phone).unwrap()
}

/// Validate a username based on the policy:
/// - case insensitive
/// - only ascii alphanum + underscores
/// - max 32 chars
/// - min 1 char
pub fn validate_username(username: &str) -> bool {
    lazy_static! {
        static ref USERNAME_REGEX: Regex = Regex::new(r"^[[:alnum:]_]{1,32}$").unwrap();
    }

    USERNAME_REGEX.is_match(username).unwrap()
}

/// Validate a password based on the policy:
/// - At least **one digit** \[0-9\]
/// - At least **one lowercase** character \[a-z\]
/// - At least **one uppercase** character \[A-Z\]
/// - At least **one special** character \[.!@#$%^&{}\[\]:;<>,?\\/~_+\-=|'\*\(\)\]
/// - At least **8** characters in length, but no more than **64**.
pub fn validate_password(password: &str) -> bool {
    lazy_static! {
        static ref PASSWORD_REGEX: Regex = Regex::new(r"^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[.!@#$%^&{}\[\]:;<>,?\\/~_+\-=|'\*\(\)]).{8,64}$").unwrap();
    }
    PASSWORD_REGEX.is_match(password).unwrap()
}

