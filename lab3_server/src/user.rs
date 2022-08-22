use std::fmt;
use std::fmt::{Formatter};
/// This file is used to store and retrieve user accounts from the database
///
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum UserRole {
    StandardUser,
    HR,
}

impl fmt::Display for UserRole {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            UserRole::StandardUser => write!(f, "StandardUser"),
            UserRole::HR => write!(f, "HR"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserAccount {
    username: String,
    password: String,
    phone_number: String,
    role: UserRole,
}

impl UserAccount {
    pub fn new(username: String, password: String, phone_number: String, role: UserRole) -> Self {
        Self {
            username,
            password,
            phone_number,
            role,
        }
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn phone_number(&self) -> &str {
        &self.phone_number
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn role(&self) -> &UserRole {
        &self.role
    }

    pub fn set_phone_number(&mut self, phone_number: String) {
        self.phone_number = phone_number;
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserInfo {
    username: String,
    phone_number: String,
}

impl UserInfo {
    pub fn new(username: String, phone_number: String) -> Self {
        Self {
            username,
            phone_number,
        }
    }
}

