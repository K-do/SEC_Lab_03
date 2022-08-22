/// This file is used to store and retrieve user accounts from the database

use crate::user::{UserAccount, UserInfo, UserRole};
use lazy_static::lazy_static;
use rustbreak::{deser::Ron, FileDatabase};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use log::info;

lazy_static! {
    static ref DB: FileDatabase<Database, Ron> =
        FileDatabase::load_from_path_or_default("db.ron").unwrap();
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Database {
    data: HashMap<String, UserAccount>,
}

impl Database {
    pub fn insert(user: &UserAccount) -> Result<(), Box<dyn Error>> {
        DB.write(|db| db.data.insert(user.username().to_string(), user.clone()))?;
        DB.save()?;
        info!("database updated");
        Ok(())
    }

    pub fn get(username: &str) -> Result<Option<UserAccount>, Box<dyn Error>> {
        Ok(match DB.borrow_data()?.data.get(username) {
            Some(user) => Some(user.clone()),
            None => None,
        })
    }

    pub fn get_all_user_info() -> Result<Vec<UserInfo>, Box<dyn Error>> {
        Ok(DB.borrow_data()?.data
            .values()
            .cloned()
            .map(|u| {
                UserInfo::new(String::from(u.username()), String::from(u.phone_number()))})
            .collect())
    }
}

impl Default for Database {
    fn default() -> Self {
        let mut db = Database {
            data: HashMap::new(),
        };

        // Password is Test1234.
        // => please use this account only for setup and remove it in prod
        let u1 = UserAccount::new(
            "default_user".to_string(),
            "$argon2id$v=19$m=65536,t=3,p=4$saKWfVlIpG7rMgG9fk4LYA$qYyHtS8jrIVQ3w4feR32r4t4G9FTSCV74k5r48+A+ISf0ZB7B1Ut5EWn2/L57uDTfXtqO98rJD/BD5jc+FE9mQ".to_string(),
            "0784539872".to_string(),
            UserRole::StandardUser,
        );

        // Password is Test1234.
        // => please use this account only for setup and remove it in prod
        let u2 = UserAccount::new(
            "default_hr".to_string(),
            "$argon2id$v=19$m=65536,t=3,p=4$saKWfVlIpG7rMgG9fk4LYA$qYyHtS8jrIVQ3w4feR32r4t4G9FTSCV74k5r48+A+ISf0ZB7B1Ut5EWn2/L57uDTfXtqO98rJD/BD5jc+FE9mQ".to_string(),
            "0793175289".to_string(),
            UserRole::HR,
        );

        db.data.insert(u1.username().to_string(), u1);
        db.data.insert(u2.username().to_string(), u2);

        db
    }
}
