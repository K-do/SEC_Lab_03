/// This file is used to execute the various actions submitted by the clients

use crate::connection::Connection;
use crate::database::Database;
use crate::user::{UserAccount, UserInfo, UserRole};
use serde::{Deserialize, Serialize};
use std::error::Error;
use casbin::prelude::{CoreApi, Enforcer};
use log::{info, warn};
use strum_macros::{EnumIter, EnumString};
use crate::argon2::{hash_password, verify_password};
use crate::validator::{validate_password, validate_phone, validate_username};

#[derive(Serialize, Deserialize, Debug, EnumString, EnumIter)]
pub enum Action {
    #[strum(serialize = "Show users", serialize = "1")]
    ShowUsers,
    #[strum(serialize = "Change my phone number", serialize = "2")]
    ChangeOwnPhone,
    #[strum(serialize = "Show someone's phone number", serialize = "3")]
    ChangePhone,
    #[strum(serialize = "Add user", serialize = "4")]
    AddUser,
    #[strum(serialize = "Login", serialize = "5")]
    Login,
    #[strum(serialize = "Logout", serialize = "6")]
    Logout,
    #[strum(serialize = "Exit", serialize = "7")]
    Exit,
}

/// The individual actions are implemented with three main steps:
///     1. Read client inputs if required
///     2. Execute various server code
///     3. Send a result
impl Action {
    const FORBIDDEN_MSG: &'static str = "forbidden";
    const UNAUTHENTICATED_MSG: &'static str = "unauthenticated";

    pub fn perform(&self, u: &mut ConnectedUser) -> Result<(), Box<dyn Error>> {
        let res = match self {
            Action::ShowUsers => Action::show_users(u),
            Action::ChangeOwnPhone => Action::change_own_phone(u),
            Action::ChangePhone => Action::change_phone(u),
            Action::AddUser => Action::add_user(u),
            Action::Login => Action::login(u),
            Action::Logout => Action::logout(u),
            Action::Exit => Err("Client disconnected")?,
        };

        res
    }

    pub fn show_users(u: &mut ConnectedUser) -> Result<(), Box<dyn Error>> {
        let users = Database::get_all_user_info()?;
        let res: Result<Vec<UserInfo>, &str> = Ok(users);
        u.conn().send(&res)
    }

    pub fn change_own_phone(u: &mut ConnectedUser) -> Result<(), Box<dyn Error>> {
        let phone = u.conn().receive::<String>()?;

        // Control access and validate phone
        let res = if u.is_anonymous() {
            warn!("Access forbidden to anonymous user trying to change own phone");
            Err(Action::UNAUTHENTICATED_MSG)
        } else {
            let mut user = u.user_account()?;
            if !Action::control_access(&user.role().to_string(), "changeOwnPhone")? {
                warn!("Access forbidden to \"{}\" trying to change own phone", u.username());
                Err(Action::FORBIDDEN_MSG)
            } else if !validate_phone(&phone) {
                warn!("\"{}\" try to change own phone with an invalid number", u.username());
                Err("Invalid phone number")
            } else {
                user.set_phone_number(phone);
                Database::insert(&user)?;
                info!("\"{}\" changed own phone", u.username());
                Ok(())
            }
        };

        u.conn().send(&res)
    }

    pub fn change_phone(u: &mut ConnectedUser) -> Result<(), Box<dyn Error>> {
        // Receive data
        let username = u.conn().receive::<String>()?.to_lowercase();
        let phone = u.conn().receive::<String>()?;
        let target_user = Database::get(&username)?;

        // Control access
        let res = if u.is_anonymous() {
            warn!("Access forbidden to anonymous user trying to change phone");
            Err(Action::UNAUTHENTICATED_MSG)
        } else if !Action::control_access(&u.user_account()?.role().to_string(), "changePhone")? {
            warn!("Access forbidden to \"{}\" trying to change phone of \"{}\"", u.username(), &username);
            Err(Action::FORBIDDEN_MSG)
        } else if target_user.is_none() {
            warn!("\"{}\" try to change phone, \"{}\" does not exist", u.username(), &username);
            Err("Target user not found")
        } else if !validate_phone(&phone) {
            warn!("\"{}\" try to change phone of \"{}\" with an invalid number", u.username(), &username);
            Err("Invalid phone number")
        } else {
            let mut target_user = target_user.unwrap();
            target_user.set_phone_number(phone);
            Database::insert(&target_user)?;
            info!("\"{}\" changed phone of \"{}\"", u.username(), &username);
            Ok(())
        };

        u.conn().send(&res)
    }

    pub fn add_user(u: &mut ConnectedUser) -> Result<(), Box<dyn Error>> {
        // Receive data
        let username = u.conn().receive::<String>()?.to_lowercase();
        let password = u.conn().receive::<String>()?;
        let phone = u.conn().receive::<String>()?;
        let role = u.conn().receive::<UserRole>()?;

        // Control access and validate inputs
        let res = if u.is_anonymous() {
            warn!("Access forbidden to anonymous user trying to add a user");
            Err(Action::UNAUTHENTICATED_MSG)
        } else if !Action::control_access(&u.user_account()?.role().to_string(), "addUser")? {
            warn!("Access forbidden to \"{}\" trying to add a user", u.username());
            Err(Action::FORBIDDEN_MSG)
        } else if Database::get(&username)?.is_some() {
            warn!("\"{}\" try to add the user \"{}\", but it already exists", u.username(), &username);
            Err("User already exists")
        } else if !validate_username(&username) {
            warn!("\"{}\" try to add an user with an invalid username", u.username());
            Err("Invalid username")
        } else if !validate_password(&password) {
            warn!("\"{}\" try to add an user with an invalid password", u.username());
            Err("Invalid password")
        } else if !validate_phone(&phone) {
            warn!("\"{}\" try to add user with an invalid phone number", u.username());
            Err("Invalid phone number")
        } else {
            let user = UserAccount::new(username.clone(), hash_password(&password)?, phone, role);
            Database::insert(&user)?;
            info!("\"{}\" user added by \"{}\"", &username, u.username());
            Ok(())
        };

        u.conn.send(&res)
    }

    pub fn login(u: &mut ConnectedUser) -> Result<(), Box<dyn Error>> {
        // Receive data
        let username = u.conn().receive::<String>()?.to_lowercase();
        let password = u.conn().receive::<String>()?;

        let res = if !u.is_anonymous() {
            Err("You are already logged in")
        } else {
            let user = Database::get(&username)?;

            if let Some(user) = user {
                if verify_password(&password, user.password())? {
                    u.set_username(&username);
                    info!("user \"{}\" logged in", u.username());
                    Ok(())
                } else {
                    warn!("user \"{}\" failed logging in: invalid credentials", username);
                    Err("Authentication failed")
                }
            } else {
                // we verify the password for timing reasons
                verify_password("Fail", "$argon2id$v=19$m=65536,t=3,p=4$0000000000000000000000$00000000000000000000000000000000000000000000000000000000000000000000000000000000000000")?;
                warn!("user \"{}\" failed logging in: invalid user", username);
                Err("Authentication failed")
            }
        };

        u.conn.send(&res)
    }

    pub fn logout(u: &mut ConnectedUser) -> Result<(), Box<dyn Error>> {
        let res: Result<(), &str>;

        // Check permissions
        res = if u.is_anonymous() {
            Err("You are not logged in")
        } else {
            info!("user \"{}\" logged out", u.username());
            u.logout();
            Ok(())
        };

        u.conn.send(&res)
    }

    #[tokio::main]
    async fn control_access(role: &str, resource: &str) -> casbin::Result<bool> {
        let e = Enforcer::new("access_policy/model.conf", "access_policy/policy.csv")
            .await
            .expect("cannot read model or policy");
        e.enforce((role, resource))
    }
}

/// Used to represent a connected user for the actions
pub struct ConnectedUser {
    username: Option<String>,
    conn: Connection,
}

impl ConnectedUser {
    pub fn anonymous(conn: Connection) -> ConnectedUser {
        ConnectedUser {
            username: None,
            conn,
        }
    }

    pub fn username(&mut self) -> String {
        self.username.as_ref().unwrap().clone()
    }

    pub fn conn(&mut self) -> &mut Connection {
        &mut self.conn
    }

    pub fn set_username(&mut self, username: &str) {
        self.username = Some(username.to_string());
    }

    pub fn is_anonymous(&self) -> bool {
        return self.username.is_none();
    }

    pub fn logout(&mut self) {
        self.username = None;
    }

    pub fn user_account(&mut self) -> Result<UserAccount, Box<dyn Error>> {
        Ok(Database::get(&self.username())?.expect("User logged in but not in DB"))
    }
}
