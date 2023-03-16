use pretty_assertions::assert_eq;
use sudo_test::{Command, Env, User};

use crate::{Result, PASSWORD, USERNAME};

#[test]
fn correct_password() -> Result<()> {
    let env = Env(format!("{USERNAME}    ALL=(ALL:ALL) ALL"))
        .user(User(USERNAME).password(PASSWORD))
        .build()?;

    Command::new("sshpass")
        .args(["-p", PASSWORD, "sudo", "true"])
        .as_user(USERNAME)
        .exec(&env)?
        .assert_success()
}

#[test]
fn incorrect_password() -> Result<()> {
    let env = Env(format!("{USERNAME}    ALL=(ALL:ALL) ALL"))
        .user(User(USERNAME).password("strong-password"))
        .build()?;

    let output = Command::new("sshpass")
        .args(["-p", "incorrect-password", "sudo", "true"])
        .as_user(USERNAME)
        .exec(&env)?;
    assert!(!output.status().success());

    // `sshpass` will override sudo's exit code with the value 5 so we can't check this
    // assert_eq!(Some(1), output.status().code());

    if sudo_test::is_original_sudo() {
        assert_contains!(output.stderr(), "1 incorrect password attempt");
    }

    Ok(())
}

#[test]
fn no_tty() -> Result<()> {
    let env = Env(format!("{USERNAME}    ALL=(ALL:ALL) ALL"))
        .user(User(USERNAME).password(PASSWORD))
        .build()?;

    let output = Command::new("sudo")
        .args(["true"])
        .as_user(USERNAME)
        .exec(&env)?;
    assert_eq!(Some(1), output.status().code());

    if sudo_test::is_original_sudo() {
        assert_contains!(output.stderr(), "no tty present");
    }

    Ok(())
}
