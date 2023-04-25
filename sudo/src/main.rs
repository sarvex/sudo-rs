#![forbid(unsafe_code)]

use pam::PamAuthenticator;
use pipeline::{Pipeline, PolicyPlugin};
use sudo_cli::SudoOptions;
use sudo_common::{Context, Error};

mod diagnostic;
use diagnostic::diagnostic;
mod pam;
mod pipeline;

/// show warning message when SUDO_RS_IS_UNSTABLE is not set to the appropriate value
fn unstable_warning() {
    let check_var = std::env::var("SUDO_RS_IS_UNSTABLE").unwrap_or_else(|_| "".to_string());

    if check_var != "I accept that my system may break unexpectedly" {
        eprintln!(
            "WARNING!
Sudo-rs is in the early stages of development and could potentially break your system.
We recommend that you do not run this on any production environment. To turn off this
warning and start using sudo-rs set the environment variable SUDO_RS_IS_UNSTABLE to
the value `I accept that my system may break unexpectedly`. If you are unsure how to
do this then this software is not suited for you at this time."
        );

        std::process::exit(1);
    }
}

#[derive(Default)]
pub struct SudoersPolicy;

impl PolicyPlugin for SudoersPolicy {
    type PreJudgementPolicy = sudoers::Sudoers;
    type Policy = sudoers::Judgement;

    fn init(&mut self) -> Result<Self::PreJudgementPolicy, Error> {
        // TODO: move to global configuration
        let sudoers_path = "/etc/sudoers.test";

        let (sudoers, syntax_errors) = sudoers::Sudoers::new(sudoers_path)
            .map_err(|e| Error::Configuration(format!("{e}")))?;

        for sudoers::Error(pos, error) in syntax_errors {
            diagnostic!("{error}", sudoers_path @ pos);
        }

        Ok(sudoers)
    }

    fn judge(
        &mut self,
        pre: Self::PreJudgementPolicy,
        context: &Context,
    ) -> Result<Self::Policy, Error> {
        Ok(pre.check(
            &context.current_user,
            &context.hostname,
            sudoers::Request {
                user: &context.target_user,
                group: &context.target_group,
                command: &context.command.command,
                arguments: &context.command.arguments.join(" "),
            },
        ))
    }
}

fn sudo_process() -> Result<std::process::ExitStatus, Error> {
    sudo_log::SudoLogger::new().into_global_logger();

    // parse cli options
    let sudo_options = SudoOptions::parse();

    unstable_warning();

    let mut pipeline = Pipeline {
        policy: SudoersPolicy::default(),
        authenticator: PamAuthenticator::default(),
    };
    pipeline.run(sudo_options)
}

fn main() {
    match sudo_process() {
        Ok(status) => {
            if let Some(code) = status.code() {
                std::process::exit(code);
            } else {
                std::process::exit(1);
            }
        }
        Err(error) => {
            diagnostic!("{error}");
            std::process::exit(1);
        }
    }
}
