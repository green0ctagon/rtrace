// external crate imports
use chrono::prelude::*;

// stdlib imports
use std::env::args;
use std::io::{self, Write};
use std::process::exit;
use std::path::Path;

// colors/formatting shit for the output
const RED:     &'static str = "\x1b[91m";
const _BLUE:    &'static str = "\x1b[94m";
const _BOLD:    &'static str = "\x1b[1m";
const GREEN:   &'static str = "\x1b[92m";
const _BLINK:   &'static str = "\x1b[5m";
const _MAGENTA: &'static str = "\x1b[95m";
const RESET:   &'static str = "\x1b[0m";


fn main() -> std::io::Result<()> {
  let logfile = check_args();
  start_operator_cli(&logfile)?;
  Ok(())
}


fn check_args() -> String {
  let args = args().collect::<Vec<String>>();
  if args.len() != 2 || !Path::is_file(Path::new(&args[0])) {
    show_usage();
  }
  return String::from(&args[1])
}


fn show_usage() {
  let args = args().collect::<Vec<String>>();
  let chunks = args[0].split("/").map(|c| c.to_owned()).collect::<Vec<String>>();
  println!("Usage: {} <input_file>", &chunks[chunks.len()-1]);
  exit(1);
}


fn get_input() -> std::io::Result<String> {
  let mut input = String::new();
  io::stdin().read_line(&mut input)?;
  let input = input.trim();
  Ok(input.to_owned())
}


// clear terminal and reset cursor position
fn clear_terminal() {
  println!("{}[2J{}[1;1H",
    27 as char,
    27 as char
  );
}


fn exploit_menu() {
  println!("Functionality not yet added");
}

fn jobs_menu() {
  println!("Functionality not yet added");
}

// this function handles input/output for the initial menu
fn start_operator_cli(logfile:&str) -> std::io::Result<()> {
  clear_terminal();
  let banner = welcome_banner(logfile);
  loop {
    main_menu(&banner);
    prompt()?;
    let input = get_input()?;
    if input == "q" {
      println!("");
      break
    }
    else if input == "c" {
      clear_terminal();
    }
    else if input == "e" {
      exploit_menu();
    }
    else if input == "j" {
      jobs_menu();
    }
    else {
      let _ = "invalid option";
    }
  }
  Ok(())
}


// display the cli prompt, where user input is typed
fn prompt() -> std::io::Result<()> {
  print!("{}øƤęƦλt0ʀ > {}",
    RED,
    RESET,
  );
  io::stdout().flush()?;
  Ok(())
}


// return ISO-8601 timestamp for the current time
fn utc_now() -> String {
  let timestamp = Utc::now().format("%Y-%d-%mT%H:%M:%SZ").to_string();
  return timestamp
}


// this is the first message that is displayed when the CLI session begins
fn welcome_banner(logfile:&str) -> String {
  let timestamp = utc_now();
  let banner = format!("[{}Ξ{}] Analysis session for {}{}{} active as of {}{}{}",
    RED,
    RESET,
    GREEN,
    logfile,
    RESET,
    GREEN,
    timestamp,
    RESET
  );
  return banner
}


// This just displays the main menu options to the user
fn main_menu(banner:&str) {
  println!("");
  println!("{}", banner);
  println!("");
  println!("\t[{}j{}]\tView running jobs",
    GREEN,
    RESET
  );
  println!("\t[{}e{}]\tView Exploits",
    GREEN,
    RESET
  );
  println!("\t[{}c{}]\tClear the Terminal",
    GREEN,
    RESET
  );
  println!("\t[{}q{}]\tQuit program",
    GREEN,
    RESET
  );
  println!("");
}
