// Test binary (corresponds to test3 of the C codebase)
// Config file parsing utilities test

use popt::*;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() == 1 {
        println!("usage: test-popt file_1 file_2 ...");
        println!("you may specify many files");
        std::process::exit(1);
    }

    for filename in &args[1..] {
        match config_file_to_string(filename) {
            Ok(config_str) => {
                println!("single string: '{}'", config_str);

                match parse_argv_string(&config_str) {
                    Ok(parsed) => {
                        println!("popt array: size={}", parsed.len());
                        for arg in &parsed {
                            println!("'{}'", arg);
                        }
                    }
                    Err(e) => {
                        eprintln!("cannot parse {}. error={}", filename, e);
                    }
                }
            }
            Err(e) => {
                eprintln!("cannot read file {}.  {}", filename, e);
                continue;
            }
        }
        println!();
    }

    Ok(())
}
