// Test binary (correspondns to tdict of the C codebase)

use popt::*;
use std::io::{BufRead, BufReader};

/// Count non-empty, non-comment lines in a file (for Bloom filter sizing).
fn count_dict_lines(path: &str) -> i32 {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return -1,
    };
    let reader = BufReader::new(file);
    let mut count: i32 = 0;
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        count += 1;
    }
    count
}

/// Load dictionary words into a Bloom filter.
fn load_dict(path: &str, bf: &mut BloomFilter) -> i32 {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return -1,
    };
    let reader = BufReader::new(file);
    let mut count: i32 = 0;
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        bf.insert(trimmed);
        count += 1;
    }
    count
}

fn main() {
    let dict_path = "/usr/share/dict/words";

    // Count lines first to size the bloom filter
    let nlines = count_dict_lines(dict_path);
    if nlines <= 0 {
        std::process::exit(2);
    }
    let k: u32 = 10;
    let n: u32 = 2 * k * (nlines as u32);

    // Define options
    let opts = OptionTable::new()
        .option(
            Opt::val("debug", 1)
                .short('d')
                .bit_or()
                .toggle()
                .description("Set debugging."),
        )
        .option(
            Opt::val("verbose", 0)
                .short('v')
                .bit_or()
                .toggle()
                .description("Set verbosity."),
        )
        .auto_alias()
        .auto_help();

    let mut ctx = match Context::builder("tdict").options(opts).build() {
        Ok(c) => c,
        Err(_) => std::process::exit(2),
    };

    if let Err(_) = ctx.parse() {
        std::process::exit(2);
    }

    // C default for _verbose is 1
    let verbose: u32 = if ctx.is_present("verbose") {
        ctx.get("verbose").unwrap_or(1)
    } else {
        1
    };

    // Load dictionary into Bloom filter
    let mut dictbits = BloomFilter::with_sizing(k, n);
    let rc = load_dict(dict_path, &mut dictbits);
    if rc <= 0 {
        std::process::exit(2);
    }

    // Get remaining args (words to check)
    let args = ctx.args();
    if args.is_empty() {
        std::process::exit(2);
    }

    // Build bloom filter from args
    let mut avbits = BloomFilter::with_sizing(k, n);
    for arg in &args {
        avbits.insert(arg);
    }

    // Check intersection: are any input words in the dictionary?
    let mut ibits = dictbits.clone();
    let has_common = ibits.intersect(&avbits);
    println!(
        "===== {} words are in {}",
        if has_common { "Some" } else { "No" },
        dict_path
    );

    // Check each word against dictionary
    let mut total: u32 = 0;
    let mut hits: u32 = 0;
    let mut misses: u32 = 0;

    for arg in &args {
        total += 1;
        if dictbits.contains(arg) {
            if verbose != 0 {
                println!("{}:\tYES", arg);
            }
            hits += 1;
        } else {
            if verbose != 0 {
                println!("{}:\tNO", arg);
            }
            misses += 1;
        }
    }

    println!("total({}) = hits({}) + misses({})", total, hits, misses);
}
