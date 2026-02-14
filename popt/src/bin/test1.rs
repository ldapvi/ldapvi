// Test binary (corresponds to test1 of the C codebase)

use popt::*;

fn main() {
    let result = run();
    if let Err(e) = result {
        println!("{}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    // Build inc as a sub-table
    let inc_table = OptionTable::new().option(
        Opt::new("inc")
            .short('I')
            .description("An included argument"),
    );

    // Callback table
    let callback_table = OptionTable::new()
        .callback(
            |arg, data| {
                print!("callback: c {} {} ", data.unwrap_or(""), arg.unwrap_or(""));
                Ok(())
            },
            Some("sampledata"),
        )
        .option(
            Opt::new("cb")
                .short('c')
                .arg_type(ArgType::String)
                .description("Test argument callbacks")
                .set_val('c' as i32),
        )
        .option(Opt::val("", ' ' as i32).doc_hidden())
        .option(
            Opt::new("longopt")
                .set_val('l' as i32)
                .description("Unused option for help testing"),
        );

    // cb2 callback table with INC_DATA flag
    let cb2_table = OptionTable::new()
        .callback_inc_data(|arg, data| {
            print!("callback: c {} {} ", data.unwrap_or(""), arg.unwrap_or(""));
            Ok(())
        })
        .option(
            Opt::new("cb2")
                .short('c')
                .arg_type(ArgType::String)
                .arg_description("STRING")
                .description("Test argument callbacks")
                .set_val('c' as i32),
        );

    let opts = OptionTable::new()
        .include_table(cb2_table, Some("arg for cb2"))
        .option(
            Opt::new("arg1")
                .description("First argument with a really long description. After all, we have to test argument help wrapping somehow, right?")
        )
        .option(
            Opt::new("arg2")
                .short('2')
                .arg_type(ArgType::String)
                .arg_description("ARG")
                .description("Another argument")
                .default_val("(none)")
                .show_default()
        )
        .option(
            Opt::new("arg3")
                .short('3')
                .arg_type(ArgType::Int)
                .arg_description("ANARG")
                .description("A third argument")
        )
        .option(
            Opt::new("onedash")
                .description("POPT_ARGFLAG_ONEDASH: Option takes a single -")
                .onedash()
        )
        .option(
            Opt::new("optional")
                .arg_type(ArgType::String)
                .optional()
                .arg_description("STRING")
                .description("POPT_ARGFLAG_OPTIONAL: Takes an optional string argument")
        )
        .option(
            Opt::val("val", 125992)
                .show_default()
                .default_val(141421i32)
                .description("POPT_ARG_VAL: 125992 141421")
        )
        .option(
            Opt::new("int")
                .short('i')
                .arg_type(ArgType::Int)
                .arg_description("INT")
                .description("POPT_ARG_INT: 271828")
                .default_val(271828i32)
                .show_default()
        )
        .option(
            Opt::new("short")
                .short('s')
                .arg_type(ArgType::Short)
                .arg_description("SHORT")
                .description("POPT_ARG_SHORT: 4523")
                .default_val(4523i16)
                .show_default()
        )
        .option(
            Opt::new("long")
                .short('l')
                .arg_type(ArgType::Long)
                .arg_description("LONG")
                .description("POPT_ARG_LONG: 738905609")
                .default_val(738905609i64)
                .show_default()
        )
        .option(
            Opt::new("longlong")
                .short('L')
                .arg_type(ArgType::LongLong)
                .arg_description("LONGLONG")
                .description("POPT_ARG_LONGLONG: 738905609")
                .default_val(738905609i64)
                .show_default()
        )
        .option(
            Opt::new("float")
                .short('f')
                .arg_type(ArgType::Float)
                .arg_description("FLOAT")
                .description("POPT_ARG_FLOAT: 3.14159")
                .default_val(3.1415926535f32)
                .show_default()
        )
        .option(
            Opt::new("double")
                .short('d')
                .arg_type(ArgType::Double)
                .arg_description("DOUBLE")
                .description("POPT_ARG_DOUBLE: 9.8696")
                .default_val(9.86960440108935861883f64)
                .show_default()
        )
        .option(
            Opt::new("randint")
                .arg_type(ArgType::Int)
                .random()
                .arg_description("INT")
                .description("POPT_ARGFLAG_RANDOM: experimental")
        )
        .option(
            Opt::new("randshort")
                .arg_type(ArgType::Short)
                .random()
                .arg_description("SHORT")
                .description("POPT_ARGFLAG_RANDOM: experimental")
        )
        .option(
            Opt::new("randlong")
                .arg_type(ArgType::Long)
                .random()
                .arg_description("LONG")
                .description("POPT_ARGFLAG_RANDOM: experimental")
        )
        .option(
            Opt::new("randlonglong")
                .arg_type(ArgType::LongLong)
                .random()
                .arg_description("LONGLONG")
                .description("POPT_ARGFLAG_RANDOM: experimental")
        )
        .option(
            Opt::new("argv")
                .arg_type(ArgType::Argv)
                .arg_description("STRING")
                .description("POPT_ARG_ARGV: append string to argv array (can be used multiple times)")
        )
        .option(
            Opt::val("bitset", 0x7777)
                .store_as("aflag")
                .default_val(0x8aceu32)
                .bit_or()
                .toggle()
                .show_default()
                .description("POPT_BIT_SET: |= 0x7777")
        )
        .option(
            Opt::val("bitclr", 0xf842u32 as i32)
                .store_as("aflag")
                .bit_nand()
                .toggle()
                .show_default()
                .description("POPT_BIT_CLR: &= ~0xf842")
        )
        .option(
            Opt::val("bitxor", (0x8aceu32 ^ 0xfeedu32) as i32)
                .store_as("aflag")
                .bit_xor()
                .show_default()
                .description("POPT_ARGFLAG_XOR: ^= (0x8ace^0xfeed)")
        )
        .option(
            Opt::new("nstr")
                .arg_type(ArgType::String)
                .show_default()
                .arg_description("STRING")
                .description("POPT_ARG_STRING: (null)")
        )
        .option(
            Opt::new("lstr")
                .arg_type(ArgType::String)
                .default_val("This tests default strings and exceeds the ... limit. 123456789+123456789+123456789+123456789+123456789+ 123456789+123456789+123456789+123456789+123456789+ 123456789+123456789+123456789+123456789+123456789+ 123456789+123456789+123456789+123456789+123456789+ ")
                .show_default()
                .arg_description("STRING")
                .description("POPT_ARG_STRING: \"123456789...\"")
        )
        .option(
            Opt::new("bits")
                .arg_type(ArgType::BitSet)
                .doc_hidden()
                .arg_description("STRING")
                .description("POPT_ARG_BITSET: bits")
        )
        .include_table(inc_table, None)
        .include_table(callback_table, Some("Callback arguments"))
        .auto_alias()
        .auto_help();

    // Create and parse context
    let mut ctx = Context::builder("test1")
        .options(opts)
        .config_file("test-poptrc")?
        .exec_path(".", true)
        .default_config(true)
        .build()?;

    ctx.parse()?;

    // Print results
    let arg1: i32 = ctx.get("arg1").unwrap_or(0);
    let arg2: String = ctx.get("arg2").unwrap_or_else(|_| "(none)".to_string());
    print!("arg1: {} arg2: {}", arg1, arg2);

    if ctx.is_present("arg3") {
        let arg3: i32 = ctx.get("arg3")?;
        print!(" arg3: {}", arg3);
    }

    if ctx.is_present("inc") {
        print!(" inc: {}", ctx.get::<i32>("inc")?);
    }

    if ctx.is_present("onedash") {
        print!(" short: {}", ctx.get::<i32>("onedash")?);
    }

    if ctx.is_present("int") {
        print!(" aInt: {}", ctx.get::<i32>("int")?);
    }

    if ctx.is_present("short") {
        print!(" aShort: {}", ctx.get::<i16>("short")?);
    }

    if ctx.is_present("long") {
        print!(" aLong: {}", ctx.get::<i64>("long")?);
    }

    if ctx.is_present("longlong") {
        print!(" aLongLong: {}", ctx.get::<i64>("longlong")?);
    }

    if ctx.is_present("float") {
        print!(" aFloat: {}", ctx.get::<f32>("float")?);
    }

    if ctx.is_present("double") {
        print!(" aDouble: {}", ctx.get::<f64>("double")?);
    }

    // Optional string
    if ctx.is_present("optional") {
        match ctx.get::<String>("optional") {
            Ok(s) => print!(" oStr: {}", s),
            Err(_) => print!(" oStr: (none)"),
        }
    }

    // ARGV accumulation
    if ctx.is_present("argv") {
        let argv_vals: Vec<String> = ctx.get("argv")?;
        print!(" aArgv:");
        for v in &argv_vals {
            print!(" {}", v);
        }
    }

    // Flags (shared storage "aflag")
    let aflag: u32 = ctx.get("aflag").unwrap_or(0x8ace);
    if aflag != 0x8ace {
        print!(" aFlag: 0x{:x}", aflag);
    }

    // Bloom filter bits
    if ctx.is_present("bits") {
        let bits: BloomFilter = ctx.get("bits")?;
        let attributes = ["foo", "bar", "baz", "bing", "bang", "boom"];
        let mut separator = " ";
        print!(" aBits:");
        for attr in &attributes {
            if !bits.contains(attr) {
                continue;
            }
            print!("{}{}", separator, attr);
            separator = ",";
        }
    }

    // Print remaining arguments
    let remaining = ctx.args();
    if !remaining.is_empty() {
        print!(" rest:");
        for arg in &remaining {
            print!(" {}", arg);
        }
    }

    println!();
    Ok(())
}
