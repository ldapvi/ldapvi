// Test binary (corresponds to test2 of the C codebase)

use popt::*;

fn main() -> Result<()> {
    // User options sub-table
    let user_table = OptionTable::new()
        .option(
            Opt::new("first")
                .short('f')
                .arg_type(ArgType::String)
                .description("user's first name")
                .arg_description("first"),
        )
        .option(
            Opt::new("last")
                .short('l')
                .arg_type(ArgType::String)
                .description("user's last name")
                .arg_description("last"),
        )
        .option(
            Opt::new("username")
                .short('u')
                .arg_type(ArgType::String)
                .description("system user name")
                .arg_description("user"),
        )
        .option(
            Opt::new("password")
                .short('p')
                .arg_type(ArgType::String)
                .description("system password name")
                .arg_description("password"),
        )
        .option(
            Opt::new("addr1")
                .short('1')
                .arg_type(ArgType::String)
                .description("line 1 of address")
                .arg_description("addr1"),
        )
        .option(
            Opt::new("addr2")
                .short('2')
                .arg_type(ArgType::String)
                .description("line 2 of address")
                .arg_description("addr2"),
        )
        .option(
            Opt::new("city")
                .short('c')
                .arg_type(ArgType::String)
                .description("city")
                .arg_description("city"),
        )
        .option(
            Opt::new("state")
                .short('s')
                .arg_type(ArgType::String)
                .description("state or province")
                .arg_description("state"),
        )
        .option(
            Opt::new("postal")
                .short('P')
                .arg_type(ArgType::String)
                .description("postal or zip code")
                .arg_description("postal"),
        )
        .option(
            Opt::new("zip")
                .short('z')
                .arg_type(ArgType::String)
                .store_as("postal") // Same storage as postal
                .description("postal or zip code")
                .arg_description("postal"),
        )
        .option(
            Opt::new("country")
                .short('C')
                .arg_type(ArgType::String)
                .description("two letter ISO country code")
                .arg_description("country"),
        )
        .option(
            Opt::new("email")
                .short('e')
                .arg_type(ArgType::String)
                .description("user's email address")
                .arg_description("email"),
        )
        .option(
            Opt::new("dayphone")
                .short('d')
                .arg_type(ArgType::String)
                .description("day time phone number")
                .arg_description("dayphone"),
        )
        .option(
            Opt::new("fax")
                .short('F')
                .arg_type(ArgType::String)
                .description("fax number")
                .arg_description("fax"),
        );

    // Transact options sub-table
    let transact_table = OptionTable::new()
        .option(
            Opt::new("keyfile")
                .arg_type(ArgType::String)
                .description("transact offer key file (flat_O.kf)")
                .arg_description("key-file"),
        )
        .option(
            Opt::new("offerfile")
                .arg_type(ArgType::String)
                .description("offer template file (osl.ofr)")
                .arg_description("offer-file"),
        )
        .option(
            Opt::new("storeid")
                .arg_type(ArgType::Int)
                .description("store id")
                .arg_description("store-id"),
        )
        .option(
            Opt::new("rcfile")
                .arg_type(ArgType::String)
                .description("default command line options (in popt format)")
                .arg_description("rcfile"),
        )
        .option(
            Opt::new("txhost")
                .arg_type(ArgType::String)
                .description("transact host")
                .arg_description("transact-host"),
        )
        .option(
            Opt::new("txsslport")
                .arg_type(ArgType::Int)
                .description("transact server ssl port ")
                .arg_description("transact ssl port"),
        )
        .option(
            Opt::new("cnhost")
                .arg_type(ArgType::String)
                .description("content host")
                .arg_description("content-host"),
        )
        .option(
            Opt::new("cnpath")
                .arg_type(ArgType::String)
                .description("content url path")
                .arg_description("content-path"),
        );

    // Database options sub-table
    let database_table = OptionTable::new()
        .option(
            Opt::new("dbpassword")
                .arg_type(ArgType::String)
                .description("Database password")
                .arg_description("DB password"),
        )
        .option(
            Opt::new("dbusername")
                .arg_type(ArgType::String)
                .description("Database user name")
                .arg_description("DB UserName"),
        );

    // Main options table
    let opts = OptionTable::new()
        .include_table(
            transact_table,
            Some("Transact Options (not all will apply)"),
        )
        .include_table(database_table, Some("Transact Database Names"))
        .include_table(user_table, Some("User Fields"))
        .auto_help();

    // Config file: check env var first, then default paths
    let mut builder = Context::builder("test2").options(opts);

    if let Ok(rcfile) = std::env::var("testpoptrc") {
        builder = builder.config_file(&rcfile)?;
    } else {
        builder = builder
            .config_file("test-poptrc")?
            .config_file("../../test-poptrc")?;
    }

    let mut ctx = builder.build()?;

    // Parse options, ignoring errors (matches C test2 behavior)
    let _ = ctx.parse();

    // Helper to get string or "(null)"
    fn s(ctx: &Context, name: &str) -> String {
        ctx.get::<String>(name)
            .unwrap_or_else(|_| "(null)".to_string())
    }

    // Print output matching C format
    println!(
        "dbusername {}\tdbpassword {}",
        s(&ctx, "dbusername"),
        s(&ctx, "dbpassword")
    );
    println!(
        "txhost {}\ttxsslport {}\ttxstoreid {}\tpathofkeyfile {}",
        s(&ctx, "txhost"),
        ctx.get::<i32>("txsslport").unwrap_or(443),
        ctx.get::<i32>("storeid").unwrap_or(0),
        s(&ctx, "keyfile")
    );
    println!(
        "username {}\tpassword {}\tfirstname {}\tlastname {}",
        s(&ctx, "username"),
        s(&ctx, "password"),
        s(&ctx, "first"),
        s(&ctx, "last")
    );
    println!(
        "addr1 {}\taddr2 {}\tcity {}\tstate {}\tpostal {}",
        s(&ctx, "addr1"),
        s(&ctx, "addr2"),
        s(&ctx, "city"),
        s(&ctx, "state"),
        s(&ctx, "postal")
    );
    println!(
        "country {}\temail {}\tdayphone {}\tfax {}",
        s(&ctx, "country"),
        s(&ctx, "email"),
        s(&ctx, "dayphone"),
        s(&ctx, "fax")
    );

    Ok(())
}
