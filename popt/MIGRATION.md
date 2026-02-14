# Migrating from C popt to Rust Native popt

This guide explains how to port C programs that use the popt library to the
Rust native module (`popt::native`). The native module is a pure Rust
reimplementation of popt with an idiomatic API — no FFI, no unsafe code, no
raw pointers.

## Table of Contents

- [Quick Start](#quick-start)
- [Key Differences](#key-differences)
- [Option Tables](#option-tables)
- [Argument Types](#argument-types)
- [Option Flags](#option-flags)
- [Context Creation and Parsing](#context-creation-and-parsing)
- [Retrieving Values](#retrieving-values)
- [Callbacks](#callbacks)
- [Config Files and Aliases](#config-files-and-aliases)
- [Auto Help and Usage](#auto-help-and-usage)
- [Bloom Filters (Bit Sets)](#bloom-filters-bit-sets)
- [String Utilities](#string-utilities)
- [Error Handling](#error-handling)
- [Complete Example](#complete-example)
- [API Reference Map](#api-reference-map)

## Quick Start

**C:**
```c
#include <popt.h>

int verbose = 0;
char *output = NULL;

struct poptOption options[] = {
    { "verbose", 'v', POPT_ARG_NONE, &verbose, 0,
      "Enable verbose output", NULL },
    { "output", 'o', POPT_ARG_STRING, &output, 0,
      "Output file", "FILE" },
    POPT_AUTOHELP
    POPT_TABLEEND
};

int main(int argc, const char **argv) {
    poptContext ctx = poptGetContext("myapp", argc, argv, options, 0);
    int rc;
    while ((rc = poptGetNextOpt(ctx)) > 0) {}
    if (rc < -1) {
        fprintf(stderr, "%s: %s: %s\n",
            poptBadOption(ctx, 0), poptStrerror(rc),
            poptGetInvocationName(ctx));
        return 1;
    }
    const char **args = poptGetArgs(ctx);
    poptFreeContext(ctx);
    return 0;
}
```

**Rust:**
```rust
use popt::native::*;

fn main() {
    let opts = OptionTable::new()
        .option(
            Opt::new("verbose")
                .short('v')
                .description("Enable verbose output")
        )
        .option(
            Opt::new("output")
                .short('o')
                .arg_type(ArgType::String)
                .arg_description("FILE")
                .description("Output file")
        )
        .auto_help();

    let mut ctx = Context::builder("myapp")
        .options(opts)
        .build()
        .unwrap();

    if let Err(e) = ctx.parse() {
        eprintln!("{}", e);
        std::process::exit(1);
    }

    let verbose: bool = ctx.get("verbose").unwrap_or(false);
    let output: String = ctx.get("output").unwrap_or_else(|_| String::new());
    let args = ctx.args();
}
```

## Key Differences

| Aspect | C popt | Rust native |
|--------|--------|-------------|
| Value storage | Pointer to caller's variable (`void *arg`) | Internal storage, retrieved via `ctx.get::<T>("name")` |
| Option table | Array of `struct poptOption` with sentinel | Builder pattern: `OptionTable::new().option(...)` |
| Flags | Bitfield constants (`POPT_ARGFLAG_*`) | Method calls (`.toggle()`, `.show_default()`) |
| Arg types | Integer constants (`POPT_ARG_INT`, etc.) | Enum: `ArgType::Int`, `ArgType::String`, etc. |
| Parsing loop | Manual `while (poptGetNextOpt(ctx) > 0)` | Single call: `ctx.parse()` |
| Error handling | Integer return codes | `Result<T, Error>` with the `?` operator |
| Memory management | Manual `poptFreeContext()` | Automatic (RAII) |
| Include tables | `POPT_ARG_INCLUDE_TABLE` entry in array | `.include_table(sub_table, description)` |
| Callbacks | Function pointer + `POPT_ARG_CALLBACK` entry | Closure: `.callback(\|arg, data\| { ... })` |

## Option Tables

### C: Static Array

```c
struct poptOption options[] = {
    { "verbose", 'v', POPT_ARG_NONE, &verbose, 0,
      "Enable verbose output", NULL },
    { "count",   'c', POPT_ARG_INT,  &count,   0,
      "Set count",            "NUM" },
    POPT_AUTOHELP
    POPT_TABLEEND
};
```

### Rust: Builder Pattern

```rust
let opts = OptionTable::new()
    .option(
        Opt::new("verbose")
            .short('v')
            .description("Enable verbose output")
    )
    .option(
        Opt::new("count")
            .short('c')
            .arg_type(ArgType::Int)
            .arg_description("NUM")
            .description("Set count")
    )
    .auto_help();
```

Each field of `struct poptOption` maps to a method on `Opt`:

| C field | Rust method | Notes |
|---------|-------------|-------|
| `longName` | First argument to `Opt::new("name")` | Required |
| `shortName` | `.short('c')` | Optional |
| `argInfo` type bits | `.arg_type(ArgType::Int)` | Default: `ArgType::None` |
| `argInfo` flag bits | `.toggle()`, `.show_default()`, etc. | See [Option Flags](#option-flags) |
| `arg` (pointer) | Not needed | Values stored internally |
| `val` | `.set_val(n)` | For callbacks; for VAL options use `Opt::val()` |
| `descrip` | `.description("text")` | For `--help` output |
| `argDescrip` | `.arg_description("ARG")` | For `--help` and `--usage` output |

### Include Tables

**C:**
```c
struct poptOption subTableOptions[] = { ... POPT_TABLEEND };

struct poptOption mainOptions[] = {
    { NULL, '\0', POPT_ARG_INCLUDE_TABLE, subTableOptions,
      0, "Sub-table description", NULL },
    ...
};
```

**Rust:**
```rust
let sub_table = OptionTable::new()
    .option(Opt::new("sub-opt").description("A sub option"));

let opts = OptionTable::new()
    .include_table(sub_table, Some("Sub-table description"))
    .option(Opt::new("main-opt").description("A main option"))
    .auto_help();
```

### Special Table Entries

| C Macro | Rust Method |
|---------|-------------|
| `POPT_AUTOHELP` | `.auto_help()` |
| `POPT_AUTOALIAS` | `.auto_alias()` |
| `POPT_TABLEEND` | Not needed (builder pattern) |

## Argument Types

| C Constant | Rust Enum | Rust Retrieval Type | Notes |
|------------|-----------|---------------------|-------|
| `POPT_ARG_NONE` | `ArgType::None` (default) | `bool` or `i32` | Flag option, no argument taken |
| `POPT_ARG_STRING` | `ArgType::String` | `String` | |
| `POPT_ARG_INT` | `ArgType::Int` | `i32` | |
| `POPT_ARG_SHORT` | `ArgType::Short` | `i16` | |
| `POPT_ARG_LONG` | `ArgType::Long` | `i64` | |
| `POPT_ARG_LONGLONG` | `ArgType::LongLong` | `i64` | |
| `POPT_ARG_FLOAT` | `ArgType::Float` | `f32` | |
| `POPT_ARG_DOUBLE` | `ArgType::Double` | `f64` | |
| `POPT_ARG_VAL` | `ArgType::Val(i32)` via `Opt::val()` | `i32` or `u32` | Stores constant value when triggered |
| `POPT_ARG_ARGV` | `ArgType::Argv` | `Vec<String>` | Accumulates multiple values |
| `POPT_ARG_BITSET` | `ArgType::BitSet` | `BloomFilter` | Bloom filter bit set |
| `POPT_ARG_INCLUDE_TABLE` | `.include_table()` | N/A | Table-level, not per-option |
| `POPT_ARG_CALLBACK` | `.callback()` | N/A | Table-level, not per-option |

### POPT_ARG_VAL

VAL options store a predetermined constant value when the option is triggered,
rather than reading a value from the command line.

**C:**
```c
int flag = 0;
{ "enable", '\0', POPT_ARG_VAL, &flag, 42, "Enable feature", NULL }
```

**Rust:**
```rust
.option(Opt::val("enable", 42).description("Enable feature"))
// Retrieve:
let flag: i32 = ctx.get("enable").unwrap_or(0);
```

### POPT_ARG_VAL with Bit Operations (Shared Storage)

In C, multiple options write to the same variable via the `arg` pointer. In
Rust, use `.store_as("shared_name")` to direct multiple options to the same
storage key.

**C:**
```c
unsigned int flags = 0x8ace;
{ "bitset", '\0', POPT_BIT_SET,              &flags, 0x7777, "Set bits", NULL },
{ "bitclr", '\0', POPT_BIT_CLR,              &flags, 0xf842, "Clear bits", NULL },
{ "bitxor", '\0', POPT_ARG_VAL|POPT_ARGFLAG_XOR, &flags, 0x7643, "XOR bits", NULL },
```

**Rust:**
```rust
.option(
    Opt::val("bitset", 0x7777)
        .store_as("flags")
        .default_val(0x8aceu32)
        .bit_or()
        .toggle()
)
.option(
    Opt::val("bitclr", 0xf842u32 as i32)
        .store_as("flags")
        .bit_nand()
        .toggle()
)
.option(
    Opt::val("bitxor", 0x7643)
        .store_as("flags")
        .bit_xor()
)
// Retrieve:
let flags: u32 = ctx.get("flags").unwrap_or(0x8ace);
```

Bit operation methods:

| C Flag | Rust Method | Operation |
|--------|-------------|-----------|
| `POPT_ARGFLAG_OR` / `POPT_BIT_SET` | `.bit_or()` | `current \|= value` |
| `POPT_ARGFLAG_NAND` / `POPT_BIT_CLR` | `.bit_nand()` | `current &= !value` |
| `POPT_ARGFLAG_XOR` | `.bit_xor()` | `current ^= value` |

## Option Flags

| C Flag | Rust Method | Description |
|--------|-------------|-------------|
| `POPT_ARGFLAG_ONEDASH` | `.onedash()` | Allow `-longopt` (single dash) |
| `POPT_ARGFLAG_DOC_HIDDEN` | `.doc_hidden()` | Hide from `--help` / `--usage` |
| `POPT_ARGFLAG_OPTIONAL` | `.optional()` | Argument value is optional |
| `POPT_ARGFLAG_SHOW_DEFAULT` | `.show_default()` | Show default in `--help` |
| `POPT_ARGFLAG_TOGGLE` | `.toggle()` | Allow `--[no]opt` prefix toggle |
| `POPT_ARGFLAG_RANDOM` | `.random()` | Generate random value (experimental) |
| `POPT_ARGFLAG_OR` | `.bit_or()` | Bitwise OR operation |
| `POPT_ARGFLAG_NAND` | `.bit_nand()` | Bitwise NAND operation |
| `POPT_ARGFLAG_XOR` | `.bit_xor()` | Bitwise XOR operation |

## Context Creation and Parsing

### C: Multi-Step Manual Process

```c
poptContext ctx = poptGetContext("myapp", argc, argv, options, 0);
poptSetExecPath(ctx, ".", 1);
poptReadConfigFile(ctx, "myapp-rc");
poptReadDefaultConfig(ctx, 1);

int rc;
while ((rc = poptGetNextOpt(ctx)) > 0) {
    /* handle return values from options with non-zero val */
}
if (rc < -1) {
    fprintf(stderr, "%s: %s: %s\n",
        poptBadOption(ctx, 0), poptStrerror(rc),
        poptGetInvocationName(ctx));
    exit(1);
}

const char **remaining = poptGetArgs(ctx);
poptFreeContext(ctx);
```

### Rust: Builder + Single Parse Call

```rust
let mut ctx = Context::builder("myapp")
    .options(opts)
    .config_file("myapp-rc")?
    .exec_path(".", true)
    .default_config(true)
    .build()?;

ctx.parse()?;  // Errors are returned via Result

let remaining = ctx.args();
// ctx is automatically freed when it goes out of scope
```

### ContextBuilder Methods

| C Function | Rust Method |
|------------|-------------|
| `poptGetContext(name, argc, argv, opts, flags)` | `Context::builder(name).options(opts)` |
| `poptReadConfigFile(ctx, path)` | `.config_file(path)?` |
| `poptSetExecPath(ctx, path, allowAbsolute)` | `.exec_path(path, allow_absolute)` |
| `poptReadDefaultConfig(ctx, useEnv)` | `.default_config(use_env)` |
| `.build()` | Constructs the `Context` |

Note: `argv` is read automatically from `std::env::args()` — you do not pass
`argc`/`argv` explicitly.

## Retrieving Values

The biggest API difference: C popt writes values through pointers to your
variables. Rust native stores values internally and you retrieve them by name.

### C: Pointer-Based

```c
int count = 0;
char *name = NULL;
float ratio = 1.0;

struct poptOption options[] = {
    { "count", 'c', POPT_ARG_INT,    &count, 0, "Count", "N" },
    { "name",  'n', POPT_ARG_STRING, &name,  0, "Name", "STR" },
    { "ratio", 'r', POPT_ARG_FLOAT,  &ratio, 0, "Ratio", "F" },
    POPT_TABLEEND
};

/* After parsing, count/name/ratio are populated directly */
printf("count=%d name=%s ratio=%f\n", count, name ? name : "(null)", ratio);
```

### Rust: Typed Retrieval

```rust
let opts = OptionTable::new()
    .option(Opt::new("count").short('c').arg_type(ArgType::Int)
        .default_val(0i32).arg_description("N").description("Count"))
    .option(Opt::new("name").short('n').arg_type(ArgType::String)
        .arg_description("STR").description("Name"))
    .option(Opt::new("ratio").short('r').arg_type(ArgType::Float)
        .default_val(1.0f32).arg_description("F").description("Ratio"));

// After parsing:
let count: i32 = ctx.get("count").unwrap_or(0);
let name: String = ctx.get("name").unwrap_or_else(|_| "(null)".into());
let ratio: f32 = ctx.get("ratio").unwrap_or(1.0);
```

### Checking Presence

To distinguish "not given" from "given with default value", use `is_present()`:

**C:**
```c
/* C popt doesn't directly support this; you'd use a sentinel value
   or check if the option was seen in the poptGetNextOpt() loop */
```

**Rust:**
```rust
if ctx.is_present("name") {
    let name: String = ctx.get("name")?;
    println!("name was given: {}", name);
}
```

This is especially useful with `POPT_ARGFLAG_OPTIONAL` (`.optional()`):

```rust
.option(
    Opt::new("output")
        .arg_type(ArgType::String)
        .optional()
        .arg_description("FILE")
        .description("Output (optional filename)")
)

// After parsing:
if ctx.is_present("output") {
    match ctx.get::<String>("output") {
        Ok(file) => println!("output to {}", file),
        Err(_) => println!("output to stdout"),  // --output given without value
    }
}
```

### Default Values

**C:**
```c
int port = 8080;  /* default set in variable declaration */
{ "port", 'p', POPT_ARG_INT, &port, 0, "Port", "NUM" }
```

**Rust:**
```rust
Opt::new("port")
    .short('p')
    .arg_type(ArgType::Int)
    .default_val(8080i32)
    .arg_description("NUM")
    .description("Port")
```

When `.show_default()` is also set, the default value appears in `--help`
output as `(default: 8080)`.

### Supported Retrieval Types

| Call | Returns | For ArgType |
|------|---------|-------------|
| `ctx.get::<i32>("x")` | `Result<i32>` | `Int`, `None` (as 0/1), `Val` |
| `ctx.get::<u32>("x")` | `Result<u32>` | `Val` with bit ops |
| `ctx.get::<i16>("x")` | `Result<i16>` | `Short` |
| `ctx.get::<i64>("x")` | `Result<i64>` | `Long`, `LongLong` |
| `ctx.get::<f32>("x")` | `Result<f32>` | `Float` |
| `ctx.get::<f64>("x")` | `Result<f64>` | `Double` |
| `ctx.get::<bool>("x")` | `Result<bool>` | `None` |
| `ctx.get::<String>("x")` | `Result<String>` | `String` |
| `ctx.get::<Vec<String>>("x")` | `Result<Vec<String>>` | `Argv` |
| `ctx.get::<BloomFilter>("x")` | `Result<BloomFilter>` | `BitSet` |

## Callbacks

### C: Function Pointer at Table Head

```c
static void my_callback(poptContext con,
    enum poptCallbackReason reason,
    const struct poptOption *opt,
    const char *arg, const void *data)
{
    printf("callback: %s %s\n", (const char *)data, arg ? arg : "");
}

struct poptOption callbackTable[] = {
    { NULL, '\0', POPT_ARG_CALLBACK | POPT_CBFLAG_INC_DATA,
      (void *)my_callback, 0, NULL, NULL },
    { "cb-opt", 'c', POPT_ARG_STRING, NULL, 0,
      "Callback option", "ARG" },
    POPT_TABLEEND
};

/* Include in main table */
{ NULL, '\0', POPT_ARG_INCLUDE_TABLE, callbackTable,
  0, "data string for INC_DATA", NULL }
```

### Rust: Closure on OptionTable

```rust
// Standard callback (data comes from .callback() second argument)
let cb_table = OptionTable::new()
    .callback(|arg, data| {
        println!("callback: {} {}",
            data.unwrap_or(""), arg.unwrap_or(""));
        Ok(())
    }, Some("sampledata"))
    .option(
        Opt::new("cb-opt")
            .short('c')
            .arg_type(ArgType::String)
            .description("Callback option")
    );

// INC_DATA callback (data comes from include_table description)
let cb2_table = OptionTable::new()
    .callback_inc_data(|arg, data| {
        println!("callback: {} {}",
            data.unwrap_or(""), arg.unwrap_or(""));
        Ok(())
    })
    .option(
        Opt::new("cb2-opt")
            .short('c')
            .arg_type(ArgType::String)
            .description("Callback option")
    );

// Include with data string (becomes callback data for INC_DATA)
let opts = OptionTable::new()
    .include_table(cb2_table, Some("data string for INC_DATA"))
    .auto_help();
```

| C Pattern | Rust Pattern |
|-----------|--------------|
| `POPT_ARG_CALLBACK` entry, data in `descrip` field | `.callback(closure, Some("data"))` |
| `POPT_CBFLAG_INC_DATA` flag | `.callback_inc_data(closure)` — data comes from `include_table` description |

### Callback Signature

**C:**
```c
void (*callback)(poptContext con,
    enum poptCallbackReason reason,
    const struct poptOption *opt,
    const char *arg,
    const void *data);
```

**Rust:**
```rust
Fn(Option<&str>, Option<&str>) -> Result<()>
//  ^arg value    ^data string
```

The Rust callback is simpler: it receives the argument value and the data
string. The context and option details are not passed (they are rarely needed
in practice).

## Config Files and Aliases

### Config File Format

Config files define aliases and exec entries. The format is unchanged:

```
# Comments start with #
appname alias --option-name  expansion args...
appname exec  --option-name  /path/to/executable
```

### C: Manual Loading

```c
poptContext ctx = poptGetContext("myapp", argc, argv, opts, 0);
poptReadConfigFile(ctx, "myapp-rc");
poptSetExecPath(ctx, "/usr/lib/myapp", 1);
poptReadDefaultConfig(ctx, 1);
```

### Rust: Builder Methods

```rust
let mut ctx = Context::builder("myapp")
    .options(opts)
    .config_file("myapp-rc")?
    .exec_path("/usr/lib/myapp", true)
    .default_config(true)
    .build()?;
```

### Alias Meta-Options

Aliases can embed `--POPTdesc=` and `--POPTargs=` to provide help text:

```
myapp alias --simple --arg2 "simple description" --POPTdesc=$"an alias" --POPTargs=$ARG
```

This works identically in both C and Rust. The `--POPTdesc` text appears in
`--help`, and `--POPTargs` text appears as the argument descriptor.

## Auto Help and Usage

### C: Macros

```c
struct poptOption options[] = {
    /* ... your options ... */
    POPT_AUTOALIAS  /* adds "Options implemented via popt alias/exec:" section */
    POPT_AUTOHELP   /* adds --help and --usage */
    POPT_TABLEEND
};
```

### Rust: Builder Methods

```rust
let opts = OptionTable::new()
    .option(/* ... */)
    .auto_alias()
    .auto_help();
```

Both `--help` and `--usage` trigger automatic output and `exit(0)`, matching
C popt behavior.

## Bloom Filters (Bit Sets)

The native module includes a full Bloom filter implementation compatible with
C popt's `poptBits*` functions, using the same Bob Jenkins lookup3 hash.

### C: Opaque poptBits Pointer

```c
poptBits bits = NULL;
poptBitsAdd(bits, "foo");
if (poptBitsChk(bits, "foo")) { /* found */ }
poptBitsDel(bits, "foo");
poptBitsClr(bits);

/* As an option type */
{ "bits", '\0', POPT_ARG_BITSET, &bits, 0, "Bit set", "STRING" }
/* Usage: --bits=foo,bar,baz or --bits=!foo to remove */
```

### Rust: BloomFilter Struct

```rust
let mut bf = BloomFilter::new();               // default sizing
let mut bf = BloomFilter::with_sizing(k, n);   // custom K/N

bf.insert("foo");
bf.contains("foo");  // -> true
bf.remove("foo");
bf.clear();

// Set operations
let mut a = BloomFilter::new();
let b = BloomFilter::new();
a.union(&b);                       // a |= b
let has_common = a.intersect(&b);  // a &= b, returns true if any bits set

// Comma-separated parsing (matches poptSaveBits behavior)
bf.save_bits("foo,bar,baz");    // insert foo, bar, baz
bf.save_bits("!foo");           // remove foo
```

| C Function | Rust Method |
|------------|-------------|
| `poptBitsAdd(bits, s)` | `bf.insert(s)` |
| `poptBitsChk(bits, s)` | `bf.contains(s)` |
| `poptBitsDel(bits, s)` | `bf.remove(s)` |
| `poptBitsClr(bits)` | `bf.clear()` |
| `poptBitsUnion(&a, b)` | `a.union(&b)` |
| `poptBitsIntersect(&a, b)` | `a.intersect(&b)` |
| `poptSaveBits(&bits, argInfo, s)` | `bf.save_bits(s)` |

### As an Option

**C:**
```c
poptBits bits = NULL;
{ "bits", '\0', POPT_ARG_BITSET, &bits, 0, "Bit set", "STRING" }
```

**Rust:**
```rust
.option(
    Opt::new("bits")
        .arg_type(ArgType::BitSet)
        .arg_description("STRING")
        .description("Bit set")
)

// After parsing:
if ctx.is_present("bits") {
    let bits: BloomFilter = ctx.get("bits")?;
    if bits.contains("foo") { /* ... */ }
}
```

### Standalone Use (e.g., Dictionary Checking)

```rust
use popt::native::BloomFilter;

// Size for 100,000 items with 10 hash functions
let k = 10;
let n = 2 * k * 100_000;
let mut bf = BloomFilter::with_sizing(k, n);

// Load dictionary
for word in words {
    bf.insert(word);
}

// Query
if bf.contains("hello") {
    println!("probably in dictionary");
}
```

## String Utilities

### config_file_to_string (poptConfigFileToString)

Converts a key=value config file into command-line argument form.

**C:**
```c
FILE *fp = fopen("config.ini", "r");
char *argstr = NULL;
poptConfigFileToString(fp, &argstr, 0);
/* argstr = " --key1=\"val1\" --key2=\"val2\"" */
free(argstr);
```

**Rust:**
```rust
let argstr = config_file_to_string("config.ini")?;
// argstr = " --key1=\"val1\" --key2=\"val2\""
```

### parse_argv_string (poptParseArgvString)

Splits a command-line string into an argument vector, handling quoting.

**C:**
```c
int argc;
const char **argv;
poptParseArgvString("--foo \"bar baz\" --qux", &argc, &argv);
/* argv = ["--foo", "bar baz", "--qux"] */
free(argv);
```

**Rust:**
```rust
let args = parse_argv_string("--foo \"bar baz\" --qux")?;
// args = vec!["--foo", "bar baz", "--qux"]
```

## Error Handling

### C: Integer Error Codes

```c
#define POPT_ERROR_NOARG       -10
#define POPT_ERROR_BADOPT      -11
#define POPT_ERROR_BADQUOTE    -15
#define POPT_ERROR_BADNUMBER   -17
#define POPT_ERROR_UNWANTEDARG -23

int rc = poptGetNextOpt(ctx);
if (rc < -1) {
    fprintf(stderr, "%s: %s\n",
        poptBadOption(ctx, 0), poptStrerror(rc));
}
```

### Rust: Error Enum with Result

```rust
pub enum Error {
    BadOption(String),      // POPT_ERROR_BADOPT
    MissingArg(String),     // POPT_ERROR_NOARG
    UnwantedArg(String),    // POPT_ERROR_UNWANTEDARG
    BadNumber(String),      // POPT_ERROR_BADNUMBER
    BadQuote(String),       // POPT_ERROR_BADQUOTE
    ConfigFile(String),     // POPT_ERROR_ERRNO
    NotFound(String),       // Option name not found in stored values
    Other(String),          // Catch-all
}
```

Use `?` for propagation and `match` for specific handling:

```rust
match ctx.parse() {
    Ok(()) => {},
    Err(Error::BadOption(msg)) => {
        eprintln!("{}", msg);
        std::process::exit(1);
    }
    Err(e) => {
        eprintln!("{}", e);
        std::process::exit(2);
    }
}
```

Error messages are formatted identically to C popt:
- `"myapp: bad argument --foo: unknown option"`
- `"myapp: bad argument --count: missing argument"`
- `"myapp: bad argument --count: invalid numeric value"`

## Complete Example

A full port of a C program to Rust native:

### C Original

```c
#include <popt.h>
#include <stdio.h>

int main(int argc, const char **argv) {
    int debug = 0;
    int verbose = 1;
    char *output = NULL;
    int count = 10;

    struct poptOption options[] = {
        { "debug",   'd', POPT_BIT_SET|POPT_ARGFLAG_TOGGLE,
          &debug, 1, "Enable debug", NULL },
        { "verbose", 'v', POPT_BIT_SET|POPT_ARGFLAG_TOGGLE,
          &verbose, 1, "Enable verbose", NULL },
        { "output",  'o', POPT_ARG_STRING,
          &output, 0, "Output file", "FILE" },
        { "count",   'c', POPT_ARG_INT|POPT_ARGFLAG_SHOW_DEFAULT,
          &count, 0, "Repeat count", "N" },
        POPT_AUTOHELP
        POPT_TABLEEND
    };

    poptContext ctx = poptGetContext("myapp", argc, argv, options, 0);
    int rc;
    while ((rc = poptGetNextOpt(ctx)) > 0) {}
    if (rc < -1) {
        fprintf(stderr, "%s: %s\n",
            poptBadOption(ctx, 0), poptStrerror(rc));
        return 1;
    }

    const char **args = poptGetArgs(ctx);
    printf("debug=%d verbose=%d output=%s count=%d\n",
        debug, verbose, output ? output : "(none)", count);
    if (args) {
        printf("args:");
        while (*args) printf(" %s", *args++);
        printf("\n");
    }

    poptFreeContext(ctx);
    return 0;
}
```

### Rust Native Port

```rust
use popt::native::*;

fn main() {
    let opts = OptionTable::new()
        .option(
            Opt::val("debug", 1)
                .short('d')
                .bit_or()
                .toggle()
                .description("Enable debug")
        )
        .option(
            Opt::val("verbose", 1)
                .short('v')
                .bit_or()
                .toggle()
                .description("Enable verbose")
        )
        .option(
            Opt::new("output")
                .short('o')
                .arg_type(ArgType::String)
                .arg_description("FILE")
                .description("Output file")
        )
        .option(
            Opt::new("count")
                .short('c')
                .arg_type(ArgType::Int)
                .default_val(10i32)
                .show_default()
                .arg_description("N")
                .description("Repeat count")
        )
        .auto_help();

    let mut ctx = match Context::builder("myapp")
        .options(opts)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(2);
        }
    };

    if let Err(e) = ctx.parse() {
        eprintln!("{}", e);
        std::process::exit(1);
    }

    let debug: i32 = ctx.get("debug").unwrap_or(0);
    let verbose: i32 = ctx.get("verbose").unwrap_or(1);
    let output: String = ctx.get("output")
        .unwrap_or_else(|_| "(none)".into());
    let count: i32 = ctx.get("count").unwrap_or(10);

    println!("debug={} verbose={} output={} count={}",
        debug, verbose, output, count);

    let args = ctx.args();
    if !args.is_empty() {
        print!("args:");
        for a in &args {
            print!(" {}", a);
        }
        println!();
    }
}
```

## API Reference Map

### Functions

| C Function | Rust Equivalent |
|------------|-----------------|
| `poptGetContext()` | `Context::builder(name).options(opts).build()` |
| `poptFreeContext()` | Automatic (drop) |
| `poptResetContext()` | Not yet implemented |
| `poptGetNextOpt()` | `ctx.parse()` (all-at-once) |
| `poptGetOptArg()` | Not needed (values stored internally) |
| `poptGetArg()` | `ctx.args()` (returns all at once) |
| `poptPeekArg()` | Not yet implemented |
| `poptGetArgs()` | `ctx.args()` |
| `poptBadOption()` | Error message includes option name |
| `poptStrerror()` | `Error` implements `Display` |
| `poptStuffArgs()` | Not yet implemented |
| `poptAddAlias()` | Config file loading (automatic) |
| `poptAddItem()` | Config file loading (automatic) |
| `poptReadConfigFile()` | `.config_file(path)?` on builder |
| `poptReadConfigFiles()` | Multiple `.config_file()` calls |
| `poptReadDefaultConfig()` | `.default_config(true)` on builder |
| `poptSetExecPath()` | `.exec_path(path, allow_absolute)` on builder |
| `poptPrintHelp()` | Automatic via `.auto_help()` and `--help` |
| `poptPrintUsage()` | Automatic via `.auto_help()` and `--usage` |
| `poptSetOtherOptionHelp()` | Not yet implemented |
| `poptGetInvocationName()` | Context name from builder |
| `poptSaneFile()` | Not exposed (internal) |
| `poptReadFile()` | Use `std::fs::read_to_string()` |
| `poptDupArgv()` | Not needed (Rust owns `Vec<String>`) |
| `poptParseArgvString()` | `parse_argv_string(s)` |
| `poptConfigFileToString()` | `config_file_to_string(path)` |
| `poptSaveString()` | Not exposed (internal to `ArgType::Argv`) |
| `poptSaveInt()` | Not exposed (internal to parser) |
| `poptSaveLong()` | Not exposed (internal to parser) |
| `poptSaveLongLong()` | Not exposed (internal to parser) |
| `poptSaveShort()` | Not exposed (internal to parser) |
| `poptSaveBits()` | `BloomFilter::save_bits(s)` |
| `poptBitsAdd()` | `bf.insert(s)` |
| `poptBitsChk()` | `bf.contains(s)` |
| `poptBitsDel()` | `bf.remove(s)` |
| `poptBitsClr()` | `bf.clear()` |
| `poptBitsUnion()` | `bf.union(&other)` |
| `poptBitsIntersect()` | `bf.intersect(&other)` |
| `poptBitsArgs()` | Not exposed |
| `poptStrippedArgv()` | Not yet implemented |

### Types

| C Type | Rust Type |
|--------|-----------|
| `poptContext` | `Context` |
| `struct poptOption` | `Opt` (builder) + `OptionTable` (collection) |
| `struct poptAlias` | Internal (loaded from config files) |
| `poptItem` | Internal |
| `poptBits` | `BloomFilter` |
| `poptCallbackType` | `Fn(Option<&str>, Option<&str>) -> Result<()>` |
| `enum poptCallbackReason` | Not needed (callbacks fire during parsing) |

### Constants to Methods

| C Constant(s) | Rust |
|----------------|------|
| `POPT_ARG_NONE` | `ArgType::None` (default) |
| `POPT_ARG_STRING` | `ArgType::String` |
| `POPT_ARG_INT` | `ArgType::Int` |
| `POPT_ARG_SHORT` | `ArgType::Short` |
| `POPT_ARG_LONG` | `ArgType::Long` |
| `POPT_ARG_LONGLONG` | `ArgType::LongLong` |
| `POPT_ARG_FLOAT` | `ArgType::Float` |
| `POPT_ARG_DOUBLE` | `ArgType::Double` |
| `POPT_ARG_VAL` | `Opt::val(name, value)` |
| `POPT_ARG_ARGV` | `ArgType::Argv` |
| `POPT_ARG_BITSET` | `ArgType::BitSet` |
| `POPT_ARG_INCLUDE_TABLE` | `.include_table()` |
| `POPT_ARG_CALLBACK` | `.callback()` / `.callback_inc_data()` |
| `POPT_ARGFLAG_ONEDASH` | `.onedash()` |
| `POPT_ARGFLAG_DOC_HIDDEN` | `.doc_hidden()` |
| `POPT_ARGFLAG_OPTIONAL` | `.optional()` |
| `POPT_ARGFLAG_SHOW_DEFAULT` | `.show_default()` |
| `POPT_ARGFLAG_TOGGLE` | `.toggle()` |
| `POPT_ARGFLAG_RANDOM` | `.random()` |
| `POPT_ARGFLAG_OR` / `POPT_BIT_SET` | `.bit_or()` |
| `POPT_ARGFLAG_NAND` / `POPT_BIT_CLR` | `.bit_nand()` |
| `POPT_ARGFLAG_XOR` | `.bit_xor()` |
| `POPT_CBFLAG_INC_DATA` | `.callback_inc_data()` |
| `POPT_AUTOHELP` | `.auto_help()` |
| `POPT_AUTOALIAS` | `.auto_alias()` |
| `POPT_TABLEEND` | Not needed |
| `POPT_ERROR_*` | `Error` enum variants |
| `POPT_CONTEXT_POSIXMEHARDER` | Automatic (`POSIXLY_CORRECT` env var detection) |
