//! Native Rust implementation of the popt API.
//!
//! Pure Rust command-line option parsing with a VISION-style API:
//! - `ctx.get::<T>("name")` for value retrieval (no raw pointers)
//! - `ArgType` enum for type-safe argument types
//! - Method-based flags (`.toggle()`, `.show_default()`, `.optional()`)
//! - Table-level callbacks with closures

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

// ============================================================================
// Result and Error types
// ============================================================================

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    BadOption(String),
    MissingArg(String),
    UnwantedArg(String),
    BadNumber(String),
    BadQuote(String),
    ConfigFile(String),
    NotFound(String),
    Other(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BadOption(s) => write!(f, "{}", s),
            Error::MissingArg(s) => write!(f, "{}", s),
            Error::UnwantedArg(s) => write!(f, "{}", s),
            Error::BadNumber(s) => write!(f, "{}", s),
            Error::BadQuote(s) => write!(f, "{}", s),
            Error::ConfigFile(s) => write!(f, "{}", s),
            Error::NotFound(s) => write!(f, "option not found: {}", s),
            Error::Other(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for Error {}

// ============================================================================
// ArgType — type-safe argument type enum
// ============================================================================

#[derive(Debug, Clone)]
pub enum ArgType {
    None,
    String,
    Int,
    Long,
    LongLong,
    Short,
    Float,
    Double,
    Val(i32),
    Argv,
    BitSet,
}

// ============================================================================
// BitOp — bit operation for VAL options
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub enum BitOp {
    Or,
    Nand,
    Xor,
}

// ============================================================================
// StoredValue — internal typed value storage
// ============================================================================

#[derive(Debug, Clone)]
#[doc(hidden)]
pub enum StoredValue {
    Bool(bool),
    Int(i32),
    Long(i64),
    LongLong(i64),
    Short(i16),
    Float(f32),
    Double(f64),
    Str(String),
    Argv(Vec<String>),
    Uint(u32),
    Bits(BloomFilter),
}

// ============================================================================
// Opt — option builder (VISION API)
// ============================================================================

pub type OptionCallback =
    Arc<dyn Fn(Option<&str>, Option<&str>) -> Result<()> + Send + Sync + 'static>;

pub struct Opt {
    long_name: String,
    short_name: Option<char>,
    arg_type: ArgType,
    bit_op: Option<BitOp>,
    val: Option<i32>,
    description: Option<String>,
    arg_description: Option<String>,
    default_value: Option<StoredValue>,
    store_name: Option<String>,
    flags_toggle: bool,
    flags_optional: bool,
    flags_onedash: bool,
    flags_doc_hidden: bool,
    flags_show_default: bool,
    flags_random: bool,
}

impl Opt {
    pub fn new(name: &str) -> Self {
        Opt {
            long_name: name.to_string(),
            short_name: None,
            arg_type: ArgType::None,
            bit_op: None,
            val: None,
            description: None,
            arg_description: None,
            default_value: None,
            store_name: None,
            flags_toggle: false,
            flags_optional: false,
            flags_onedash: false,
            flags_doc_hidden: false,
            flags_show_default: false,
            flags_random: false,
        }
    }

    /// Create a VAL option (sets a constant value when triggered)
    pub fn val(name: &str, value: i32) -> Self {
        Opt {
            long_name: name.to_string(),
            short_name: None,
            arg_type: ArgType::Val(value),
            bit_op: None,
            val: Some(value),
            description: None,
            arg_description: None,
            default_value: None,
            store_name: None,
            flags_toggle: false,
            flags_optional: false,
            flags_onedash: false,
            flags_doc_hidden: false,
            flags_show_default: false,
            flags_random: false,
        }
    }

    pub fn short(mut self, c: char) -> Self {
        self.short_name = Some(c);
        self
    }

    pub fn arg_type(mut self, t: ArgType) -> Self {
        self.arg_type = t;
        self
    }

    pub fn description(mut self, desc: &str) -> Self {
        self.description = Some(desc.to_string());
        self
    }

    pub fn arg_description(mut self, desc: &str) -> Self {
        self.arg_description = Some(desc.to_string());
        self
    }

    pub fn default_val<T: IntoStoredValue>(mut self, v: T) -> Self {
        self.default_value = Some(v.into_stored_value());
        self
    }

    pub fn store_as(mut self, name: &str) -> Self {
        self.store_name = Some(name.to_string());
        self
    }

    pub fn toggle(mut self) -> Self {
        self.flags_toggle = true;
        self
    }

    pub fn optional(mut self) -> Self {
        self.flags_optional = true;
        self
    }

    pub fn onedash(mut self) -> Self {
        self.flags_onedash = true;
        self
    }

    pub fn doc_hidden(mut self) -> Self {
        self.flags_doc_hidden = true;
        self
    }

    pub fn show_default(mut self) -> Self {
        self.flags_show_default = true;
        self
    }

    pub fn random(mut self) -> Self {
        self.flags_random = true;
        self
    }

    pub fn bit_or(mut self) -> Self {
        self.bit_op = Some(BitOp::Or);
        self
    }

    pub fn bit_nand(mut self) -> Self {
        self.bit_op = Some(BitOp::Nand);
        self
    }

    pub fn bit_xor(mut self) -> Self {
        self.bit_op = Some(BitOp::Xor);
        self
    }

    /// Set the val field (for callback association or VAL options)
    pub fn set_val(mut self, v: i32) -> Self {
        self.val = Some(v);
        self
    }
}

/// Trait for converting Rust values into StoredValue
pub trait IntoStoredValue {
    fn into_stored_value(self) -> StoredValue;
}

impl IntoStoredValue for i32 {
    fn into_stored_value(self) -> StoredValue {
        StoredValue::Int(self)
    }
}

impl IntoStoredValue for u32 {
    fn into_stored_value(self) -> StoredValue {
        StoredValue::Uint(self)
    }
}

impl IntoStoredValue for i64 {
    fn into_stored_value(self) -> StoredValue {
        StoredValue::Long(self)
    }
}

impl IntoStoredValue for i16 {
    fn into_stored_value(self) -> StoredValue {
        StoredValue::Short(self)
    }
}

impl IntoStoredValue for f32 {
    fn into_stored_value(self) -> StoredValue {
        StoredValue::Float(self)
    }
}

impl IntoStoredValue for f64 {
    fn into_stored_value(self) -> StoredValue {
        StoredValue::Double(self)
    }
}

impl IntoStoredValue for &str {
    fn into_stored_value(self) -> StoredValue {
        StoredValue::Str(self.to_string())
    }
}

impl IntoStoredValue for String {
    fn into_stored_value(self) -> StoredValue {
        StoredValue::Str(self)
    }
}

impl IntoStoredValue for bool {
    fn into_stored_value(self) -> StoredValue {
        StoredValue::Bool(self)
    }
}

// ============================================================================
// Trait for typed retrieval from Context
// ============================================================================

pub trait FromStoredValue: Sized {
    fn from_stored_value(v: &StoredValue) -> Result<Self>;
}

impl FromStoredValue for i32 {
    fn from_stored_value(v: &StoredValue) -> Result<Self> {
        match v {
            StoredValue::Int(n) => Ok(*n),
            StoredValue::Bool(b) => Ok(if *b { 1 } else { 0 }),
            StoredValue::Uint(n) => Ok(*n as i32),
            _ => Err(Error::Other("type mismatch: expected i32".to_string())),
        }
    }
}

impl FromStoredValue for u32 {
    fn from_stored_value(v: &StoredValue) -> Result<Self> {
        match v {
            StoredValue::Uint(n) => Ok(*n),
            StoredValue::Int(n) => Ok(*n as u32),
            _ => Err(Error::Other("type mismatch: expected u32".to_string())),
        }
    }
}

impl FromStoredValue for bool {
    fn from_stored_value(v: &StoredValue) -> Result<Self> {
        match v {
            StoredValue::Bool(b) => Ok(*b),
            StoredValue::Int(n) => Ok(*n != 0),
            _ => Err(Error::Other("type mismatch: expected bool".to_string())),
        }
    }
}

impl FromStoredValue for String {
    fn from_stored_value(v: &StoredValue) -> Result<Self> {
        match v {
            StoredValue::Str(s) => Ok(s.clone()),
            _ => Err(Error::Other("type mismatch: expected String".to_string())),
        }
    }
}

impl FromStoredValue for i64 {
    fn from_stored_value(v: &StoredValue) -> Result<Self> {
        match v {
            StoredValue::Long(n) => Ok(*n),
            StoredValue::LongLong(n) => Ok(*n),
            _ => Err(Error::Other("type mismatch: expected i64".to_string())),
        }
    }
}

impl FromStoredValue for i16 {
    fn from_stored_value(v: &StoredValue) -> Result<Self> {
        match v {
            StoredValue::Short(n) => Ok(*n),
            _ => Err(Error::Other("type mismatch: expected i16".to_string())),
        }
    }
}

impl FromStoredValue for f32 {
    fn from_stored_value(v: &StoredValue) -> Result<Self> {
        match v {
            StoredValue::Float(n) => Ok(*n),
            _ => Err(Error::Other("type mismatch: expected f32".to_string())),
        }
    }
}

impl FromStoredValue for f64 {
    fn from_stored_value(v: &StoredValue) -> Result<Self> {
        match v {
            StoredValue::Double(n) => Ok(*n),
            _ => Err(Error::Other("type mismatch: expected f64".to_string())),
        }
    }
}

impl FromStoredValue for Vec<String> {
    fn from_stored_value(v: &StoredValue) -> Result<Self> {
        match v {
            StoredValue::Argv(v) => Ok(v.clone()),
            _ => Err(Error::Other(
                "type mismatch: expected Vec<String>".to_string(),
            )),
        }
    }
}

impl FromStoredValue for BloomFilter {
    fn from_stored_value(v: &StoredValue) -> Result<Self> {
        match v {
            StoredValue::Bits(bf) => Ok(bf.clone()),
            _ => Err(Error::Other(
                "type mismatch: expected BloomFilter".to_string(),
            )),
        }
    }
}

// ============================================================================
// OptionTable
// ============================================================================

enum TableEntry {
    Option(Opt),
    IncludeTable(OptionTable, Option<String>),
    Callback {
        func: OptionCallback,
        data: Option<String>,
        inc_data: bool,
    },
    AutoHelp,
    AutoAlias,
}

pub struct OptionTable {
    entries: Vec<TableEntry>,
}

impl OptionTable {
    pub fn new() -> Self {
        OptionTable {
            entries: Vec::new(),
        }
    }

    pub fn option(mut self, opt: Opt) -> Self {
        self.entries.push(TableEntry::Option(opt));
        self
    }

    pub fn include_table(mut self, table: OptionTable, description: Option<&str>) -> Self {
        self.entries.push(TableEntry::IncludeTable(
            table,
            description.map(|s| s.to_string()),
        ));
        self
    }

    pub fn callback<F>(mut self, func: F, data: Option<&str>) -> Self
    where
        F: Fn(Option<&str>, Option<&str>) -> Result<()> + Send + Sync + 'static,
    {
        self.entries.push(TableEntry::Callback {
            func: Arc::new(func),
            data: data.map(|s| s.to_string()),
            inc_data: false,
        });
        self
    }

    pub fn callback_inc_data<F>(mut self, func: F) -> Self
    where
        F: Fn(Option<&str>, Option<&str>) -> Result<()> + Send + Sync + 'static,
    {
        self.entries.push(TableEntry::Callback {
            func: Arc::new(func),
            data: None,
            inc_data: true,
        });
        self
    }

    pub fn auto_help(mut self) -> Self {
        self.entries.push(TableEntry::AutoHelp);
        self
    }

    pub fn auto_alias(mut self) -> Self {
        self.entries.push(TableEntry::AutoAlias);
        self
    }
}

impl Default for OptionTable {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Internal: flattened option definition
// ============================================================================

#[derive(Clone)]
struct OptionDef {
    long_name: String,
    short_name: Option<char>,
    arg_type: ArgType,
    bit_op: Option<BitOp>,
    _val: Option<i32>,
    description: Option<String>,
    arg_description: Option<String>,
    default_value: Option<StoredValue>,
    store_name: Option<String>, // if set, value stored under this key
    flags_toggle: bool,
    flags_optional: bool,
    flags_onedash: bool,
    flags_doc_hidden: bool,
    flags_show_default: bool,
    _flags_random: bool,
    // Which callback index applies to this option (from its table)
    callback_idx: Option<usize>,
}

impl OptionDef {
    fn storage_key(&self) -> &str {
        self.store_name.as_deref().unwrap_or(&self.long_name)
    }

    fn takes_arg(&self) -> bool {
        !matches!(self.arg_type, ArgType::None | ArgType::Val(_))
    }
}

#[derive(Clone)]
struct CallbackDef {
    func: OptionCallback,
    data: Option<String>,
    _inc_data: bool,
}

struct Alias {
    long_name: Option<String>, // e.g., "simple" (without --)
    short_name: Option<char>,  // e.g., 'T'
    expansion: Vec<String>,    // what it expands to
    description: Option<String>,
    arg_description: Option<String>,
    doc_hidden: bool,
}

#[cfg(feature = "exec")]
struct ExecAlias {
    long_name: Option<String>,
    short_name: Option<char>,
    argv: Vec<String>, // [executable_path, extra_args...]
}

// Parse frame for option stack (nested alias expansion)
struct ParseFrame {
    args: Vec<String>,
    next: usize,
    consumed: HashSet<usize>,        // args consumed by !#:+ substitution
    next_char_arg: Option<String>,   // remaining short option chars after alias
    curr_alias_long: Option<String>, // for recursion detection
    curr_alias_short: Option<char>,
}

// ============================================================================
// ContextBuilder
// ============================================================================

pub struct ContextBuilder {
    name: String,
    options: Option<OptionTable>,
    config_files: Vec<String>,
    #[cfg(feature = "exec")]
    exec_path: Option<(String, bool)>,
    read_default_config: bool,
}

impl ContextBuilder {
    pub fn new(name: &str) -> Self {
        ContextBuilder {
            name: name.to_string(),
            options: None,
            config_files: Vec::new(),
            #[cfg(feature = "exec")]
            exec_path: None,
            read_default_config: false,
        }
    }

    pub fn options(mut self, opts: OptionTable) -> Self {
        self.options = Some(opts);
        self
    }

    pub fn config_file(mut self, path: &str) -> Result<Self> {
        self.config_files.push(path.to_string());
        Ok(self)
    }

    #[cfg(feature = "exec")]
    pub fn exec_path(mut self, path: &str, allow_absolute: bool) -> Self {
        self.exec_path = Some((path.to_string(), allow_absolute));
        self
    }

    pub fn default_config(mut self, _use_env: bool) -> Self {
        self.read_default_config = true;
        self
    }

    pub fn build(self) -> Result<Context> {
        let table = self
            .options
            .ok_or_else(|| Error::Other("No options provided".to_string()))?;

        // Flatten option table into option defs and callbacks
        let mut options = Vec::new();
        let mut callbacks = Vec::new();
        let mut has_auto_help = false;
        let mut has_auto_alias = false;
        let mut table_sections = Vec::new();
        flatten_table(
            &table,
            &mut options,
            &mut callbacks,
            &mut table_sections,
            &mut has_auto_help,
            &mut has_auto_alias,
            None,
            None,
        );

        // Set up default values
        let mut values = HashMap::new();
        for opt in &options {
            if let Some(ref default) = opt.default_value {
                values.insert(opt.storage_key().to_string(), default.clone());
            }
        }

        Ok(Context {
            name: self.name,
            options,
            callbacks,
            config_files: self.config_files,
            #[cfg(feature = "exec")]
            exec_path: self.exec_path,
            _read_default_config: self.read_default_config,
            has_auto_help,
            _has_auto_alias: has_auto_alias,
            table_sections,
            _option_table: table,
            values,
            present: HashSet::new(),
            remaining: Vec::new(),
            aliases: Vec::new(),
            #[cfg(feature = "exec")]
            execs: Vec::new(),
            #[cfg(feature = "exec")]
            exec_av: Vec::new(),
        })
    }
}

/// Flatten an OptionTable tree into a Vec<OptionDef>
fn flatten_table(
    table: &OptionTable,
    options: &mut Vec<OptionDef>,
    callbacks: &mut Vec<CallbackDef>,
    table_sections: &mut Vec<(usize, usize, Option<String>)>,
    has_auto_help: &mut bool,
    has_auto_alias: &mut bool,
    parent_callback_idx: Option<usize>,
    include_description: Option<&str>,
) {
    // Check if this table has its own callback
    let mut current_callback_idx = parent_callback_idx;

    for entry in &table.entries {
        match entry {
            TableEntry::Callback {
                func,
                data,
                inc_data,
            } => {
                let idx = callbacks.len();
                // If inc_data, use the include_table description as the data
                let effective_data = if *inc_data {
                    include_description.map(|s| s.to_string())
                } else {
                    data.clone()
                };
                callbacks.push(CallbackDef {
                    func: func.clone(),
                    data: effective_data,
                    _inc_data: *inc_data,
                });
                current_callback_idx = Some(idx);
            }
            TableEntry::Option(opt) => {
                options.push(OptionDef {
                    long_name: opt.long_name.clone(),
                    short_name: opt.short_name,
                    arg_type: opt.arg_type.clone(),
                    bit_op: opt.bit_op,
                    _val: opt.val,
                    description: opt.description.clone(),
                    arg_description: opt.arg_description.clone(),
                    default_value: opt.default_value.clone(),
                    store_name: opt.store_name.clone(),
                    flags_toggle: opt.flags_toggle,
                    flags_optional: opt.flags_optional,
                    flags_onedash: opt.flags_onedash,
                    flags_doc_hidden: opt.flags_doc_hidden,
                    flags_show_default: opt.flags_show_default,
                    _flags_random: opt.flags_random,
                    callback_idx: current_callback_idx,
                });
            }
            TableEntry::IncludeTable(sub_table, description) => {
                let start_idx = options.len();
                flatten_table(
                    sub_table,
                    options,
                    callbacks,
                    table_sections,
                    has_auto_help,
                    has_auto_alias,
                    parent_callback_idx,
                    description.as_deref(),
                );
                let end_idx = options.len();
                table_sections.push((start_idx, end_idx, description.clone()));
            }
            TableEntry::AutoHelp => {
                *has_auto_help = true;
                let start_idx = options.len();
                // Add --help and --usage options
                options.push(OptionDef {
                    long_name: "help".to_string(),
                    short_name: Some('?'),
                    arg_type: ArgType::None,
                    bit_op: None,
                    _val: None,
                    description: Some("Show this help message".to_string()),
                    arg_description: None,
                    default_value: None,
                    store_name: None,
                    flags_toggle: false,
                    flags_optional: false,
                    flags_onedash: false,
                    flags_doc_hidden: false,
                    flags_show_default: false,
                    _flags_random: false,
                    callback_idx: None,
                });
                options.push(OptionDef {
                    long_name: "usage".to_string(),
                    short_name: None,
                    arg_type: ArgType::None,
                    bit_op: None,
                    _val: None,
                    description: Some("Display brief usage message".to_string()),
                    arg_description: None,
                    default_value: None,
                    store_name: None,
                    flags_toggle: false,
                    flags_optional: false,
                    flags_onedash: false,
                    flags_doc_hidden: false,
                    flags_show_default: false,
                    _flags_random: false,
                    callback_idx: None,
                });
                let end_idx = options.len();
                table_sections.push((start_idx, end_idx, Some("Help options:".to_string())));
            }
            TableEntry::AutoAlias => {
                *has_auto_alias = true;
                let start_idx = options.len();
                table_sections.push((
                    start_idx,
                    start_idx,
                    Some("Options implemented via popt alias/exec:".to_string()),
                ));
            }
        }
    }
}

// ============================================================================
// Free helper functions for parse_with_stack (avoids borrow conflicts with &mut self)
// ============================================================================

/// Consume the next argument value from the option stack.
/// Pops exhausted frames to find a value in a parent frame.
fn consume_next_value(
    ctx_name: &str,
    stack: &mut Vec<ParseFrame>,
    opt_name: &str,
    is_optional: bool,
) -> Result<Option<String>> {
    loop {
        if let Some(frame) = stack.last_mut() {
            while frame.next < frame.args.len() && frame.consumed.contains(&frame.next) {
                frame.next += 1;
            }
            if frame.next < frame.args.len() {
                if is_optional && frame.args[frame.next].starts_with('-') {
                    return Ok(None);
                }
                let val = frame.args[frame.next].clone();
                frame.next += 1;
                return Ok(Some(val));
            }
            if stack.len() > 1 {
                stack.pop();
                continue;
            }
        }
        break;
    }
    if is_optional {
        Ok(None)
    } else {
        Err(Error::MissingArg(format!(
            "{}: bad argument --{}: missing argument",
            ctx_name, opt_name
        )))
    }
}

/// Expand `!#:+` substitution markers in a value string.
fn expand_next_arg(s: &str, stack: &mut [ParseFrame]) -> String {
    if !s.contains("!#:+") {
        return s.to_string();
    }

    let mut result = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut subst_arg: Option<String> = None;

    while i < bytes.len() {
        if i + 3 < bytes.len()
            && bytes[i] == b'!'
            && bytes[i + 1] == b'#'
            && bytes[i + 2] == b':'
            && bytes[i + 3] == b'+'
        {
            if subst_arg.is_none() {
                subst_arg = find_next_arg_from_stack(stack);
            }
            if let Some(ref a) = subst_arg {
                result.push_str(a);
            }
            i += 4;
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }
    result
}

/// Find and consume the next non-option positional arg from the option stack.
fn find_next_arg_from_stack(stack: &mut [ParseFrame]) -> Option<String> {
    for frame in stack.iter_mut().rev() {
        for i in frame.next..frame.args.len() {
            if frame.consumed.contains(&i) {
                continue;
            }
            let arg = &frame.args[i];
            if arg.starts_with('-') {
                continue;
            }
            frame.consumed.insert(i);
            return Some(arg.clone());
        }
    }
    None
}

#[cfg(feature = "exec")]
/// Push an option to exec_av accumulator
fn push_exec_av(
    exec_av: &mut Vec<String>,
    opt_name: &str,
    short_name: Option<char>,
    is_onedash: bool,
    value: Option<&str>,
) {
    if is_onedash {
        exec_av.push(format!("-{}", opt_name));
    } else if !opt_name.is_empty() {
        exec_av.push(format!("--{}", opt_name));
    } else if let Some(c) = short_name {
        exec_av.push(format!("-{}", c));
    }
    if let Some(v) = value {
        exec_av.push(v.to_string());
    }
}

// ============================================================================
// Help/Usage formatting helpers (free functions)
// ============================================================================

/// Calculate the left column width for an option in help output
fn calc_option_left_width(opt: &OptionDef) -> usize {
    if opt.flags_doc_hidden {
        return 0;
    }
    let mut len: usize = 2 + 4; // "  " + "-X, " (always padded even if no short)

    if !opt.long_name.is_empty() {
        len += if opt.flags_onedash { 1 } else { 2 }; // "-" or "--"
        len += opt.long_name.len();
    }

    let arg_descrip = Context::get_arg_descrip(opt);
    if let Some(ref ad) = arg_descrip {
        if !ad.starts_with(' ') && !ad.starts_with('=') && !ad.starts_with('(') {
            len += 1; // "="
        }
        len += ad.len();
    }

    if opt.flags_optional {
        len += 2;
    } // "[]"

    len
}

/// Calculate the left column width for an alias in help output
fn calc_alias_left_width(alias: &Alias) -> usize {
    if alias.doc_hidden {
        return 0;
    }
    let mut len: usize = 2 + 4; // "  " + "-X, "
    if let Some(ref name) = alias.long_name {
        len += 2 + name.len(); // "--" + name
    }
    if let Some(ref ad) = alias.arg_description {
        if !ad.starts_with(' ') && !ad.starts_with('=') && !ad.starts_with('(') {
            len += 1; // "="
        }
        len += ad.len();
    }
    len
}

#[cfg(feature = "exec")]
/// Calculate the left column width for an exec alias in help output
fn calc_exec_left_width(exec: &ExecAlias) -> usize {
    let mut len: usize = 2 + 4; // "  " + "-X, "
    if let Some(ref name) = exec.long_name {
        len += 2 + name.len(); // "--" + name
    }
    len
}

/// Format an alias/exec item for usage output, returning new cursor position
fn format_item_usage<W: std::io::Write>(
    out: &mut W,
    short_name: Option<char>,
    long_name: Option<&str>,
    arg_descrip: Option<&str>,
    onedash: bool,
    cur: usize,
    max_col: usize,
) -> usize {
    let prtshort = short_name.is_some_and(|c| c != ' ' && c.is_ascii_graphic());
    let prtlong = long_name.is_some();

    if !prtshort && !prtlong {
        return cur;
    }

    let mut len: usize = 3; // " []"
    if prtshort {
        len += 2;
    } // "-c"
    if prtlong {
        if prtshort {
            len += 1;
        } // "|"
        len += if onedash { 1 } else { 2 }; // "-" or "--"
        len += long_name.unwrap().len();
    }
    if let Some(ad) = arg_descrip {
        if !ad.starts_with(' ') && !ad.starts_with('=') && !ad.starts_with('(') {
            len += 1; // "="
        }
        len += ad.len();
    }

    let mut cur = cur;
    if cur + len > max_col {
        let _ = write!(out, "\n       ");
        cur = 7;
    }

    let _ = write!(out, " [");
    if prtshort {
        let _ = write!(out, "-{}", short_name.unwrap());
    }
    if prtlong {
        let sep = if prtshort { "|" } else { "" };
        let dash = if onedash { "-" } else { "--" };
        let _ = write!(out, "{}{}{}", sep, dash, long_name.unwrap());
    }
    if let Some(ad) = arg_descrip {
        if !ad.starts_with(' ') && !ad.starts_with('=') && !ad.starts_with('(') {
            let _ = write!(out, "=");
        }
        let _ = write!(out, "{}", ad);
    }
    let _ = write!(out, "]");

    cur + len + 1
}

/// Word-wrap text at word boundaries with indentation
fn write_wrapped_text<W: std::io::Write>(
    out: &mut W,
    text: &str,
    indent_length: usize,
    line_length: usize,
) {
    let mut help = text;
    while help.len() > line_length {
        // Find the last space within line_length
        let search_range = &help[..line_length];
        let break_pos = match search_range.rfind(' ') {
            Some(pos) if pos > 0 => pos,
            _ => break, // give up if no space found
        };

        // Print up to the break point
        let _ = write!(
            out,
            "{}\n{:indent$}",
            &help[..break_pos],
            "",
            indent = indent_length
        );

        // Skip the space(s) at the break
        help = &help[break_pos..];
        help = help.trim_start_matches(' ');
    }

    if !help.is_empty() {
        let _ = write!(out, "{}\n", help);
    }
}

/// Mimic C's %g format for a double value
fn c_format_g(v: f64) -> String {
    if v == 0.0 {
        return "0".to_string();
    }
    // C's %g uses 6 significant digits by default, removes trailing zeros
    let abs = v.abs();
    let exp = abs.log10().floor() as i32;
    if exp >= -4 && exp < 6 {
        // Use fixed notation
        let decimals = std::cmp::max(0, 5 - exp) as usize;
        let s = format!("{:.*}", decimals, v);
        // Remove trailing zeros after decimal point
        if s.contains('.') {
            let s = s.trim_end_matches('0');
            let s = s.trim_end_matches('.');
            s.to_string()
        } else {
            s
        }
    } else {
        // Use scientific notation
        format!("{:e}", v)
    }
}

// ============================================================================
// Context
// ============================================================================

pub struct Context {
    name: String,
    options: Vec<OptionDef>,
    callbacks: Vec<CallbackDef>,
    config_files: Vec<String>,
    #[cfg(feature = "exec")]
    exec_path: Option<(String, bool)>,
    _read_default_config: bool,
    has_auto_help: bool,
    _has_auto_alias: bool,
    table_sections: Vec<(usize, usize, Option<String>)>, // (start, end, description)
    _option_table: OptionTable,
    values: HashMap<String, StoredValue>,
    present: HashSet<String>,
    remaining: Vec<String>,
    aliases: Vec<Alias>,
    #[cfg(feature = "exec")]
    execs: Vec<ExecAlias>,
    #[cfg(feature = "exec")]
    // Accumulated parsed options (for exec)
    exec_av: Vec<String>,
}

impl Context {
    pub fn builder(name: &str) -> ContextBuilder {
        ContextBuilder::new(name)
    }

    pub fn parse(&mut self) -> Result<()> {
        // Load config files for aliases
        for cfg in &self.config_files.clone() {
            let _ = self.load_config_file(cfg);
        }

        // Get argv
        let argv: Vec<String> = std::env::args().collect();
        let args: Vec<String> = if argv.len() > 1 {
            argv[1..].to_vec()
        } else {
            vec![]
        };

        // Check for POSIXLY_CORRECT
        let posixly_correct =
            std::env::var("POSIXLY_CORRECT").is_ok() || std::env::var("POSIX_ME_HARDER").is_ok();

        // Parse using option stack
        self.parse_with_stack(args, posixly_correct)
    }

    fn parse_with_stack(&mut self, args: Vec<String>, posixly_correct: bool) -> Result<()> {
        let mut stack: Vec<ParseFrame> = vec![ParseFrame {
            args,
            next: 0,
            consumed: HashSet::new(),
            next_char_arg: None,
            curr_alias_long: None,
            curr_alias_short: None,
        }];
        let mut rest_leftover = false;
        #[cfg(feature = "exec")]
        let mut do_exec: Option<usize> = None; // index into self.execs

        loop {
            // Pop exhausted frames (no more args and no remaining short chars)
            while let Some(frame) = stack.last() {
                if frame.next_char_arg.is_some() {
                    break;
                }
                if frame.next < frame.args.len() {
                    break;
                }
                stack.pop();
            }
            if stack.is_empty() {
                break;
            }

            let depth = stack.len() - 1;

            // Process remaining short option chars first
            if stack[depth].next_char_arg.is_some() {
                let next_chars = stack[depth].next_char_arg.take().unwrap();
                if next_chars.is_empty() {
                    continue;
                }
                let c = next_chars.chars().next().unwrap();
                let remaining = next_chars[c.len_utf8()..].to_string();

                // Check short alias (recursion detection)
                let is_curr_alias = stack[depth].curr_alias_short == Some(c);
                if !is_curr_alias {
                    if let Some(alias_idx) = self.find_alias_by_short(c) {
                        if !remaining.is_empty() {
                            stack[depth].next_char_arg = Some(remaining);
                        }
                        let expansion = self.aliases[alias_idx].expansion.clone();
                        if stack.len() >= 10 {
                            return Err(Error::Other("alias expansion too deep".to_string()));
                        }
                        stack.push(ParseFrame {
                            args: expansion,
                            next: 0,
                            consumed: HashSet::new(),
                            next_char_arg: None,
                            curr_alias_long: None,
                            curr_alias_short: Some(c),
                        });
                        continue;
                    }
                }

                // Check short exec
                #[cfg(feature = "exec")]
                if let Some(exec_idx) = self.find_exec_by_short(c) {
                    if !remaining.is_empty() {
                        stack[depth].next_char_arg = Some(remaining);
                    }
                    if do_exec.is_none() {
                        do_exec = Some(exec_idx);
                    } else {
                        self.exec_av.push(format!("-{}", c));
                    }
                    continue;
                }

                // Find short option
                let opt_idx = match self.find_option_idx_by_short(c) {
                    Some(idx) => idx,
                    None => {
                        return Err(Error::BadOption(format!(
                            "{}: bad argument -{}: unknown option",
                            self.name, c
                        )));
                    }
                };

                // Clone needed data from option before calling mutable methods
                let opt_name = self.options[opt_idx].long_name.clone();
                let takes_arg = self.options[opt_idx].takes_arg();
                #[cfg(feature = "exec")]
                let is_onedash = self.options[opt_idx].flags_onedash;
                #[cfg(feature = "exec")]
                let short_name = self.options[opt_idx].short_name;

                if takes_arg {
                    if !remaining.is_empty() {
                        let val = if remaining.starts_with('=') {
                            remaining[1..].to_string()
                        } else {
                            remaining
                        };
                        let val = expand_next_arg(&val, &mut stack);
                        self.store_option(opt_idx, Some(&val), false, true)?;
                        self.present.insert(opt_name.clone());
                        #[cfg(feature = "exec")]
                        push_exec_av(
                            &mut self.exec_av,
                            &opt_name,
                            short_name,
                            is_onedash,
                            Some(&val),
                        );
                    } else {
                        let value = consume_next_value(&self.name, &mut stack, &opt_name, false)?;
                        if let Some(val) = &value {
                            let val = expand_next_arg(val, &mut stack);
                            self.store_option(opt_idx, Some(&val), false, true)?;
                            #[cfg(feature = "exec")]
                            push_exec_av(
                                &mut self.exec_av,
                                &opt_name,
                                short_name,
                                is_onedash,
                                Some(&val),
                            );
                        } else {
                            self.store_option(opt_idx, None, false, true)?;
                            #[cfg(feature = "exec")]
                            push_exec_av(
                                &mut self.exec_av,
                                &opt_name,
                                short_name,
                                is_onedash,
                                None,
                            );
                        }
                        self.present.insert(opt_name.clone());
                    }
                } else {
                    if !remaining.is_empty() {
                        stack[depth].next_char_arg = Some(remaining);
                    }
                    self.store_option(opt_idx, None, false, true)?;
                    self.present.insert(opt_name.clone());
                    #[cfg(feature = "exec")]
                    push_exec_av(&mut self.exec_av, &opt_name, short_name, is_onedash, None);
                }
                continue;
            }

            // Skip consumed args (from !#:+ substitution)
            while stack[depth].next < stack[depth].args.len()
                && stack[depth].consumed.contains(&stack[depth].next)
            {
                stack[depth].next += 1;
            }
            if stack[depth].next >= stack[depth].args.len() {
                continue;
            }

            let arg = stack[depth].args[stack[depth].next].clone();
            stack[depth].next += 1;

            // Handle rest_leftover and positional args
            if rest_leftover {
                self.remaining.push(arg);
                continue;
            }

            if arg == "--" {
                rest_leftover = true;
                continue;
            }

            if arg == "-" || !arg.starts_with('-') {
                if posixly_correct {
                    rest_leftover = true;
                }
                self.remaining.push(arg);
                continue;
            }

            if arg.starts_with("--") {
                // Long option
                let opt_str = &arg[2..];

                // Split on '='
                let (name, long_arg) = match opt_str.find('=') {
                    Some(pos) => (&opt_str[..pos], Some(&opt_str[pos + 1..])),
                    None => (opt_str, None),
                };

                // Check for --noXXX toggle negation
                let (actual_name, negated) = if name.starts_with("no") && name.len() > 2 {
                    let base = &name[2..];
                    if self
                        .find_option_by_long(base)
                        .is_some_and(|o| o.flags_toggle)
                    {
                        (base.to_string(), true)
                    } else {
                        (name.to_string(), false)
                    }
                } else {
                    (name.to_string(), false)
                };

                // Check alias (recursion detection)
                let is_curr_alias = stack[depth].curr_alias_long.as_deref() == Some(&actual_name);
                if !is_curr_alias {
                    if let Some(alias_idx) = self.find_alias_by_long(&actual_name) {
                        let mut expansion = self.aliases[alias_idx].expansion.clone();
                        if let Some(la) = long_arg {
                            expansion.push(la.to_string());
                        }
                        if stack.len() >= 10 {
                            return Err(Error::Other("alias expansion too deep".to_string()));
                        }
                        stack.push(ParseFrame {
                            args: expansion,
                            next: 0,
                            consumed: HashSet::new(),
                            next_char_arg: None,
                            curr_alias_long: Some(actual_name),
                            curr_alias_short: None,
                        });
                        continue;
                    }
                }

                // Check exec alias
                #[cfg(feature = "exec")]
                if let Some(exec_idx) = self.find_exec_by_long(&actual_name) {
                    if do_exec.is_none() {
                        do_exec = Some(exec_idx);
                    } else {
                        self.exec_av.push(format!("--{}", actual_name));
                    }
                    continue;
                }

                // Handle --help and --usage
                if actual_name == "help" && self.has_auto_help {
                    self.print_help();
                    std::process::exit(0);
                }
                if actual_name == "usage" && self.has_auto_help {
                    self.print_usage();
                    std::process::exit(0);
                }

                // Find the option
                let opt_idx = match self.find_option_idx_by_long(&actual_name) {
                    Some(idx) => idx,
                    None => {
                        return Err(Error::BadOption(format!(
                            "{}: bad argument {}: unknown option",
                            self.name, arg
                        )));
                    }
                };

                // Clone needed data before calling mutable methods
                let opt_name = self.options[opt_idx].long_name.clone();
                let takes_arg = self.options[opt_idx].takes_arg();
                let is_optional = self.options[opt_idx].flags_optional;
                #[cfg(feature = "exec")]
                let is_onedash = self.options[opt_idx].flags_onedash;
                #[cfg(feature = "exec")]
                let short_name = self.options[opt_idx].short_name;

                if !takes_arg && long_arg.is_some() {
                    return Err(Error::UnwantedArg(format!(
                        "{}: bad argument {}: option does not take an argument",
                        self.name, arg
                    )));
                }

                let value_str = if takes_arg {
                    if let Some(v) = long_arg {
                        Some(expand_next_arg(v, &mut stack))
                    } else {
                        let value =
                            consume_next_value(&self.name, &mut stack, &opt_name, is_optional)?;
                        value.map(|v| expand_next_arg(&v, &mut stack))
                    }
                } else {
                    None
                };

                self.store_option(opt_idx, value_str.as_deref(), negated, true)?;
                self.present.insert(opt_name.clone());
                #[cfg(feature = "exec")]
                push_exec_av(
                    &mut self.exec_av,
                    &opt_name,
                    short_name,
                    is_onedash,
                    value_str.as_deref(),
                );
            } else if arg.starts_with('-') && arg.len() > 1 {
                // Short option(s) or onedash long option
                let after_dash = &arg[1..];

                // First check: is this a -onedash style long option?
                let (onedash_base, onedash_val) = match after_dash.find('=') {
                    Some(pos) => (&after_dash[..pos], Some(&after_dash[pos + 1..])),
                    None => (after_dash, None),
                };

                let is_onedash_match = self
                    .find_option_idx_by_long(onedash_base)
                    .map(|idx| self.options[idx].flags_onedash)
                    .unwrap_or(false);

                if is_onedash_match {
                    let idx = self.find_option_idx_by_long(onedash_base).unwrap();
                    let opt_name = self.options[idx].long_name.clone();
                    let takes_arg = self.options[idx].takes_arg();
                    #[cfg(feature = "exec")]
                    let is_onedash = true;
                    #[cfg(feature = "exec")]
                    let short_name = self.options[idx].short_name;

                    let value_str = if takes_arg {
                        if let Some(v) = onedash_val {
                            Some(v.to_string())
                        } else {
                            consume_next_value(&self.name, &mut stack, &opt_name, false)?
                        }
                    } else {
                        None
                    };

                    self.store_option(idx, value_str.as_deref(), false, true)?;
                    self.present.insert(opt_name.clone());
                    #[cfg(feature = "exec")]
                    push_exec_av(
                        &mut self.exec_av,
                        &opt_name,
                        short_name,
                        is_onedash,
                        value_str.as_deref(),
                    );
                    continue;
                }

                // Set up short option processing via next_char_arg
                stack[depth].next_char_arg = Some(after_dash.to_string());
            } else {
                // Positional argument
                if posixly_correct {
                    rest_leftover = true;
                }
                self.remaining.push(arg);
            }
        }

        // Gather any remaining positional args from the stack
        if rest_leftover {
            for frame in &stack {
                for i in frame.next..frame.args.len() {
                    if !frame.consumed.contains(&i) {
                        self.remaining.push(frame.args[i].clone());
                    }
                }
            }
        }

        // Handle exec
        #[cfg(feature = "exec")]
        if let Some(exec_idx) = do_exec {
            let exec_alias = &self.execs[exec_idx];
            let exec_path = if exec_alias.argv[0].contains('/') {
                exec_alias.argv[0].clone()
            } else if let Some((ref ep, _)) = self.exec_path {
                format!("{}/{}", ep, exec_alias.argv[0])
            } else {
                exec_alias.argv[0].clone()
            };

            let mut argv: Vec<String> = Vec::new();
            for a in &exec_alias.argv[1..] {
                argv.push(a.clone());
            }
            argv.extend(self.exec_av.drain(..));
            argv.extend(self.remaining.drain(..));

            use std::os::unix::process::CommandExt;
            let err = std::process::Command::new(&exec_path).args(&argv).exec();
            return Err(Error::Other(format!("exec failed: {}", err)));
        }

        Ok(())
    }

    /// Store a parsed option value
    fn store_option(
        &mut self,
        opt_idx: usize,
        value_str: Option<&str>,
        negated: bool,
        fire_callbacks: bool,
    ) -> Result<()> {
        let opt = self.options[opt_idx].clone();
        let key = opt.storage_key().to_string();

        // Fire callback if applicable
        if fire_callbacks {
            if let Some(cb_idx) = opt.callback_idx {
                let cb = self.callbacks[cb_idx].clone();
                let data = cb.data.as_deref();
                (cb.func)(value_str, data)?;
            }
        }

        match &opt.arg_type {
            ArgType::None => {
                if negated {
                    self.values.insert(key, StoredValue::Bool(false));
                } else {
                    self.values.insert(key, StoredValue::Bool(true));
                }
            }
            ArgType::String => {
                if let Some(val) = value_str {
                    self.values.insert(key, StoredValue::Str(val.to_string()));
                }
            }
            ArgType::Int => {
                if let Some(val) = value_str {
                    let n: i32 = val.parse().map_err(|_| {
                        Error::BadNumber(format!(
                            "{}: bad argument --{}: invalid numeric value",
                            self.name, opt.long_name
                        ))
                    })?;
                    self.values.insert(key, StoredValue::Int(n));
                }
            }
            ArgType::Long => {
                if let Some(val) = value_str {
                    let n: i64 = val.parse().map_err(|_| {
                        Error::BadNumber(format!(
                            "{}: bad argument --{}: invalid numeric value",
                            self.name, opt.long_name
                        ))
                    })?;
                    self.values.insert(key, StoredValue::Long(n));
                }
            }
            ArgType::LongLong => {
                if let Some(val) = value_str {
                    let n: i64 = val.parse().map_err(|_| {
                        Error::BadNumber(format!(
                            "{}: bad argument --{}: invalid numeric value",
                            self.name, opt.long_name
                        ))
                    })?;
                    self.values.insert(key, StoredValue::LongLong(n));
                }
            }
            ArgType::Short => {
                if let Some(val) = value_str {
                    let n: i16 = val.parse().map_err(|_| {
                        Error::BadNumber(format!(
                            "{}: bad argument --{}: invalid numeric value",
                            self.name, opt.long_name
                        ))
                    })?;
                    self.values.insert(key, StoredValue::Short(n));
                }
            }
            ArgType::Float => {
                if let Some(val) = value_str {
                    let n: f32 = val.parse().map_err(|_| {
                        Error::BadNumber(format!(
                            "{}: bad argument --{}: invalid numeric value",
                            self.name, opt.long_name
                        ))
                    })?;
                    self.values.insert(key, StoredValue::Float(n));
                }
            }
            ArgType::Double => {
                if let Some(val) = value_str {
                    let n: f64 = val.parse().map_err(|_| {
                        Error::BadNumber(format!(
                            "{}: bad argument --{}: invalid numeric value",
                            self.name, opt.long_name
                        ))
                    })?;
                    self.values.insert(key, StoredValue::Double(n));
                }
            }
            ArgType::Val(constant) => {
                let constant = *constant;
                if let Some(bit_op) = opt.bit_op {
                    // Bit operation on shared storage
                    let current = match self.values.get(&key) {
                        Some(StoredValue::Uint(n)) => *n,
                        Some(StoredValue::Int(n)) => *n as u32,
                        _ => 0,
                    };
                    let operand = constant as u32;
                    let new_val = if negated {
                        // Toggle negation: reverse the operation
                        match bit_op {
                            BitOp::Or => current & !operand,  // no-bitset: clear instead of set
                            BitOp::Nand => current | operand, // no-bitclr: set instead of clear
                            BitOp::Xor => current ^ operand,  // xor is self-inverse
                        }
                    } else {
                        match bit_op {
                            BitOp::Or => current | operand,
                            BitOp::Nand => current & !operand,
                            BitOp::Xor => current ^ operand,
                        }
                    };
                    self.values.insert(key, StoredValue::Uint(new_val));
                } else {
                    // Plain VAL: just store the constant
                    self.values.insert(key, StoredValue::Int(constant));
                }
            }
            ArgType::Argv => {
                if let Some(val) = value_str {
                    let entry = self
                        .values
                        .entry(key)
                        .or_insert_with(|| StoredValue::Argv(Vec::new()));
                    if let StoredValue::Argv(ref mut vec) = entry {
                        vec.push(val.to_string());
                    }
                }
            }
            ArgType::BitSet => {
                if let Some(val) = value_str {
                    let entry = self
                        .values
                        .entry(key)
                        .or_insert_with(|| StoredValue::Bits(BloomFilter::new()));
                    if let StoredValue::Bits(ref mut bloom) = entry {
                        bloom.save_bits(val);
                    }
                }
            }
        }

        Ok(())
    }

    fn find_option_by_long(&self, name: &str) -> Option<&OptionDef> {
        self.options.iter().find(|o| o.long_name == name)
    }

    fn find_option_idx_by_long(&self, name: &str) -> Option<usize> {
        self.options.iter().position(|o| o.long_name == name)
    }

    fn find_option_idx_by_short(&self, c: char) -> Option<usize> {
        self.options.iter().position(|o| o.short_name == Some(c))
    }

    fn find_alias_by_long(&self, name: &str) -> Option<usize> {
        self.aliases
            .iter()
            .position(|a| a.long_name.as_deref() == Some(name))
    }

    fn find_alias_by_short(&self, c: char) -> Option<usize> {
        self.aliases.iter().position(|a| a.short_name == Some(c))
    }

    #[cfg(feature = "exec")]
    fn find_exec_by_long(&self, name: &str) -> Option<usize> {
        self.execs
            .iter()
            .position(|e| e.long_name.as_deref() == Some(name))
    }

    #[cfg(feature = "exec")]
    fn find_exec_by_short(&self, c: char) -> Option<usize> {
        self.execs.iter().position(|e| e.short_name == Some(c))
    }

    fn load_config_file(&mut self, path: &str) -> Result<()> {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Ok(()), // silently ignore missing files
        };

        // Handle \ line continuations
        let mut joined = String::with_capacity(content.len());
        let mut chars = content.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' {
                if chars.peek() == Some(&'\n') {
                    chars.next(); // skip the newline
                    continue;
                }
            }
            joined.push(c);
        }

        for line in joined.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            self.parse_config_line(l);
        }
        Ok(())
    }

    fn parse_config_line(&mut self, line: &str) {
        let mut parts = line.splitn(4, |c: char| c.is_ascii_whitespace());

        let app_name = match parts.next() {
            Some(s) if !s.is_empty() => s,
            _ => return,
        };

        // Check if this config line applies to our app
        if app_name != self.name {
            return;
        }

        // Skip whitespace and get entry type
        let entry_type = loop {
            match parts.next() {
                Some("") => continue,
                Some(s) => break s,
                None => return,
            }
        };

        // Get the rest of the line after entry_type
        let _rest = loop {
            match parts.next() {
                Some("") => continue,
                Some(s) => break s,
                None => return,
            }
        };

        // rest now starts at the option name. We need to re-split from here.
        // Actually, splitn(4) may have consumed too much. Let me use a manual approach.
        // Re-parse from the original line more carefully.
        let after_app = &line[app_name.len()..].trim_start();
        let after_type = &after_app[entry_type.len()..].trim_start();

        // Parse opt name (first token)
        let opt_end = after_type
            .find(|c: char| c.is_ascii_whitespace())
            .unwrap_or(after_type.len());
        let opt = &after_type[..opt_end];

        if opt.is_empty() {
            return;
        }

        // For aliases, the opt must start with - and there must be expansion text
        let expansion_str = after_type[opt_end..].trim_start();

        // Parse opt into long or short name
        let (long_name, short_name) = if opt.starts_with("--") {
            (Some(opt[2..].to_string()), None)
        } else if opt.starts_with('-') && opt.len() == 2 {
            (None, Some(opt.chars().nth(1).unwrap()))
        } else {
            return; // not a valid option format
        };

        if entry_type == "alias" {
            // Need expansion
            if opt.starts_with('-') && expansion_str.is_empty() {
                return;
            }

            // Parse expansion using poptParseArgvString
            let expansion_args = match parse_argv_string(expansion_str) {
                Ok(args) => args,
                Err(_) => return,
            };

            // Process --POPTdesc= and --POPTargs= meta-options
            let mut filtered = Vec::new();
            let mut description: Option<String> = None;
            let mut arg_description: Option<String> = None;
            let mut doc_hidden = true;

            for arg in &expansion_args {
                if let Some(rest) = arg.strip_prefix("--POPTdesc=") {
                    let desc = if rest.starts_with('$') {
                        &rest[1..]
                    } else {
                        rest
                    };
                    description = Some(desc.to_string());
                    doc_hidden = false;
                } else if let Some(rest) = arg.strip_prefix("--POPTargs=") {
                    let desc = if rest.starts_with('$') {
                        &rest[1..]
                    } else {
                        rest
                    };
                    arg_description = Some(desc.to_string());
                } else {
                    filtered.push(arg.clone());
                }
            }

            self.aliases.push(Alias {
                #[cfg(feature = "exec")]
                long_name: long_name.clone(),
                #[cfg(not(feature = "exec"))]
                long_name,
                short_name,
                expansion: filtered,
                description,
                arg_description,
                doc_hidden,
            });
        }
        #[cfg(feature = "exec")]
        if entry_type == "exec" {
            // For exec: the "expansion" is the path to the executable
            // Parse the rest as argv
            let exec_args = match parse_argv_string(expansion_str) {
                Ok(args) if !args.is_empty() => args,
                _ => return,
            };

            self.execs.push(ExecAlias {
                long_name,
                short_name,
                argv: exec_args,
            });
        }
    }

    pub fn print_help(&self) {
        use std::io::Write;
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        let max_col_width: usize = 79;

        // Print header
        let _ = write!(out, "Usage: {} [OPTION...]\n", self.name);

        // Calculate maxLeftCol across all options (including aliases/execs)
        let max_left_col = self.calc_max_left_col();
        let indent_length = max_left_col + 5; // 2 prefix + maxLeftCol + 3 separator
        let line_length = if max_col_width > indent_length {
            max_col_width - indent_length
        } else {
            20
        };

        // Build a set of indices that belong to sections (include tables)
        let mut in_section = vec![false; self.options.len()];
        for &(start, end, _) in &self.table_sections {
            for flag in &mut in_section[start..end] {
                *flag = true;
            }
        }

        // First: print main table options (those not in any section)
        for (opt, &in_sec) in self.options.iter().zip(in_section.iter()) {
            if in_sec {
                continue;
            }
            if (opt.long_name.is_empty() && opt.short_name.is_none()) || opt.flags_doc_hidden {
                continue;
            }
            self.format_option_help(&mut out, opt, max_left_col, indent_length, line_length);
        }

        // Then: print each section (include tables)
        for &(start, end, ref description) in &self.table_sections {
            // Check if this is the auto-alias section
            let is_auto_alias =
                description.as_deref() == Some("Options implemented via popt alias/exec:");

            if is_auto_alias {
                // Skip if no visible aliases
                let has_visible = self.aliases.iter().any(|a| !a.doc_hidden);
                if !has_visible {
                    continue;
                }
            }

            // Print section header
            if let Some(desc) = description {
                let _ = write!(out, "\n{}\n", desc);
            }

            if is_auto_alias {
                // Print non-hidden aliases only
                for alias in &self.aliases {
                    self.format_alias_help(
                        &mut out,
                        alias,
                        max_left_col,
                        indent_length,
                        line_length,
                    );
                }
            } else {
                // Print options in this section
                for i in start..end {
                    let opt = &self.options[i];
                    if (opt.long_name.is_empty() && opt.short_name.is_none())
                        || opt.flags_doc_hidden
                    {
                        continue;
                    }
                    self.format_option_help(
                        &mut out,
                        opt,
                        max_left_col,
                        indent_length,
                        line_length,
                    );
                }
            }
        }
    }

    fn print_usage(&self) {
        use std::io::Write;
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        let max_col: usize = 79;

        // Print "Usage: test1"
        let intro = format!("Usage: {}", self.name);
        let _ = write!(out, "{}", intro);
        let mut cur: usize = intro.len();

        // Collect short options with ArgType::None (no argument) for [-abc] group
        let mut short_opts = String::new();
        self.collect_short_opts_for_usage(&self.options, &mut short_opts);

        if !short_opts.is_empty() {
            let group = format!(" [-{}]", short_opts);
            cur += group.len();
            let _ = write!(out, "{}", group);
        }

        // Print each option
        for opt in &self.options {
            if opt.flags_doc_hidden {
                continue;
            }
            cur = self.format_option_usage(&mut out, opt, cur, max_col);
        }

        // Print alias and exec items
        for alias in &self.aliases {
            if alias.doc_hidden {
                continue;
            }
            let has_short = alias.short_name.is_some();
            let has_long = alias.long_name.is_some();
            if !has_short && !has_long {
                continue;
            }
            cur = format_item_usage(
                &mut out,
                alias.short_name,
                alias.long_name.as_deref(),
                alias.arg_description.as_deref(),
                false,
                cur,
                max_col,
            );
        }
        // Exec aliases are always DOC_HIDDEN in C popt, don't show in usage

        let _ = write!(out, "\n");
    }

    /// Collect short options (NONE type only, not doc_hidden) for the [-abc] group
    fn collect_short_opts_for_usage(&self, options: &[OptionDef], out: &mut String) {
        for opt in options {
            if opt.flags_doc_hidden {
                continue;
            }
            if let Some(ch) = opt.short_name {
                if ch != ' ' && ch.is_ascii_graphic() && !matches!(opt.arg_type, ArgType::None) {
                    continue; // skip options that take arguments
                }
                if matches!(opt.arg_type, ArgType::None) && !out.contains(ch) {
                    out.push(ch);
                }
            }
        }
    }

    /// Calculate the maximum left column width for help formatting
    fn calc_max_left_col(&self) -> usize {
        let mut max: usize = 0;

        for opt in &self.options {
            if opt.flags_doc_hidden {
                continue;
            }
            if opt.long_name.is_empty() && opt.short_name.is_none() {
                continue;
            }
            let w = calc_option_left_width(opt);
            if w > max {
                max = w;
            }
        }

        // Also check aliases and execs
        for alias in &self.aliases {
            if alias.doc_hidden {
                continue;
            }
            let w = calc_alias_left_width(alias);
            if w > max {
                max = w;
            }
        }
        #[cfg(feature = "exec")]
        for exec in &self.execs {
            let w = calc_exec_left_width(exec);
            if w > max {
                max = w;
            }
        }

        max
    }

    /// Get the argument descriptor string for an option (for help/usage display)
    fn get_arg_descrip(opt: &OptionDef) -> Option<String> {
        match &opt.arg_type {
            ArgType::None => None,
            ArgType::Val(_) => None,
            ArgType::Argv => opt.arg_description.clone(),
            _ => {
                if let Some(ref ad) = opt.arg_description {
                    Some(ad.clone())
                } else {
                    match &opt.arg_type {
                        ArgType::Int => Some("INT".to_string()),
                        ArgType::Short => Some("SHORT".to_string()),
                        ArgType::Long => Some("LONG".to_string()),
                        ArgType::LongLong => Some("LONGLONG".to_string()),
                        ArgType::String => Some("STRING".to_string()),
                        ArgType::Float => Some("FLOAT".to_string()),
                        ArgType::Double => Some("DOUBLE".to_string()),
                        ArgType::BitSet => Some("ARG".to_string()),
                        _ => None,
                    }
                }
            }
        }
    }

    /// Format a single option for the usage line, returning the new cursor position
    fn format_option_usage<W: std::io::Write>(
        &self,
        out: &mut W,
        opt: &OptionDef,
        cur: usize,
        max_col: usize,
    ) -> usize {
        let prtshort = opt
            .short_name
            .is_some_and(|c| c != ' ' && c.is_ascii_graphic());
        let prtlong = !opt.long_name.is_empty();

        if !prtshort && !prtlong {
            return cur;
        }

        let arg_descrip = Self::get_arg_descrip(opt);

        // Calculate length
        let mut len: usize = 3; // " []"
        if prtshort {
            len += 2;
        } // "-c"
        if prtlong {
            if prtshort {
                len += 1;
            } // "|"
            len += if opt.flags_onedash { 1 } else { 2 }; // "-" or "--"
            len += opt.long_name.len();
        }
        if let Some(ref ad) = arg_descrip {
            if !ad.starts_with(' ') && !ad.starts_with('=') && !ad.starts_with('(') {
                len += 1; // "="
            }
            len += ad.len();
        }

        let mut cur = cur;
        if cur + len > max_col {
            let _ = write!(out, "\n       "); // 7 spaces
            cur = 7;
        }

        let _ = write!(out, " [");
        if prtshort {
            let _ = write!(out, "-{}", opt.short_name.unwrap());
        }
        if prtlong {
            let sep = if prtshort { "|" } else { "" };
            let dash = if opt.flags_onedash { "-" } else { "--" };
            let _ = write!(out, "{}{}{}", sep, dash, opt.long_name);
        }
        if let Some(ref ad) = arg_descrip {
            if !ad.starts_with(' ') && !ad.starts_with('=') && !ad.starts_with('(') {
                let _ = write!(out, "=");
            }
            let _ = write!(out, "{}", ad);
        }
        let _ = write!(out, "]");

        cur + len + 1 // +1 matches C popt behavior
    }

    /// Format a single option for the help display
    fn format_option_help<W: std::io::Write>(
        &self,
        out: &mut W,
        opt: &OptionDef,
        max_left_col: usize,
        indent_length: usize,
        line_length: usize,
    ) {
        let prtshort = opt
            .short_name
            .is_some_and(|c| c != ' ' && c.is_ascii_graphic());
        let prtlong = !opt.long_name.is_empty();

        if !prtshort && !prtlong {
            return;
        }

        let arg_descrip = Self::get_arg_descrip(opt);

        // Build left column
        let mut left = String::new();
        if prtshort && prtlong {
            let dash = if opt.flags_onedash { "-" } else { "--" };
            left = format!("-{}, {}{}", opt.short_name.unwrap(), dash, opt.long_name);
        } else if prtshort {
            left = format!("-{}", opt.short_name.unwrap());
        } else if prtlong {
            let dash = if opt.flags_onedash { "-" } else { "--" };
            let mut long_name = opt.long_name.as_str();
            let toggle;
            if opt.flags_toggle {
                toggle = "[no]";
                if long_name.starts_with("no") {
                    long_name = &long_name[2..];
                    if long_name.starts_with('-') {
                        long_name = &long_name[1..];
                    }
                }
            } else {
                toggle = "";
            }
            left = format!("    {}{}{}", dash, toggle, long_name);
        }

        // Append argument descriptor
        if let Some(ref ad) = arg_descrip {
            if opt.flags_optional {
                left.push('[');
            }

            // Separator: for custom argDescrip with ARGV type, use space; else =
            if let Some(ref custom_ad) = opt.arg_description {
                if !custom_ad.starts_with(' ')
                    && !custom_ad.starts_with('=')
                    && !custom_ad.starts_with('(')
                {
                    match &opt.arg_type {
                        ArgType::Argv => left.push(' '),
                        _ => left.push('='),
                    }
                }
                left.push_str(custom_ad);
            } else {
                // Auto-generated argDescrip
                let sep = if prtlong { '=' } else { ' ' };
                left.push(sep);
                left.push_str(ad);
            }

            if opt.flags_optional {
                left.push(']');
            }
        }

        // Build help text with default value
        let mut help_text = opt.description.clone().unwrap_or_default();
        if opt.flags_show_default && arg_descrip.is_some() {
            let default_str = self.format_default_value(opt, line_length);
            if let Some(ds) = default_str {
                help_text.push(' ');
                help_text.push_str(&ds);
            }
        }

        if !help_text.is_empty() {
            // Print with alignment
            let _ = write!(out, "  {:width$}   ", left, width = max_left_col);
            // Word-wrap the help text
            write_wrapped_text(out, &help_text, indent_length, line_length);
        } else {
            let _ = write!(out, "  {}\n", left);
        }
    }

    /// Format the default value string for an option
    fn format_default_value(&self, opt: &OptionDef, line_length: usize) -> Option<String> {
        let mut result = String::from("(default: ");
        match opt.default_value.as_ref() {
            Some(dv) => match dv {
                StoredValue::Int(v) => result.push_str(&format!("{}", v)),
                StoredValue::Short(v) => result.push_str(&format!("{}", v)),
                StoredValue::Long(v) => result.push_str(&format!("{}", v)),
                StoredValue::LongLong(v) => result.push_str(&format!("{}", v)),
                StoredValue::Float(v) => {
                    let s = c_format_g(*v as f64);
                    result.push_str(&s);
                }
                StoredValue::Double(v) => {
                    let s = c_format_g(*v);
                    result.push_str(&s);
                }
                StoredValue::Str(s) => {
                    // Match C sizeof("\"\")") = 4
                    let limit = 4 * line_length - result.len() - 4;
                    result.push('"');
                    if s.len() <= limit {
                        result.push_str(s);
                    } else {
                        result.push_str(&s[..limit]);
                        // Replace last 3 chars with ...
                        let rlen = result.len();
                        result.replace_range((rlen - 3).., "...");
                    }
                    result.push('"');
                }
                StoredValue::Bool(_)
                | StoredValue::Argv(_)
                | StoredValue::Uint(_)
                | StoredValue::Bits(_) => {
                    return None;
                }
            },
            None => {
                // For String type with no default, show "null"
                match &opt.arg_type {
                    ArgType::String => result.push_str("null"),
                    _ => return None,
                }
            }
        }
        result.push(')');
        Some(result)
    }

    /// Format alias for help display
    fn format_alias_help<W: std::io::Write>(
        &self,
        out: &mut W,
        alias: &Alias,
        max_left_col: usize,
        indent_length: usize,
        line_length: usize,
    ) {
        if alias.doc_hidden {
            return;
        }
        let has_long = alias.long_name.is_some();
        let has_short = alias.short_name.is_some();
        if !has_long && !has_short {
            return;
        }

        // Build left column
        let mut left = String::new();
        if has_short && has_long {
            left = format!(
                "-{}, --{}",
                alias.short_name.unwrap(),
                alias.long_name.as_ref().unwrap()
            );
        } else if has_short {
            left = format!("-{}", alias.short_name.unwrap());
        } else if has_long {
            left = format!("    --{}", alias.long_name.as_ref().unwrap());
        }

        // Append arg description
        if let Some(ref ad) = alias.arg_description {
            if !ad.starts_with(' ') && !ad.starts_with('=') && !ad.starts_with('(') {
                left.push('=');
            }
            left.push_str(ad);
        }

        let help_text = alias.description.clone().unwrap_or_default();
        if !help_text.is_empty() {
            let _ = write!(out, "  {:width$}   ", left, width = max_left_col);
            write_wrapped_text(out, &help_text, indent_length, line_length);
        } else {
            let _ = write!(out, "  {}\n", left);
        }
    }

    /// Get a typed value by option name (or store_as name)
    pub fn get<T: FromStoredValue>(&self, name: &str) -> Result<T> {
        match self.values.get(name) {
            Some(v) => T::from_stored_value(v),
            None => Err(Error::NotFound(name.to_string())),
        }
    }

    /// Check if an option was explicitly given on the command line
    pub fn is_present(&self, name: &str) -> bool {
        self.present.contains(name)
    }

    /// Get remaining positional arguments
    pub fn args(&self) -> Vec<String> {
        self.remaining.clone()
    }
}

// ============================================================================
// Lookup3 Hash (Bob Jenkins) — used by BloomFilter
// ============================================================================

fn jlu3_mix(a: &mut u32, b: &mut u32, c: &mut u32) {
    *a = (*a).wrapping_sub(*c);
    *a ^= (*c).rotate_left(4);
    *c = (*c).wrapping_add(*b);
    *b = (*b).wrapping_sub(*a);
    *b ^= (*a).rotate_left(6);
    *a = (*a).wrapping_add(*c);
    *c = (*c).wrapping_sub(*b);
    *c ^= (*b).rotate_left(8);
    *b = (*b).wrapping_add(*a);
    *a = (*a).wrapping_sub(*c);
    *a ^= (*c).rotate_left(16);
    *c = (*c).wrapping_add(*b);
    *b = (*b).wrapping_sub(*a);
    *b ^= (*a).rotate_left(19);
    *a = (*a).wrapping_add(*c);
    *c = (*c).wrapping_sub(*b);
    *c ^= (*b).rotate_left(4);
    *b = (*b).wrapping_add(*a);
}

fn jlu3_final(a: &mut u32, b: &mut u32, c: &mut u32) {
    *c ^= *b;
    *c = (*c).wrapping_sub((*b).rotate_left(14));
    *a ^= *c;
    *a = (*a).wrapping_sub((*c).rotate_left(11));
    *b ^= *a;
    *b = (*b).wrapping_sub((*a).rotate_left(25));
    *c ^= *b;
    *c = (*c).wrapping_sub((*b).rotate_left(16));
    *a ^= *c;
    *a = (*a).wrapping_sub((*c).rotate_left(4));
    *b ^= *a;
    *b = (*b).wrapping_sub((*a).rotate_left(14));
    *c ^= *b;
    *c = (*c).wrapping_sub((*b).rotate_left(24));
}

/// Bob Jenkins lookup3 hash pair (byte-at-a-time little-endian path).
/// Returns (primary_hash, secondary_hash) with initial seeds of 0.
fn jlu32lpair(key: &[u8]) -> (u32, u32) {
    let size = key.len();
    let init = 0xdeadbeef_u32.wrapping_add(size as u32); // _JLU3_INIT(0, size)
    let mut a = init;
    let mut b = init;
    let mut c = init;
    // pc=0, pb=0 initial seeds → c += 0 is no-op

    let mut k = key;
    let mut remaining = size;

    // Process 12-byte blocks
    while remaining > 12 {
        a = a.wrapping_add(k[0] as u32);
        a = a.wrapping_add((k[1] as u32) << 8);
        a = a.wrapping_add((k[2] as u32) << 16);
        a = a.wrapping_add((k[3] as u32) << 24);
        b = b.wrapping_add(k[4] as u32);
        b = b.wrapping_add((k[5] as u32) << 8);
        b = b.wrapping_add((k[6] as u32) << 16);
        b = b.wrapping_add((k[7] as u32) << 24);
        c = c.wrapping_add(k[8] as u32);
        c = c.wrapping_add((k[9] as u32) << 8);
        c = c.wrapping_add((k[10] as u32) << 16);
        c = c.wrapping_add((k[11] as u32) << 24);
        jlu3_mix(&mut a, &mut b, &mut c);
        remaining -= 12;
        k = &k[12..];
    }

    // Last block (fall-through pattern from C switch)
    if remaining == 0 {
        return (c, b);
    }
    if remaining >= 12 {
        c = c.wrapping_add((k[11] as u32) << 24);
    }
    if remaining >= 11 {
        c = c.wrapping_add((k[10] as u32) << 16);
    }
    if remaining >= 10 {
        c = c.wrapping_add((k[9] as u32) << 8);
    }
    if remaining >= 9 {
        c = c.wrapping_add(k[8] as u32);
    }
    if remaining >= 8 {
        b = b.wrapping_add((k[7] as u32) << 24);
    }
    if remaining >= 7 {
        b = b.wrapping_add((k[6] as u32) << 16);
    }
    if remaining >= 6 {
        b = b.wrapping_add((k[5] as u32) << 8);
    }
    if remaining >= 5 {
        b = b.wrapping_add(k[4] as u32);
    }
    if remaining >= 4 {
        a = a.wrapping_add((k[3] as u32) << 24);
    }
    if remaining >= 3 {
        a = a.wrapping_add((k[2] as u32) << 16);
    }
    if remaining >= 2 {
        a = a.wrapping_add((k[1] as u32) << 8);
    }
    if remaining >= 1 {
        a = a.wrapping_add(k[0] as u32);
    }

    jlu3_final(&mut a, &mut b, &mut c);
    (c, b)
}

// ============================================================================
// BloomFilter
// ============================================================================

const BLOOM_DEFAULT_N: u32 = 1024;
const BLOOM_DEFAULT_K: u32 = 16;

#[derive(Debug, Clone)]
pub struct BloomFilter {
    bits: Vec<u32>,
    k: u32,
    m: u32,
}

impl BloomFilter {
    pub fn new() -> Self {
        Self::with_sizing(BLOOM_DEFAULT_K, BLOOM_DEFAULT_N)
    }

    pub fn with_sizing(k: u32, n: u32) -> Self {
        let k = if k == 0 || k > 32 { BLOOM_DEFAULT_K } else { k };
        let n = if n == 0 { BLOOM_DEFAULT_N } else { n };
        let m = (3 * n) / 2;
        let nwords = (m as usize).saturating_sub(1) / 32 + 1;
        BloomFilter {
            bits: vec![0u32; nwords],
            k,
            m,
        }
    }

    pub fn insert(&mut self, s: &str) {
        let (h0, h1) = jlu32lpair(s.as_bytes());
        for i in 0..self.k {
            let h = h0.wrapping_add(i.wrapping_mul(h1));
            let ix = h % self.m;
            self.bits[(ix / 32) as usize] |= 1u32 << (ix % 32);
        }
    }

    pub fn contains(&self, s: &str) -> bool {
        let (h0, h1) = jlu32lpair(s.as_bytes());
        for i in 0..self.k {
            let h = h0.wrapping_add(i.wrapping_mul(h1));
            let ix = h % self.m;
            if self.bits[(ix / 32) as usize] & (1u32 << (ix % 32)) == 0 {
                return false;
            }
        }
        true
    }

    pub fn remove(&mut self, s: &str) {
        let (h0, h1) = jlu32lpair(s.as_bytes());
        for i in 0..self.k {
            let h = h0.wrapping_add(i.wrapping_mul(h1));
            let ix = h % self.m;
            self.bits[(ix / 32) as usize] &= !(1u32 << (ix % 32));
        }
    }

    pub fn clear(&mut self) {
        for w in &mut self.bits {
            *w = 0;
        }
    }

    pub fn union(&mut self, other: &BloomFilter) {
        let nw = self.bits.len().min(other.bits.len());
        for i in 0..nw {
            self.bits[i] |= other.bits[i];
        }
    }

    pub fn intersect(&mut self, other: &BloomFilter) -> bool {
        let nw = self.bits.len().min(other.bits.len());
        let mut any = 0u32;
        for i in 0..nw {
            self.bits[i] &= other.bits[i];
            any |= self.bits[i];
        }
        any != 0
    }

    /// Parse comma-separated items into the bloom filter.
    /// Items prefixed with '!' are removed (if present).
    pub fn save_bits(&mut self, s: &str) {
        for token in s.split(',') {
            if token.is_empty() {
                continue;
            }
            if let Some(rest) = token.strip_prefix('!') {
                if self.contains(rest) {
                    self.remove(rest);
                }
            } else {
                self.insert(token);
            }
        }
    }
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Config file utilities
// ============================================================================

/// Convert a config file to an argv-style string.
///
/// Each non-empty, non-comment line becomes `--key` (bare) or `--key="value"` (with value).
/// Lines with spaces in the key name (before `=`) are silently ignored.
/// Lines with empty values after `=` are silently ignored.
pub fn config_file_to_string(path: &str) -> Result<String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| Error::ConfigFile(format!("Failed to open {}: {}", path, e)))?;

    let mut result = std::string::String::new();

    for line in content.lines() {
        // Strip leading whitespace
        let l = line.trim_start();

        // Skip empty lines and comments
        if l.is_empty() || l.starts_with('#') {
            continue;
        }

        // Find key: non-space, non-= characters from the start
        let key_end = l
            .find(|c: char| c.is_ascii_whitespace() || c == '=')
            .unwrap_or(l.len());
        let key = &l[..key_end];

        if key.is_empty() {
            continue;
        }

        // After key, skip whitespace
        let rest = &l[key_end..];
        let rest = rest.trim_start();

        if rest.is_empty() {
            // Bare option (no = sign, nothing after key)
            result.push_str(" --");
            result.push_str(key);
            continue;
        }

        if !rest.starts_with('=') {
            // Something after key that's not '=' — silently ignore (e.g., "reall bad line")
            continue;
        }

        // Skip the '=' and whitespace after it
        let value_part = rest[1..].trim_start();

        // Strip trailing whitespace from value
        let value = value_part.trim_end();

        if value.is_empty() {
            // Empty value — silently ignore
            continue;
        }

        // Append --key="value"
        result.push_str(" --");
        result.push_str(key);
        result.push_str("=\"");
        result.push_str(value);
        result.push('"');
    }

    Ok(result)
}

/// Parse an argv-style string into a vector of arguments.
///
/// Handles single and double quoting, backslash escaping.
/// Matches popt's `poptParseArgvString` behavior.
pub fn parse_argv_string(s: &str) -> Result<Vec<String>> {
    let mut args = Vec::new();
    let mut current = std::string::String::new();
    let mut quote: Option<char> = None;
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            // Inside quotes
            if c == q {
                // End quote
                quote = None;
            } else if c == '\\' {
                // Backslash inside quotes
                match chars.next() {
                    None => return Err(Error::BadQuote("unterminated backslash".to_string())),
                    Some(next) => {
                        if next != q {
                            current.push('\\');
                        }
                        current.push(next);
                    }
                }
            } else {
                current.push(c);
            }
        } else if c.is_ascii_whitespace() {
            // Outside quotes, whitespace delimits tokens
            if !current.is_empty() {
                args.push(std::mem::take(&mut current));
            }
        } else {
            match c {
                '"' | '\'' => {
                    quote = Some(c);
                }
                '\\' => match chars.next() {
                    None => return Err(Error::BadQuote("unterminated backslash".to_string())),
                    Some(next) => {
                        current.push(next);
                    }
                },
                _ => {
                    current.push(c);
                }
            }
        }
    }

    // Don't forget the last token
    if !current.is_empty() {
        args.push(current);
    }

    Ok(args)
}
