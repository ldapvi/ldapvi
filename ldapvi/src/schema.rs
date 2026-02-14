use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};

// ---------------------------------------------------------------------------
// CaseFold — case-insensitive string key for HashMap
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CaseFold(String);

impl CaseFold {
    fn new(s: &str) -> Self {
        CaseFold(s.to_string())
    }
}

impl PartialEq for CaseFold {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl Eq for CaseFold {}

impl Hash for CaseFold {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for b in self.0.bytes() {
            state.write_u8(b.to_ascii_lowercase());
        }
    }
}

// ---------------------------------------------------------------------------
// ObjectClass, AttributeType
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectClassKind {
    Abstract,
    Structural,
    Auxiliary,
}

#[derive(Debug, Clone)]
pub struct ObjectClass {
    pub oid: String,
    pub names: Vec<String>,
    pub sup: Vec<String>,
    pub kind: ObjectClassKind,
    pub must: Vec<String>,
    pub may: Vec<String>,
}

impl ObjectClass {
    pub fn name(&self) -> &str {
        self.names.first().map(|s| s.as_str()).unwrap_or(&self.oid)
    }
}

impl fmt::Display for ObjectClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[derive(Debug, Clone)]
pub struct AttributeType {
    pub oid: String,
    pub names: Vec<String>,
}

impl AttributeType {
    pub fn name(&self) -> &str {
        self.names.first().map(|s| s.as_str()).unwrap_or(&self.oid)
    }
}

impl fmt::Display for AttributeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ---------------------------------------------------------------------------
// RFC 4512 schema definition parsers
// ---------------------------------------------------------------------------

/// Tokenizer for RFC 4512 schema definitions.
struct SchemaTokenizer<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> SchemaTokenizer<'a> {
    fn new(input: &'a str) -> Self {
        SchemaTokenizer { input, pos: 0 }
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len() && self.input.as_bytes()[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    /// Read the next token. Returns None at end of input.
    /// Tokens: '(', ')', '$', quoted strings 'name', or bare words.
    fn next_token(&mut self) -> Option<String> {
        self.skip_whitespace();
        if self.pos >= self.input.len() {
            return None;
        }
        let b = self.input.as_bytes()[self.pos];
        match b {
            b'(' | b')' | b'$' => {
                self.pos += 1;
                Some((b as char).to_string())
            }
            b'\'' => {
                // Quoted string
                self.pos += 1; // skip opening quote
                let start = self.pos;
                while self.pos < self.input.len() && self.input.as_bytes()[self.pos] != b'\'' {
                    self.pos += 1;
                }
                let s = self.input[start..self.pos].to_string();
                if self.pos < self.input.len() {
                    self.pos += 1; // skip closing quote
                }
                Some(s)
            }
            _ => {
                // Bare word (OID, keyword, etc.)
                let start = self.pos;
                while self.pos < self.input.len() {
                    let c = self.input.as_bytes()[self.pos];
                    if c.is_ascii_whitespace() || c == b'(' || c == b')' || c == b'\'' || c == b'$'
                    {
                        break;
                    }
                    self.pos += 1;
                }
                Some(self.input[start..self.pos].to_string())
            }
        }
    }

    /// Read a single name or OID: either a quoted 'name' or a bare word.
    fn read_single_value(&mut self) -> Option<String> {
        self.next_token()
    }

    /// Read a list of names/OIDs: either a single value or ( val1 $ val2 ... ).
    fn read_oid_list(&mut self) -> Vec<String> {
        self.skip_whitespace();
        if self.pos < self.input.len() && self.input.as_bytes()[self.pos] == b'(' {
            // Parenthesized list
            self.next_token(); // consume '('
            let mut result = Vec::new();
            while let Some(tok) = self.next_token() {
                if tok == ")" {
                    break;
                }
                if tok == "$" {
                    continue;
                }
                result.push(tok);
            }
            result
        } else {
            // Single value
            match self.read_single_value() {
                Some(v) if v != ")" => vec![v],
                _ => vec![],
            }
        }
    }

    /// Skip past the next token or parenthesized group (for unrecognized keywords).
    fn skip_value(&mut self) {
        self.skip_whitespace();
        if self.pos < self.input.len() && self.input.as_bytes()[self.pos] == b'(' {
            // Skip parenthesized group
            self.next_token(); // '('
            let mut depth = 1;
            while depth > 0 {
                match self.next_token() {
                    Some(t) if t == "(" => depth += 1,
                    Some(t) if t == ")" => depth -= 1,
                    None => break,
                    _ => {}
                }
            }
        } else if self.pos < self.input.len() && self.input.as_bytes()[self.pos] == b'\'' {
            // Skip quoted string
            self.next_token();
        } else {
            // Skip bare word (but don't skip keywords or closing paren)
            // Peek — if next token looks like a keyword (all uppercase or ')'), don't consume
            let saved_pos = self.pos;
            if let Some(tok) = self.next_token() {
                if tok == ")" || tok.chars().all(|c| c.is_ascii_uppercase() || c == '-') {
                    // Put it back — it's a keyword, not a value
                    self.pos = saved_pos;
                }
                // Otherwise we consumed the value
            }
        }
    }
}

/// Parse an RFC 4512 ObjectClassDescription string.
pub fn parse_objectclass(s: &str) -> Result<ObjectClass, String> {
    let mut tok = SchemaTokenizer::new(s);

    // Expect opening '('
    match tok.next_token() {
        Some(t) if t == "(" => {}
        _ => return Err("expected '('".to_string()),
    }

    // Read OID
    let oid = tok.next_token().ok_or_else(|| "expected OID".to_string())?;

    let mut names = Vec::new();
    let mut sup = Vec::new();
    let mut kind = ObjectClassKind::Structural; // default per RFC 4512
    let mut must = Vec::new();
    let mut may = Vec::new();

    // Read keyword-value pairs until ')'
    loop {
        let keyword = match tok.next_token() {
            Some(t) if t == ")" => break,
            Some(t) => t,
            None => break,
        };
        match keyword.as_str() {
            "NAME" => names = tok.read_oid_list(),
            "SUP" => sup = tok.read_oid_list(),
            "ABSTRACT" => kind = ObjectClassKind::Abstract,
            "STRUCTURAL" => kind = ObjectClassKind::Structural,
            "AUXILIARY" => kind = ObjectClassKind::Auxiliary,
            "MUST" => must = tok.read_oid_list(),
            "MAY" => may = tok.read_oid_list(),
            "DESC" | "OBSOLETE" | "X-ORIGIN" | "X-SCHEMA-FILE" => {
                tok.skip_value();
            }
            _ => {
                // Unknown keyword — skip its value if any
                tok.skip_value();
            }
        }
    }

    Ok(ObjectClass {
        oid,
        names,
        sup,
        kind,
        must,
        may,
    })
}

/// Parse an RFC 4512 AttributeTypeDescription string.
pub fn parse_attributetype(s: &str) -> Result<AttributeType, String> {
    let mut tok = SchemaTokenizer::new(s);

    match tok.next_token() {
        Some(t) if t == "(" => {}
        _ => return Err("expected '('".to_string()),
    }

    let oid = tok.next_token().ok_or_else(|| "expected OID".to_string())?;

    let mut names = Vec::new();

    loop {
        let keyword = match tok.next_token() {
            Some(t) if t == ")" => break,
            Some(t) => t,
            None => break,
        };
        match keyword.as_str() {
            "NAME" => names = tok.read_oid_list(),
            _ => {
                tok.skip_value();
            }
        }
    }

    Ok(AttributeType { oid, names })
}

// ---------------------------------------------------------------------------
// Schema — case-insensitive lookup tables
// ---------------------------------------------------------------------------

pub struct Schema {
    classes: HashMap<CaseFold, ObjectClass>,
    class_index: HashMap<CaseFold, usize>,
    class_list: Vec<String>, // canonical OIDs
    types: HashMap<CaseFold, AttributeType>,
    type_index: HashMap<CaseFold, usize>,
    type_list: Vec<String>,
}

impl Default for Schema {
    fn default() -> Self {
        Self::new()
    }
}

impl Schema {
    pub fn new() -> Self {
        Schema {
            classes: HashMap::new(),
            class_index: HashMap::new(),
            class_list: Vec::new(),
            types: HashMap::new(),
            type_index: HashMap::new(),
            type_list: Vec::new(),
        }
    }

    pub fn add_objectclass(&mut self, cls: ObjectClass) {
        let oid = cls.oid.clone();
        let idx = self.class_list.len();
        self.class_list.push(oid.clone());

        // Index by OID
        self.class_index.insert(CaseFold::new(&oid), idx);
        // Index by each name
        for name in &cls.names {
            self.class_index.insert(CaseFold::new(name), idx);
        }
        self.classes.insert(CaseFold::new(&oid), cls);
    }

    pub fn add_attributetype(&mut self, at: AttributeType) {
        let oid = at.oid.clone();
        let idx = self.type_list.len();
        self.type_list.push(oid.clone());

        self.type_index.insert(CaseFold::new(&oid), idx);
        for name in &at.names {
            self.type_index.insert(CaseFold::new(name), idx);
        }
        self.types.insert(CaseFold::new(&oid), at);
    }

    pub fn get_objectclass(&self, name: &str) -> Option<&ObjectClass> {
        let idx = self.class_index.get(&CaseFold::new(name))?;
        let oid = &self.class_list[*idx];
        self.classes.get(&CaseFold::new(oid))
    }

    pub fn get_attributetype(&self, name: &str) -> Option<&AttributeType> {
        let idx = self.type_index.get(&CaseFold::new(name))?;
        let oid = &self.type_list[*idx];
        self.types.get(&CaseFold::new(oid))
    }
}

// ---------------------------------------------------------------------------
// Entroid — computed MUST/MAY attributes for a set of objectClasses
// ---------------------------------------------------------------------------

pub struct Entroid<'a> {
    schema: &'a Schema,
    pub classes: Vec<&'a ObjectClass>,
    pub must: Vec<&'a AttributeType>,
    pub may: Vec<&'a AttributeType>,
    pub structural: Option<&'a ObjectClass>,
    pub comment: String,
    pub error: String,
}

impl<'a> Entroid<'a> {
    pub fn new(schema: &'a Schema) -> Self {
        Entroid {
            schema,
            classes: Vec::new(),
            must: Vec::new(),
            may: Vec::new(),
            structural: None,
            comment: String::new(),
            error: String::new(),
        }
    }

    pub fn reset(&mut self) {
        self.classes.clear();
        self.must.clear();
        self.may.clear();
        self.structural = None;
        self.comment.clear();
        self.error.clear();
    }

    pub fn get_objectclass(&mut self, name: &str) -> Option<&'a ObjectClass> {
        match self.schema.get_objectclass(name) {
            Some(cls) => Some(cls),
            None => {
                self.error
                    .push_str(&format!("Unknown objectClass: {}\n", name));
                None
            }
        }
    }

    pub fn get_attributetype(&mut self, name: &str) -> Option<&'a AttributeType> {
        match self.schema.get_attributetype(name) {
            Some(at) => Some(at),
            None => {
                self.error
                    .push_str(&format!("Unknown attributeType: {}\n", name));
                None
            }
        }
    }

    /// Request an objectClass to be included. Deduplicates by pointer identity.
    pub fn request_class(&mut self, name: &str) -> Option<&'a ObjectClass> {
        let cls = self.get_objectclass(name)?;
        let ptr = cls as *const ObjectClass;
        if !self.classes.iter().any(|c| std::ptr::eq(*c, ptr)) {
            self.classes.push(cls);
        }
        Some(cls)
    }

    /// Compute the full entroid from the requested object classes.
    ///
    /// Add all superclasses to `self.classes`; collect required and optional
    /// attributes into `self.must` and `self.may`.  Set `self.structural`
    /// to the structural objectclass, if any.  Trace output for user
    /// display goes into `self.comment`; errors into `self.error`.
    pub fn compute(&mut self) -> Result<(), String> {
        // We need to iterate by index because compute_one may add new classes.
        let mut i = 0;
        while i < self.classes.len() {
            let cls = self.classes[i];
            self.compute_one(cls)?;
            i += 1;
        }

        if self.structural.is_none() {
            self.comment
                .push_str("### WARNING: no structural object class\n");
        }

        Ok(())
    }

    fn compute_one(&mut self, cls: &'a ObjectClass) -> Result<(), String> {
        // Add superclasses
        for sup_name in &cls.sup {
            if self.request_class(sup_name).is_none() {
                return Err(format!("superclass not found: {}", sup_name));
            }
        }

        // Track structural class
        if cls.kind == ObjectClassKind::Structural {
            if self.structural.is_some() {
                self.comment.push_str(&format!(
                    "### WARNING: extra structural object class: {}\n",
                    cls.name()
                ));
            } else {
                self.comment
                    .push_str(&format!("# structural object class: {}\n", cls.name()));
                self.structural = Some(cls);
            }
        }

        // Process MUST attributes
        for attr_name in &cls.must {
            let at = match self.get_attributetype(attr_name) {
                Some(at) => at,
                None => return Err(format!("attribute type not found: {}", attr_name)),
            };
            let at_ptr = at as *const AttributeType;
            // Remove from MAY if present
            self.may.retain(|m| !std::ptr::eq(*m, at_ptr));
            // Add to MUST if not already present
            if !self.must.iter().any(|m| std::ptr::eq(*m, at_ptr)) {
                self.must.push(at);
            }
        }

        // Process MAY attributes
        for attr_name in &cls.may {
            let at = match self.get_attributetype(attr_name) {
                Some(at) => at,
                None => return Err(format!("attribute type not found: {}", attr_name)),
            };
            let at_ptr = at as *const AttributeType;
            // Only add to MAY if not already in MUST
            let in_must = self.must.iter().any(|m| std::ptr::eq(*m, at_ptr));
            if !in_must {
                self.may.push(at);
            }
        }

        Ok(())
    }

    /// Remove an attribute descriptor from MUST or MAY lists.
    /// Handles attribute options by stripping the `;option` suffix.
    /// Returns true if the attribute was found and removed.
    pub fn remove_ad(&mut self, ad: &str) -> bool {
        // Strip options suffix (e.g., "cn;binary" → "cn")
        let base_name = match ad.find(';') {
            Some(pos) => &ad[..pos],
            None => ad,
        };

        let at = match self.schema.get_attributetype(base_name) {
            Some(at) => at,
            None => return false,
        };
        let at_ptr = at as *const AttributeType;

        // Try removing from MUST
        let must_len = self.must.len();
        self.must.retain(|m| !std::ptr::eq(*m, at_ptr));
        if self.must.len() < must_len {
            return true;
        }

        // Try removing from MAY
        let may_len = self.may.len();
        self.may.retain(|m| !std::ptr::eq(*m, at_ptr));
        if self.may.len() < may_len {
            return true;
        }

        false
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Test fixture: builds a schema with top, person, organizationalPerson
    fn make_test_schema() -> Schema {
        let mut schema = Schema::new();

        schema.add_attributetype(parse_attributetype("( 2.5.4.0 NAME 'objectClass' )").unwrap());
        schema.add_attributetype(parse_attributetype("( 2.5.4.3 NAME 'cn' )").unwrap());
        schema.add_attributetype(parse_attributetype("( 2.5.4.4 NAME 'sn' )").unwrap());
        schema.add_attributetype(parse_attributetype("( 2.5.4.35 NAME 'userPassword' )").unwrap());
        schema
            .add_attributetype(parse_attributetype("( 2.5.4.20 NAME 'telephoneNumber' )").unwrap());
        schema.add_attributetype(parse_attributetype("( 2.5.4.34 NAME 'seeAlso' )").unwrap());
        schema.add_attributetype(parse_attributetype("( 2.5.4.13 NAME 'description' )").unwrap());

        schema.add_objectclass(
            parse_objectclass("( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )").unwrap(),
        );
        schema.add_objectclass(
            parse_objectclass(
                "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL \
                 MUST ( sn $ cn ) \
                 MAY ( userPassword $ telephoneNumber $ seeAlso $ description ) )",
            )
            .unwrap(),
        );
        schema.add_objectclass(
            parse_objectclass(
                "( 2.5.6.7 NAME 'organizationalPerson' SUP person STRUCTURAL \
                 MAY ( telephoneNumber $ seeAlso $ description ) )",
            )
            .unwrap(),
        );

        schema
    }

    // -- Group 1: Name extraction --

    #[test]
    fn objectclass_name_with_names() {
        let cls = parse_objectclass("( 1.2.3 NAME 'testClass' )").unwrap();
        assert_eq!(cls.name(), "testClass");
    }

    #[test]
    fn objectclass_name_oid_only() {
        let cls = parse_objectclass("( 1.2.3.4.5 )").unwrap();
        assert_eq!(cls.name(), "1.2.3.4.5");
    }

    #[test]
    fn attributetype_name_with_names() {
        let at = parse_attributetype("( 1.2.3 NAME 'testAttr' )").unwrap();
        assert_eq!(at.name(), "testAttr");
    }

    #[test]
    fn attributetype_name_oid_only() {
        let at = parse_attributetype("( 9.8.7.6 )").unwrap();
        assert_eq!(at.name(), "9.8.7.6");
    }

    // -- Group 2: Schema lookups --

    #[test]
    fn schema_get_objectclass_by_name() {
        let schema = make_test_schema();
        let cls = schema.get_objectclass("person").unwrap();
        assert_eq!(cls.name(), "person");
    }

    #[test]
    fn schema_get_objectclass_case_insensitive() {
        let schema = make_test_schema();
        let cls = schema.get_objectclass("perSON").unwrap();
        assert_eq!(cls.name(), "person");
    }

    #[test]
    fn schema_get_attributetype_by_name() {
        let schema = make_test_schema();
        let at = schema.get_attributetype("cn").unwrap();
        assert_eq!(at.name(), "cn");
    }

    #[test]
    fn schema_get_attributetype_not_found() {
        let schema = make_test_schema();
        assert!(schema.get_attributetype("noSuchAttr").is_none());
    }

    // -- Group 3: Entroid lifecycle --

    #[test]
    fn entroid_new_initializes() {
        let schema = make_test_schema();
        let ent = Entroid::new(&schema);
        assert_eq!(ent.classes.len(), 0);
        assert_eq!(ent.must.len(), 0);
        assert_eq!(ent.may.len(), 0);
        assert!(ent.structural.is_none());
        assert!(ent.comment.is_empty());
        assert!(ent.error.is_empty());
    }

    #[test]
    fn entroid_reset_clears() {
        let schema = make_test_schema();
        let mut ent = Entroid::new(&schema);
        ent.request_class("person");
        ent.compute().unwrap();

        assert!(ent.classes.len() > 0);
        assert!(ent.must.len() > 0);

        ent.reset();

        assert_eq!(ent.classes.len(), 0);
        assert_eq!(ent.must.len(), 0);
        assert_eq!(ent.may.len(), 0);
        assert!(ent.structural.is_none());
        assert!(ent.comment.is_empty());
        assert!(ent.error.is_empty());
    }

    #[test]
    fn entroid_drop_no_crash() {
        let schema = make_test_schema();
        let ent = Entroid::new(&schema);
        drop(ent);
    }

    // -- Group 4: Entroid lookups --

    #[test]
    fn entroid_get_objectclass_found() {
        let schema = make_test_schema();
        let mut ent = Entroid::new(&schema);
        let cls = ent.get_objectclass("person");
        assert!(cls.is_some());
        assert!(ent.error.is_empty());
    }

    #[test]
    fn entroid_get_objectclass_not_found() {
        let schema = make_test_schema();
        let mut ent = Entroid::new(&schema);
        let cls = ent.get_objectclass("noSuchClass");
        assert!(cls.is_none());
        assert!(ent.error.contains("noSuchClass"));
    }

    // -- Group 5: Class deduplication --

    #[test]
    fn entroid_request_class_dedup() {
        let schema = make_test_schema();
        let mut ent = Entroid::new(&schema);
        ent.request_class("person");
        ent.request_class("person");
        assert_eq!(ent.classes.len(), 1);
    }

    // -- Group 6: Entroid computation --

    #[test]
    fn compute_entroid_person() {
        let schema = make_test_schema();
        let mut ent = Entroid::new(&schema);
        ent.request_class("person");
        ent.compute().unwrap();

        // classes should include person + top (superclass)
        assert!(ent.classes.len() >= 2);
        assert!(ent.structural.is_some());
        assert_eq!(ent.structural.unwrap().name(), "person");

        // must should include sn, cn (from person) and objectClass (from top)
        assert!(ent.must.len() >= 3);
        let must_names: Vec<&str> = ent.must.iter().map(|at| at.name()).collect();
        assert!(must_names.contains(&"sn"));
        assert!(must_names.contains(&"cn"));
        assert!(must_names.contains(&"objectClass"));

        // may should include userPassword etc.
        assert!(ent.may.len() >= 1);

        // comment should mention structural
        assert!(ent.comment.contains("structural"));
    }

    #[test]
    fn compute_entroid_no_structural_warning() {
        let schema = make_test_schema();
        let mut ent = Entroid::new(&schema);
        ent.request_class("top");
        let rc = ent.compute();
        assert!(rc.is_ok());
        assert!(ent.structural.is_none());
        assert!(ent.comment.contains("WARNING"));
        assert!(ent.comment.contains("no structural"));
    }

    #[test]
    fn compute_entroid_unknown_class() {
        let schema = make_test_schema();
        let mut ent = Entroid::new(&schema);
        let cls = ent.request_class("bogusClass");
        assert!(cls.is_none());
        assert!(ent.error.len() > 0);
    }

    // -- Group 7: Attribute removal --

    #[test]
    fn entroid_remove_ad_from_must() {
        let schema = make_test_schema();
        let mut ent = Entroid::new(&schema);
        ent.request_class("person");
        ent.compute().unwrap();

        let must_before = ent.must.len();
        let found = ent.remove_ad("cn");
        assert!(found);
        assert_eq!(ent.must.len(), must_before - 1);
    }

    #[test]
    fn entroid_remove_ad_with_option() {
        let schema = make_test_schema();
        let mut ent = Entroid::new(&schema);
        ent.request_class("person");
        ent.compute().unwrap();

        let must_before = ent.must.len();
        let found = ent.remove_ad("cn;binary");
        assert!(found);
        assert_eq!(ent.must.len(), must_before - 1);
    }

    #[test]
    fn entroid_remove_ad_not_found() {
        let schema = make_test_schema();
        let mut ent = Entroid::new(&schema);
        ent.request_class("person");
        ent.compute().unwrap();

        let found = ent.remove_ad("nonExistentAttr");
        assert!(!found);
    }

    // -- Group 8: RFC 4512 parsing --

    #[test]
    fn parse_objectclass_full() {
        let cls = parse_objectclass(
            "( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL \
             MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber ) )",
        )
        .unwrap();
        assert_eq!(cls.oid, "2.5.6.6");
        assert_eq!(cls.names, vec!["person"]);
        assert_eq!(cls.sup, vec!["top"]);
        assert_eq!(cls.kind, ObjectClassKind::Structural);
        assert_eq!(cls.must, vec!["sn", "cn"]);
        assert_eq!(cls.may, vec!["userPassword", "telephoneNumber"]);
    }

    #[test]
    fn parse_attributetype_full() {
        let at = parse_attributetype("( 2.5.4.3 NAME 'cn' DESC 'RFC4519: common name' SUP name )")
            .unwrap();
        assert_eq!(at.oid, "2.5.4.3");
        assert_eq!(at.names, vec!["cn"]);
    }

    #[test]
    fn parse_objectclass_oid_only() {
        let cls = parse_objectclass("( 1.2.3.4.5 )").unwrap();
        assert_eq!(cls.oid, "1.2.3.4.5");
        assert!(cls.names.is_empty());
        assert!(cls.sup.is_empty());
        assert!(cls.must.is_empty());
        assert!(cls.may.is_empty());
    }

    #[test]
    fn parse_objectclass_multiple_names() {
        let cls = parse_objectclass("( 1.2.3 NAME ( 'commonName' 'cn' ) )").unwrap();
        assert_eq!(cls.names, vec!["commonName", "cn"]);
    }

    #[test]
    fn parse_objectclass_dollar_separated() {
        let cls = parse_objectclass("( 1.2.3 MUST ( sn $ cn $ uid ) )").unwrap();
        assert_eq!(cls.must, vec!["sn", "cn", "uid"]);
    }

    #[test]
    fn parse_objectclass_unrecognized_keywords_skipped() {
        let cls = parse_objectclass(
            "( 1.2.3 NAME 'test' X-ORIGIN 'RFC 1234' X-SCHEMA-FILE '00core.ldif' MUST cn )",
        )
        .unwrap();
        assert_eq!(cls.names, vec!["test"]);
        assert_eq!(cls.must, vec!["cn"]);
    }

    #[test]
    fn parse_objectclass_malformed() {
        assert!(parse_objectclass("garbage").is_err());
    }
}
