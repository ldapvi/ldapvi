/// An LDAP entry: a DN with a list of attributes.
#[derive(Debug, Clone)]
pub struct Entry {
    pub dn: String,
    pub attributes: Vec<Attribute>,
}

/// An attribute: a descriptor (name) with a list of binary-safe values.
#[derive(Debug, Clone)]
pub struct Attribute {
    pub ad: String,
    pub values: Vec<Vec<u8>>,
}

/// A modification operation (replaces C LDAPMod for internal use).
#[derive(Debug, Clone)]
pub struct Mod {
    pub attr: String,
    pub values: Vec<Vec<u8>>,
}

/// LDAP modification operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModOp {
    Add,
    Delete,
    Replace,
}

/// An LDAP modification with operation type (used in modify change records).
#[derive(Debug, Clone)]
pub struct LdapMod {
    pub op: ModOp,
    pub attr: String,
    pub values: Vec<Vec<u8>>,
}

/// A rename (modrdn) record.
#[derive(Debug, Clone)]
pub struct RenameRecord {
    pub old_dn: String,
    pub new_dn: String,
    pub delete_old_rdn: bool,
}

/// A modify record.
#[derive(Debug, Clone)]
pub struct ModifyRecord {
    pub dn: String,
    pub mods: Vec<LdapMod>,
}

impl Entry {
    pub fn new(dn: String) -> Entry {
        Entry {
            dn,
            attributes: Vec::new(),
        }
    }

    /// Find an attribute by descriptor name.
    /// If `create` is true and the attribute doesn't exist, create it.
    pub fn find_attribute(&mut self, ad: &str, create: bool) -> Option<&mut Attribute> {
        let pos = self.attributes.iter().position(|a| a.ad == ad);
        match pos {
            Some(i) => Some(&mut self.attributes[i]),
            None if create => {
                self.attributes.push(Attribute::new(ad.to_string()));
                self.attributes.last_mut()
            }
            None => None,
        }
    }

    /// Find an attribute by descriptor name (immutable).
    pub fn get_attribute(&self, ad: &str) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.ad == ad)
    }

    /// Convert entry to a list of Mod structs (one per attribute).
    pub fn to_mods(&self) -> Vec<Mod> {
        self.attributes
            .iter()
            .map(|a| Mod {
                attr: a.ad.clone(),
                values: a.values.clone(),
            })
            .collect()
    }
}

impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.dn == other.dn
    }
}

impl Eq for Entry {}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.dn.cmp(&other.dn)
    }
}

impl Attribute {
    pub fn new(ad: String) -> Attribute {
        Attribute {
            ad,
            values: Vec::new(),
        }
    }

    pub fn append_value(&mut self, data: &[u8]) {
        self.values.push(data.to_vec());
    }

    /// Find a value, returning its index or None.
    pub fn find_value(&self, data: &[u8]) -> Option<usize> {
        self.values.iter().position(|v| v.as_slice() == data)
    }

    /// Remove a value. Returns true if found and removed.
    pub fn remove_value(&mut self, data: &[u8]) -> bool {
        match self.find_value(data) {
            Some(i) => {
                self.values.swap_remove(i);
                true
            }
            None => false,
        }
    }

    /// Convert to a Mod struct.
    pub fn to_mod(&self) -> Mod {
        Mod {
            attr: self.ad.clone(),
            values: self.values.clone(),
        }
    }
}

impl PartialEq for Attribute {
    fn eq(&self, other: &Self) -> bool {
        self.ad == other.ad
    }
}

impl Eq for Attribute {}

impl PartialOrd for Attribute {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Attribute {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.ad.cmp(&other.ad)
    }
}

/// Convert a binary value to a String (equivalent of C array2string).
pub fn value_to_string(value: &[u8]) -> String {
    String::from_utf8_lossy(value).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: create an entry with the given DN.
    fn make_entry(dn: &str) -> Entry {
        Entry::new(dn.to_string())
    }

    // Helper: add an attribute value to an entry.
    fn add_attr_value(entry: &mut Entry, ad: &str, val: &str) {
        let attr = entry.find_attribute(ad, true).unwrap();
        attr.append_value(val.as_bytes());
    }

    // ── Group 1: entry_new and entry_free ───────────────────────

    #[test]
    fn entry_new_sets_dn() {
        let e = Entry::new("cn=foo,dc=example,dc=com".to_string());
        assert_eq!(e.dn, "cn=foo,dc=example,dc=com");
        assert_eq!(e.attributes.len(), 0);
    }

    #[test]
    fn entry_free_with_attributes() {
        let mut e = make_entry("cn=test,dc=com");
        add_attr_value(&mut e, "cn", "test");
        add_attr_value(&mut e, "sn", "value");
        drop(e); // no crash = pass
    }

    // ── Group 2: entry_cmp ──────────────────────────────────────

    #[test]
    fn entry_cmp_equal() {
        let a = make_entry("cn=foo,dc=com");
        let b = make_entry("cn=foo,dc=com");
        assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
    }

    #[test]
    fn entry_cmp_less() {
        let a = make_entry("cn=aaa,dc=com");
        let b = make_entry("cn=zzz,dc=com");
        assert!(a < b);
    }

    #[test]
    fn entry_cmp_greater() {
        let a = make_entry("cn=zzz,dc=com");
        let b = make_entry("cn=aaa,dc=com");
        assert!(a > b);
    }

    // ── Group 3: attribute_new, attribute_free, attribute_cmp ───

    #[test]
    fn attribute_new_sets_ad() {
        let a = Attribute::new("cn".to_string());
        assert_eq!(a.ad, "cn");
        assert_eq!(a.values.len(), 0);
    }

    #[test]
    fn attribute_cmp_equal() {
        let a = Attribute::new("cn".to_string());
        let b = Attribute::new("cn".to_string());
        assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
    }

    #[test]
    fn attribute_cmp_different() {
        let a = Attribute::new("cn".to_string());
        let b = Attribute::new("sn".to_string());
        assert_ne!(a.cmp(&b), std::cmp::Ordering::Equal);
    }

    // ── Group 4: entry_find_attribute ───────────────────────────

    #[test]
    fn find_attribute_creates() {
        let mut e = make_entry("cn=test,dc=com");
        let a = e.find_attribute("cn", true);
        assert!(a.is_some());
        assert_eq!(a.unwrap().ad, "cn");
        assert_eq!(e.attributes.len(), 1);
    }

    #[test]
    fn find_attribute_no_create() {
        let mut e = make_entry("cn=test,dc=com");
        let a = e.find_attribute("cn", false);
        assert!(a.is_none());
    }

    #[test]
    fn find_attribute_existing() {
        let mut e = make_entry("cn=test,dc=com");
        e.find_attribute("cn", true);
        e.find_attribute("cn", true);
        // Should not create a duplicate
        assert_eq!(e.attributes.len(), 1);
    }

    // ── Group 5: attribute values ───────────────────────────────

    #[test]
    fn append_and_find_value() {
        let mut a = Attribute::new("cn".to_string());
        a.append_value(b"hello");
        assert_eq!(a.values.len(), 1);
        assert_eq!(a.find_value(b"hello"), Some(0));
    }

    #[test]
    fn find_value_not_found() {
        let mut a = Attribute::new("cn".to_string());
        a.append_value(b"hello");
        assert_eq!(a.find_value(b"world"), None);
    }

    #[test]
    fn remove_value_success() {
        let mut a = Attribute::new("cn".to_string());
        a.append_value(b"hello");
        assert!(a.remove_value(b"hello"));
        assert_eq!(a.values.len(), 0);
        assert_eq!(a.find_value(b"hello"), None);
    }

    #[test]
    fn remove_value_not_found() {
        let mut a = Attribute::new("cn".to_string());
        a.append_value(b"hello");
        assert!(!a.remove_value(b"world"));
        assert_eq!(a.values.len(), 1);
    }

    // ── Group 6: sorting entries ────────────────────────────────

    #[test]
    fn entry_sorting() {
        let e1 = make_entry("cn=zzz,dc=com");
        let e2 = make_entry("cn=aaa,dc=com");
        let mut arr = vec![e1, e2];
        arr.sort();
        assert_eq!(arr[0].dn, "cn=aaa,dc=com");
        assert_eq!(arr[1].dn, "cn=zzz,dc=com");
    }

    // ── Group 7: value/string conversions ───────────────────────

    #[test]
    fn value_to_string_basic() {
        assert_eq!(value_to_string(b"hello"), "hello");
        assert_eq!(value_to_string(b"hello").len(), 5);
    }

    #[test]
    fn value_to_string_from_vec() {
        let v: Vec<u8> = b"test".to_vec();
        let s = value_to_string(&v);
        assert_eq!(s, "test");
        assert_eq!(s.len(), 4);
    }

    // ── Group 8: attribute_to_mod and entry_to_mods ─────────────

    #[test]
    fn attribute_to_mod() {
        let mut a = Attribute::new("mail".to_string());
        a.append_value(b"a@b.com");
        a.append_value(b"c@d.com");
        let m = a.to_mod();
        assert_eq!(m.attr, "mail");
        assert_eq!(m.values.len(), 2);
        assert_eq!(m.values[0], b"a@b.com");
        assert_eq!(m.values[1], b"c@d.com");
    }

    #[test]
    fn entry_to_mods() {
        let mut e = make_entry("cn=test,dc=com");
        add_attr_value(&mut e, "cn", "test");
        add_attr_value(&mut e, "sn", "value");
        let mods = e.to_mods();
        assert_eq!(mods.len(), 2);
        assert_eq!(mods[0].attr, "cn");
        assert_eq!(mods[1].attr, "sn");
    }
}
