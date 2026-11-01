//! A pickle writer: `pickle.dumps(obj, protocol=5)` as `CPython` 3.14's C
//! pickler writes it, for the object graphs authentik's write paths store
//! (task messages, session data, model instances).
//!
//! The graph is an [`Obj`] tree. `CPython` memoizes by object identity, and
//! in this tree every node is a distinct object except where the writer
//! knows Python shares one: a class (`Global`) is memoized by its qualified
//! name, and a module name by its text, since classes of one module carry
//! the same interned `__module__` string.

use std::collections::HashMap;

/// An object to pickle.
#[derive(Debug, Clone, PartialEq)]
pub enum Obj {
    None,
    Bool(bool),
    Int(i128),
    /// An `int` outside `i128`: its `encode_long` bytes.
    Long(Vec<u8>),
    Float(f64),
    Str(String),
    Bytes(Vec<u8>),
    Tuple(Vec<Self>),
    List(Vec<Self>),
    /// Items in insertion order.
    Dict(Vec<(Self, Self)>),
    /// A class or function, `module.qualname`.
    Global {
        module: String,
        name: String,
    },
    /// `copyreg.__newobj__`: `cls.__new__(cls, *args)`, then `BUILD` with
    /// `state`.
    NewObj {
        cls: Box<Self>,
        args: Vec<Self>,
        state: Option<Box<Self>>,
    },
    /// `callable(*args)`, then `BUILD` with `state`.
    Reduce {
        callable: Box<Self>,
        args: Vec<Self>,
        state: Option<Box<Self>>,
    },
}

impl Obj {
    #[must_use]
    pub fn str(s: &str) -> Self {
        Self::Str(s.to_owned())
    }

    #[must_use]
    pub fn global(module: &str, name: &str) -> Self {
        Self::Global {
            module: module.to_owned(),
            name: name.to_owned(),
        }
    }

    /// `uuid.UUID`: `NEWOBJ` with state `{"int": …}` (`is_safe` is unknown
    /// for UUIDs built from text or bytes, so it is not in the state).
    #[must_use]
    pub fn uuid(value: u128) -> Self {
        let int = i128::try_from(value).map_or_else(
            // Above `i128::MAX`: 17 bytes, the last a zero sign byte.
            |_| {
                let mut data = value.to_le_bytes().to_vec();
                data.push(0);
                Self::Long(data)
            },
            Self::Int,
        );
        Self::NewObj {
            cls: Box::new(Self::global("uuid", "UUID")),
            args: Vec::new(),
            state: Some(Box::new(Self::Dict(vec![(Self::str("int"), int)]))),
        }
    }

    /// A Django model instance as `Model.__reduce__` gives it:
    /// `model_unpickle((app_label, object_name))`, state `{"_state":
    /// ModelState{adding, db, fields_cache: {}}, fields…, "_django_version"}`.
    #[must_use]
    pub fn model(
        app_label: &str,
        object_name: &str,
        fields: Vec<(&str, Self)>,
        django_version: &str,
    ) -> Self {
        let model_state = Self::NewObj {
            cls: Box::new(Self::global("django.db.models.base", "ModelState")),
            args: Vec::new(),
            state: Some(Box::new(Self::Dict(vec![
                (Self::str("adding"), Self::Bool(false)),
                (Self::str("db"), Self::str("default")),
                (Self::str("fields_cache"), Self::Dict(Vec::new())),
            ]))),
        };
        let mut state = vec![(Self::str("_state"), model_state)];
        state.extend(fields.into_iter().map(|(k, v)| (Self::str(k), v)));
        state.push((Self::str("_django_version"), Self::str(django_version)));
        Self::Reduce {
            callable: Box::new(Self::global("django.db.models.base", "model_unpickle")),
            args: vec![Self::Tuple(vec![
                Self::str(app_label),
                Self::str(object_name),
            ])],
            state: Some(Box::new(Self::Dict(state))),
        }
    }
}

const FRAME_SIZE_MIN: usize = 4;
const FRAME_SIZE_TARGET: usize = 64 * 1024;
const BATCHSIZE: usize = 1000;

struct Pickler {
    out: Vec<u8>,
    frame_start: usize,
    memo_len: u32,
    globals: HashMap<(String, String), u32>,
    modules: HashMap<String, u32>,
}

/// `encode_long`: two's complement, little-endian, minimal.
fn long_bytes(x: i128) -> Vec<u8> {
    // `nbytes = (x.bit_length() >> 3) + 1`, `bit_length` of the magnitude.
    let magnitude_bits = 128 - x.unsigned_abs().leading_zeros();
    let nbytes = usize::try_from((magnitude_bits >> 3_u32) + 1)
        .unwrap_or(16)
        .min(16);
    let mut data = x.to_le_bytes()[..nbytes].to_vec();
    if x < 0 && nbytes > 1 && data[nbytes - 1] == 0xff && data[nbytes - 2] & 0x80 != 0 {
        data.pop();
    }
    data
}

impl Pickler {
    fn memoize(&mut self) -> u32 {
        self.out.push(0x94);
        let index = self.memo_len;
        self.memo_len += 1;
        index
    }

    fn get(&mut self, index: u32) {
        if let Ok(small) = u8::try_from(index) {
            self.out.extend([b'h', small]);
        } else {
            self.out.push(b'j');
            self.out.extend(index.to_le_bytes());
        }
    }

    /// `_Pickler_OpcodeBoundary`: commit the frame once it reaches the
    /// target size.
    fn boundary(&mut self) {
        if self.out.len() - self.frame_start >= FRAME_SIZE_TARGET {
            self.commit_frame();
            self.frame_start = self.out.len();
        }
    }

    /// `_Pickler_CommitFrame`: a `FRAME` header before the frame's bytes
    /// (written only from `FRAME_SIZE_MIN` bytes on).
    fn commit_frame(&mut self) {
        let len = self.out.len() - self.frame_start;
        if len >= FRAME_SIZE_MIN {
            let mut header = vec![0x95];
            header.extend(u64::try_from(len).unwrap_or(u64::MAX).to_le_bytes());
            self.out.splice(self.frame_start..self.frame_start, header);
        }
    }

    fn save_str(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let len = bytes.len();
        if let Ok(short) = u8::try_from(len) {
            self.out.extend([0x8c, short]);
        } else if let Ok(medium) = u32::try_from(len) {
            self.out.push(b'X');
            self.out.extend(medium.to_le_bytes());
        } else {
            self.out.push(0x8d);
            self.out
                .extend(u64::try_from(len).unwrap_or(u64::MAX).to_le_bytes());
        }
        self.out.extend(bytes);
        self.memoize();
    }

    fn save_global(&mut self, module: &str, name: &str) {
        if let Some(&index) = self.globals.get(&(module.to_owned(), name.to_owned())) {
            self.get(index);
            return;
        }
        // `save_global` (protocol 4+): `STACK_GLOBAL` over the two strings.
        if let Some(&index) = self.modules.get(module) {
            self.get(index);
        } else {
            self.save_str(module);
            self.modules.insert(module.to_owned(), self.memo_len - 1);
        }
        self.save_str(name);
        self.out.push(0x93);
        let index = self.memoize();
        self.globals
            .insert((module.to_owned(), name.to_owned()), index);
    }

    fn save_items(&mut self, items: &[Obj], single: u8, many: u8) {
        if items.len() == 1 {
            self.save(&items[0]);
            self.out.push(single);
            return;
        }
        for chunk in items.chunks(BATCHSIZE) {
            self.out.push(b'(');
            for item in chunk {
                self.save(item);
            }
            self.out.push(many);
        }
    }

    fn save_args(&mut self, args: &[Obj]) {
        self.save(&Obj::Tuple(args.to_vec()));
    }

    fn save_state(&mut self, state: Option<&Obj>) {
        if let Some(state) = state {
            self.save(state);
            self.out.push(b'b');
        }
    }

    fn save(&mut self, obj: &Obj) {
        match obj {
            Obj::None => self.out.push(b'N'),
            Obj::Bool(true) => self.out.push(0x88),
            Obj::Bool(false) => self.out.push(0x89),
            Obj::Int(x) => {
                if let Ok(b) = u8::try_from(*x) {
                    self.out.extend([b'K', b]);
                } else if let Ok(w) = u16::try_from(*x) {
                    self.out.push(b'M');
                    self.out.extend(w.to_le_bytes());
                } else if let Ok(d) = i32::try_from(*x) {
                    self.out.push(b'J');
                    self.out.extend(d.to_le_bytes());
                } else {
                    self.save_long(&long_bytes(*x));
                }
            }
            Obj::Long(data) => self.save_long(data),
            Obj::Float(f) => {
                self.out.push(b'G');
                self.out.extend(f.to_be_bytes());
            }
            Obj::Str(s) => self.save_str(s),
            Obj::Bytes(b) => {
                if let Ok(short) = u8::try_from(b.len()) {
                    self.out.extend([b'C', short]);
                } else if let Ok(medium) = u32::try_from(b.len()) {
                    self.out.push(b'B');
                    self.out.extend(medium.to_le_bytes());
                } else {
                    self.out.push(0x8e);
                    self.out
                        .extend(u64::try_from(b.len()).unwrap_or(u64::MAX).to_le_bytes());
                }
                self.out.extend(b);
                self.memoize();
            }
            Obj::Tuple(items) => match items.len() {
                0 => self.out.push(b')'),
                1..=3 => {
                    for item in items {
                        self.save(item);
                    }
                    self.out.push([0x85, 0x86, 0x87][items.len() - 1]);
                    self.memoize();
                }
                _ => {
                    self.out.push(b'(');
                    for item in items {
                        self.save(item);
                    }
                    self.out.push(b't');
                    self.memoize();
                }
            },
            Obj::List(items) => {
                self.out.push(b']');
                self.memoize();
                if !items.is_empty() {
                    self.save_items(items, b'a', b'e');
                }
            }
            Obj::Dict(items) => {
                self.out.push(b'}');
                self.memoize();
                match items.as_slice() {
                    [] => {}
                    [(k, v)] => {
                        self.save(k);
                        self.save(v);
                        self.out.push(b's');
                    }
                    _ => {
                        for chunk in items.chunks(BATCHSIZE) {
                            self.out.push(b'(');
                            for (k, v) in chunk {
                                self.save(k);
                                self.save(v);
                            }
                            self.out.push(b'u');
                        }
                    }
                }
            }
            Obj::Global { module, name } => self.save_global(module, name),
            Obj::NewObj { cls, args, state } => {
                self.save(cls);
                self.save_args(args);
                self.out.push(0x81);
                self.memoize();
                self.save_state(state.as_deref());
            }
            Obj::Reduce {
                callable,
                args,
                state,
            } => {
                self.save(callable);
                self.save_args(args);
                self.out.push(b'R');
                self.memoize();
                self.save_state(state.as_deref());
            }
        }
        self.boundary();
    }

    fn save_long(&mut self, data: &[u8]) {
        if let Ok(n) = u8::try_from(data.len()) {
            self.out.extend([0x8a, n]);
        } else {
            self.out.push(0x8b);
            self.out
                .extend(u32::try_from(data.len()).unwrap_or(u32::MAX).to_le_bytes());
        }
        self.out.extend(data);
    }
}

/// `pickle.dumps(obj, protocol=5)`.
#[must_use]
pub fn dumps(obj: &Obj) -> Vec<u8> {
    let mut p = Pickler {
        out: vec![0x80, 5],
        frame_start: 2,
        memo_len: 0,
        globals: HashMap::new(),
        modules: HashMap::new(),
    };
    p.save(obj);
    p.out.push(b'.');
    p.commit_frame();
    p.out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../testdata/write_vectors.json")).expect("vectors")
    }

    fn check(name: &str, obj: &Obj) {
        let v = vectors();
        let expected = v[name].as_str().expect(name);
        assert_eq!(hex::encode(dumps(obj)), expected, "{name}");
    }

    fn ints(values: &[i128]) -> Obj {
        Obj::List(values.iter().map(|&v| Obj::Int(v)).collect())
    }

    #[test]
    fn scalars_and_containers_match_cpython() {
        check("none", &Obj::None);
        check("true", &Obj::Bool(true));
        check(
            "ints",
            &ints(&[
                0,
                1,
                255,
                256,
                65_535,
                65_536,
                -1,
                -5,
                (1_i128 << 31_u32) - 1,
                -(1_i128 << 31_u32),
                1_i128 << 31_u32,
                -(1_i128 << 31_u32) - 1,
                1_i128 << 63_u32,
                -(1_i128 << 63_u32),
                1_i128 << 100_u32,
                -(1_i128 << 100_u32),
            ]),
        );
        check(
            "floats",
            &Obj::List(vec![
                Obj::Float(0.0_f64),
                Obj::Float(-0.0_f64),
                Obj::Float(1.5_f64),
                Obj::Float(1e300_f64),
            ]),
        );
        check(
            "strs",
            &Obj::List(vec![
                Obj::str(""),
                Obj::str("a"),
                Obj::str("\u{e9}\u{1f600}"),
                Obj::Str("x".repeat(300)),
            ]),
        );
        check(
            "bytes",
            &Obj::List(vec![
                Obj::Bytes(Vec::new()),
                Obj::Bytes(b"ab".to_vec()),
                Obj::Bytes(vec![b'y'; 300]),
            ]),
        );
        check(
            "tuples",
            &Obj::List(vec![
                Obj::Tuple(Vec::new()),
                Obj::Tuple(vec![Obj::Int(1)]),
                Obj::Tuple(vec![Obj::Int(1), Obj::Int(2)]),
                Obj::Tuple(vec![Obj::Int(1), Obj::Int(2), Obj::Int(3)]),
                Obj::Tuple(vec![Obj::Int(1), Obj::Int(2), Obj::Int(3), Obj::Int(4)]),
            ]),
        );
        check(
            "nested",
            &Obj::Dict(vec![
                (Obj::str("a"), ints(&[1])),
                (Obj::str("b"), Obj::Dict(Vec::new())),
                (Obj::str("c"), Obj::Dict(vec![(Obj::str("x"), Obj::Int(1))])),
                (Obj::str("d"), Obj::List(Vec::new())),
            ]),
        );
        check("uuid_small", &Obj::uuid(12_345));
        check("uuid_big", &Obj::uuid(u128::MAX));
        check("biglist", &ints(&(0..1001).collect::<Vec<_>>()));
    }

    #[test]
    fn model_instance_matches_django() {
        let uuid = u128::from_str_radix("7d27b0360e324a3ba0328e5dce554978", 16).expect("hex");
        let tenant = Obj::model(
            "authentik_tenants",
            "Tenant",
            vec![
                ("tenant_uuid", Obj::uuid(uuid)),
                ("schema_name", Obj::str("public")),
                ("name", Obj::str("Default")),
                ("ready", Obj::Bool(true)),
                (
                    "avatars",
                    Obj::str("attributes.m7.avatar,gravatar,initials"),
                ),
                ("default_user_change_name", Obj::Bool(true)),
                ("default_user_change_email", Obj::Bool(false)),
                ("default_user_change_username", Obj::Bool(false)),
                ("event_retention", Obj::str("days=365")),
                ("reputation_lower_limit", Obj::Int(-5)),
                ("reputation_upper_limit", Obj::Int(5)),
                ("footer_links", Obj::List(Vec::new())),
                ("gdpr_compliance", Obj::Bool(true)),
                ("impersonation", Obj::Bool(true)),
                ("impersonation_require_reason", Obj::Bool(true)),
                ("default_token_duration", Obj::str("minutes=30")),
                ("default_token_length", Obj::Int(60)),
                ("pagination_default_page_size", Obj::Int(20)),
                ("pagination_max_page_size", Obj::Int(100)),
                ("flags", Obj::Dict(Vec::new())),
            ],
            "5.2.17",
        );
        check("tenant", &Obj::Dict(vec![(Obj::str("tenant"), tenant)]));
    }
}
