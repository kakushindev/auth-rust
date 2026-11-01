//! A safe reader for Python pickles (protocols 2–5), as authentik stores
//! session data (`pickle.dumps(…, protocol=HIGHEST_PROTOCOL)`).
//!
//! It never resolves or calls anything: `GLOBAL`, `REDUCE`, `NEWOBJ` and
//! `BUILD` become [`Value::Global`] and [`Value::Object`] nodes describing
//! what Python would construct. Containers are shared (`Rc<RefCell<…>>`)
//! because pickles fill them after memoizing them, and the memo must see the
//! filled container, as Python's object identity does.

pub mod write;

use std::{cell::RefCell, collections::HashMap, rc::Rc};

/// How an [`Object`] is constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Construct {
    /// `REDUCE`: `callable(*args)`.
    Reduce,
    /// `NEWOBJ`/`NEWOBJ_EX`: `cls.__new__(cls, *args)`.
    NewObj,
}

/// An object Python would construct, with its `BUILD` state.
#[derive(Debug)]
pub struct Object {
    pub construct: Construct,
    /// The callable (`Reduce`) or class (`NewObj`), usually a [`Value::Global`].
    pub callable: Value,
    pub args: Value,
    pub kwargs: Option<Value>,
    /// `BUILD` state (`__setstate__` argument or `__dict__` update).
    pub state: Option<Value>,
    /// `APPEND(S)` onto the object: its `append`/`extend` (a list subclass,
    /// `__reduce_ex__`'s `listitems`).
    pub list_items: Vec<Value>,
    /// `SETITEM(S)` on the object: its `__setitem__` (a dict subclass such
    /// as `QueryDict` or `OrderedDict`, `__reduce_ex__`'s `dictitems`).
    pub dict_items: Vec<(Value, Value)>,
}

/// A pickled value.
#[derive(Debug, Clone)]
pub enum Value {
    None,
    Bool(bool),
    /// An `int` within `i128`.
    Int(i128),
    /// An `int` beyond `i128`, as little-endian two's complement bytes.
    BigInt(Vec<u8>),
    Float(f64),
    /// A `str`; lone surrogates (`surrogatepass`) are replaced by U+FFFD.
    Str(String),
    Bytes(Vec<u8>),
    ByteArray(Vec<u8>),
    Tuple(Rc<Vec<Self>>),
    List(Rc<RefCell<Vec<Self>>>),
    Dict(Rc<RefCell<Vec<(Self, Self)>>>),
    Set(Rc<RefCell<Vec<Self>>>),
    FrozenSet(Rc<Vec<Self>>),
    /// `module.qualname`, a reference to a class or function.
    Global {
        module: String,
        name: String,
    },
    Object(Rc<RefCell<Object>>),
}

impl Value {
    /// The value of a `str` key in a dict.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<Self> {
        match self {
            Self::Dict(items) => items
                .borrow()
                .iter()
                .rev()
                .find(|(k, _)| matches!(k, Self::Str(s) if s == key))
                .map(|(_, v)| v.clone()),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Elements of a tuple or list.
    #[must_use]
    pub fn items(&self) -> Option<Vec<Self>> {
        match self {
            Self::Tuple(items) | Self::FrozenSet(items) => Some(items.to_vec()),
            Self::List(items) | Self::Set(items) => Some(items.borrow().clone()),
            _ => None,
        }
    }
}

/// Why a pickle could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Truncated,
    /// An opcode this reader does not implement.
    Unsupported(u8),
    /// A malformed pickle (stack underflow, missing mark, bad memo index…).
    Invalid(&'static str),
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        let bytes = self.data.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn le(&mut self, n: usize) -> Result<u64, Error> {
        Ok(self
            .take(n)?
            .iter()
            .rev()
            .fold(0_u64, |acc, b| (acc << 8_u32) | u64::from(*b)))
    }

    fn len(&mut self, n: usize) -> Result<usize, Error> {
        usize::try_from(self.le(n)?).map_err(|_| Error::Truncated)
    }

    fn line(&mut self) -> Result<String, Error> {
        let rest = self.data.get(self.pos..).ok_or(Error::Truncated)?;
        let end = rest
            .iter()
            .position(|&b| b == b'\n')
            .ok_or(Error::Truncated)?;
        let line = String::from_utf8_lossy(&rest[..end]).into_owned();
        self.pos += end + 1;
        Ok(line)
    }
}

/// UTF-8 with `surrogatepass`: encoded surrogates become U+FFFD.
fn decode_str(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec())
        .unwrap_or_else(|_| String::from_utf8_lossy(bytes).into_owned())
}

fn long(bytes: &[u8]) -> Value {
    if bytes.is_empty() {
        return Value::Int(0);
    }
    if bytes.len() <= 16 {
        let negative = bytes.last().is_some_and(|b| b & 0x80 != 0);
        let mut buf = [if negative { 0xff } else { 0 }; 16];
        buf[..bytes.len()].copy_from_slice(bytes);
        return Value::Int(i128::from_le_bytes(buf));
    }
    Value::BigInt(bytes.to_vec())
}

/// Read a pickle.
///
/// # Errors
///
/// A truncated or malformed pickle, or an opcode outside protocols 2–5
/// that Python's own pickler does not emit for them.
pub fn loads(data: &[u8]) -> Result<Value, Error> {
    let mut r = Reader { data, pos: 0 };
    let mut stack: Vec<Value> = Vec::new();
    let mut marks: Vec<usize> = Vec::new();
    let mut memo: HashMap<u64, Value> = HashMap::new();

    let pop = |stack: &mut Vec<Value>| stack.pop().ok_or(Error::Invalid("stack underflow"));
    let pop_mark = |stack: &mut Vec<Value>, marks: &mut Vec<usize>| -> Result<Vec<Value>, Error> {
        let mark = marks.pop().ok_or(Error::Invalid("missing mark"))?;
        if mark > stack.len() {
            return Err(Error::Invalid("mark beyond stack"));
        }
        Ok(stack.split_off(mark))
    };

    loop {
        let op = r.byte()?;
        match op {
            0x80 => {
                r.byte()?; // PROTO
            }
            0x95 => {
                r.take(8)?; // FRAME
            }
            b'.' => return pop(&mut stack), // STOP
            b'N' => stack.push(Value::None),
            0x88 => stack.push(Value::Bool(true)),
            0x89 => stack.push(Value::Bool(false)),
            b'J' => {
                let v = i32::from_le_bytes(r.take(4)?.try_into().map_err(|_| Error::Truncated)?);
                stack.push(Value::Int(i128::from(v)));
            }
            b'K' => stack.push(Value::Int(i128::from(r.byte()?))),
            b'M' => stack.push(Value::Int(i128::from(r.le(2)?))),
            0x8a => {
                let n = r.len(1)?;
                stack.push(long(r.take(n)?));
            }
            0x8b => {
                let n = r.len(4)?;
                stack.push(long(r.take(n)?));
            }
            b'G' => {
                let v = f64::from_be_bytes(r.take(8)?.try_into().map_err(|_| Error::Truncated)?);
                stack.push(Value::Float(v));
            }
            0x8c => {
                let n = r.len(1)?;
                stack.push(Value::Str(decode_str(r.take(n)?)));
            }
            b'X' => {
                let n = r.len(4)?;
                stack.push(Value::Str(decode_str(r.take(n)?)));
            }
            0x8d => {
                let n = r.len(8)?;
                stack.push(Value::Str(decode_str(r.take(n)?)));
            }
            b'C' => {
                let n = r.len(1)?;
                stack.push(Value::Bytes(r.take(n)?.to_vec()));
            }
            b'B' => {
                let n = r.len(4)?;
                stack.push(Value::Bytes(r.take(n)?.to_vec()));
            }
            0x8e => {
                let n = r.len(8)?;
                stack.push(Value::Bytes(r.take(n)?.to_vec()));
            }
            0x96 => {
                let n = r.len(8)?;
                stack.push(Value::ByteArray(r.take(n)?.to_vec()));
            }
            b']' => stack.push(Value::List(Rc::new(RefCell::new(Vec::new())))),
            b'}' => stack.push(Value::Dict(Rc::new(RefCell::new(Vec::new())))),
            b')' => stack.push(Value::Tuple(Rc::new(Vec::new()))),
            0x8f => stack.push(Value::Set(Rc::new(RefCell::new(Vec::new())))),
            0x85..=0x87 => {
                let n = usize::from(op - 0x84);
                if stack.len() < n {
                    return Err(Error::Invalid("stack underflow"));
                }
                let items = stack.split_off(stack.len() - n);
                stack.push(Value::Tuple(Rc::new(items)));
            }
            b'(' => marks.push(stack.len()),
            b't' => {
                let items = pop_mark(&mut stack, &mut marks)?;
                stack.push(Value::Tuple(Rc::new(items)));
            }
            b'l' => {
                let items = pop_mark(&mut stack, &mut marks)?;
                stack.push(Value::List(Rc::new(RefCell::new(items))));
            }
            b'd' => {
                let items = pop_mark(&mut stack, &mut marks)?;
                let pairs = items
                    .chunks_exact(2)
                    .filter_map(|p| match p {
                        [k, v] => Some((k.clone(), v.clone())),
                        _ => None,
                    })
                    .collect();
                stack.push(Value::Dict(Rc::new(RefCell::new(pairs))));
            }
            0x91 => {
                let items = pop_mark(&mut stack, &mut marks)?;
                stack.push(Value::FrozenSet(Rc::new(items)));
            }
            b'a' => {
                let item = pop(&mut stack)?;
                match stack.last() {
                    Some(Value::List(list)) => list.borrow_mut().push(item),
                    Some(Value::Object(object)) => object.borrow_mut().list_items.push(item),
                    _ => return Err(Error::Invalid("APPEND to a non-list")),
                }
            }
            b'e' => {
                let items = pop_mark(&mut stack, &mut marks)?;
                match stack.last() {
                    Some(Value::List(list)) => list.borrow_mut().extend(items),
                    Some(Value::Object(object)) => object.borrow_mut().list_items.extend(items),
                    _ => return Err(Error::Invalid("APPENDS to a non-list")),
                }
            }
            0x90 => {
                let items = pop_mark(&mut stack, &mut marks)?;
                match stack.last() {
                    Some(Value::Set(set)) => set.borrow_mut().extend(items),
                    _ => return Err(Error::Invalid("ADDITEMS to a non-set")),
                }
            }
            b's' => {
                let value = pop(&mut stack)?;
                let key = pop(&mut stack)?;
                match stack.last() {
                    Some(Value::Dict(dict)) => dict.borrow_mut().push((key, value)),
                    Some(Value::Object(object)) => {
                        object.borrow_mut().dict_items.push((key, value));
                    }
                    _ => return Err(Error::Invalid("SETITEM on a non-dict")),
                }
            }
            b'u' => {
                let items = pop_mark(&mut stack, &mut marks)?;
                let pairs = items.chunks_exact(2).filter_map(|p| match p {
                    [k, v] => Some((k.clone(), v.clone())),
                    _ => None,
                });
                match stack.last() {
                    Some(Value::Dict(dict)) => dict.borrow_mut().extend(pairs),
                    Some(Value::Object(object)) => object.borrow_mut().dict_items.extend(pairs),
                    _ => return Err(Error::Invalid("SETITEMS on a non-dict")),
                }
            }
            b'0' => {
                pop(&mut stack)?;
            }
            b'1' => {
                pop_mark(&mut stack, &mut marks)?;
            }
            b'2' => {
                let top = stack
                    .last()
                    .cloned()
                    .ok_or(Error::Invalid("stack underflow"))?;
                stack.push(top);
            }
            b'c' => {
                let module = r.line()?;
                let name = r.line()?;
                stack.push(Value::Global { module, name });
            }
            0x93 => {
                let name = pop(&mut stack)?;
                let module = pop(&mut stack)?;
                match (module, name) {
                    (Value::Str(module), Value::Str(name)) => {
                        stack.push(Value::Global { module, name });
                    }
                    _ => return Err(Error::Invalid("STACK_GLOBAL needs two strings")),
                }
            }
            b'R' | 0x81 => {
                let args = pop(&mut stack)?;
                let callable = pop(&mut stack)?;
                let construct = if op == b'R' {
                    Construct::Reduce
                } else {
                    Construct::NewObj
                };
                stack.push(Value::Object(Rc::new(RefCell::new(Object {
                    construct,
                    callable,
                    args,
                    kwargs: None,
                    state: None,
                    list_items: Vec::new(),
                    dict_items: Vec::new(),
                }))));
            }
            0x92 => {
                let kwargs = pop(&mut stack)?;
                let args = pop(&mut stack)?;
                let callable = pop(&mut stack)?;
                stack.push(Value::Object(Rc::new(RefCell::new(Object {
                    construct: Construct::NewObj,
                    callable,
                    args,
                    kwargs: Some(kwargs),
                    state: None,
                    list_items: Vec::new(),
                    dict_items: Vec::new(),
                }))));
            }
            b'b' => {
                let state = pop(&mut stack)?;
                match stack.last() {
                    Some(Value::Object(object)) => object.borrow_mut().state = Some(state),
                    _ => return Err(Error::Invalid("BUILD on a non-object")),
                }
            }
            0x94 => {
                let top = stack
                    .last()
                    .cloned()
                    .ok_or(Error::Invalid("stack underflow"))?;
                let index = u64::try_from(memo.len()).map_err(|_| Error::Invalid("memo"))?;
                memo.insert(index, top);
            }
            b'q' | b'r' => {
                let index = if op == b'q' {
                    u64::from(r.byte()?)
                } else {
                    r.le(4)?
                };
                let top = stack
                    .last()
                    .cloned()
                    .ok_or(Error::Invalid("stack underflow"))?;
                memo.insert(index, top);
            }
            b'h' | b'j' => {
                let index = if op == b'h' {
                    u64::from(r.byte()?)
                } else {
                    r.le(4)?
                };
                let value = memo
                    .get(&index)
                    .cloned()
                    .ok_or(Error::Invalid("unknown memo index"))?;
                stack.push(value);
            }
            other => return Err(Error::Unsupported(other)),
        }
    }
}

fn global_name(value: &Value) -> Option<String> {
    match value {
        Value::Global { module, name } if module == "builtins" => Some(name.clone()),
        Value::Global { module, name } => Some(format!("{module}.{name}")),
        _ => None,
    }
}

/// The name of the type Python would construct.
///
/// That is `type(v).__qualname__` for
/// builtins, `module.qualname` otherwise, and `model:<app_label>.<Model>` for
/// Django model instances (`model_unpickle`). Enum members (pickled as
/// `getattr(cls, name)`), `copyreg._reconstructor` and alternate
/// constructors (`Class._unpickle`) resolve to their class, and a pickled
/// `SimpleLazyObject` to its wrapped value's type.
#[must_use]
pub fn type_name(value: &Value) -> String {
    match value {
        Value::None => "NoneType".to_owned(),
        Value::Bool(_) => "bool".to_owned(),
        Value::Int(_) | Value::BigInt(_) => "int".to_owned(),
        Value::Float(_) => "float".to_owned(),
        Value::Str(_) => "str".to_owned(),
        Value::Bytes(_) => "bytes".to_owned(),
        Value::ByteArray(_) => "bytearray".to_owned(),
        Value::Tuple(_) => "tuple".to_owned(),
        Value::List(_) => "list".to_owned(),
        Value::Dict(_) => "dict".to_owned(),
        Value::Set(_) => "set".to_owned(),
        Value::FrozenSet(_) => "frozenset".to_owned(),
        Value::Global { .. } => "type".to_owned(),
        Value::Object(_) if let Some(wrapped) = lazy_wrapped(value) => type_name(&wrapped),
        Value::Object(object) => {
            let object = object.borrow();
            let first_arg = || {
                let args = object.args.items()?;
                args.first().cloned()
            };
            if object.construct == Construct::NewObj {
                return global_name(&object.callable).unwrap_or_else(|| "object".to_owned());
            }
            match &object.callable {
                Value::Global { module, name }
                    if module == "django.db.models.base" && name == "model_unpickle" =>
                {
                    let label = first_arg()
                        .and_then(|id| id.items())
                        .map(|parts| {
                            parts
                                .iter()
                                .filter_map(|p| p.as_str().map(str::to_owned))
                                .collect::<Vec<_>>()
                                .join(".")
                        })
                        .unwrap_or_default();
                    format!("model:{label}")
                }
                Value::Global { module, name }
                    if (module == "builtins" && name == "getattr")
                        || (module == "copyreg" && name == "_reconstructor") =>
                {
                    first_arg()
                        .and_then(|cls| global_name(&cls))
                        .unwrap_or_else(|| "object".to_owned())
                }
                Value::Global { module, name } => match name.rsplit_once('.') {
                    Some((class, _)) => format!("{module}.{class}"),
                    None => global_name(&object.callable).unwrap_or_default(),
                },
                _ => "object".to_owned(),
            }
        }
    }
}

/// The value a `SimpleLazyObject` was pickled around: Django pickles one
/// (`request.user`) as `unpickle_lazyobject(wrapped)`, which returns
/// `wrapped`.
#[must_use]
pub fn lazy_wrapped(value: &Value) -> Option<Value> {
    let Value::Object(object) = value else {
        return None;
    };
    let object = object.borrow();
    match &object.callable {
        Value::Global { module, name }
            if object.construct == Construct::Reduce
                && module == "django.utils.functional"
                && name == "unpickle_lazyobject" =>
        {
            object.args.items()?.first().cloned()
        }
        _ => None,
    }
}

/// `str(value)` for `None`, `bool`, `int` and `str`, and `len(value)` for
/// sized builtins: what the differential compares besides the type.
#[must_use]
pub fn describe(value: &Value) -> (String, Option<String>, Option<usize>) {
    if let Some(wrapped) = lazy_wrapped(value) {
        return describe(&wrapped);
    }
    let scalar = match value {
        Value::None => Some("None".to_owned()),
        Value::Bool(b) => Some(if *b { "True" } else { "False" }.to_owned()),
        Value::Int(i) => Some(i.to_string()),
        Value::Str(s) => Some(s.clone()),
        _ => None,
    };
    let len = match value {
        Value::Bytes(b) | Value::ByteArray(b) => Some(b.len()),
        Value::Tuple(items) | Value::FrozenSet(items) => Some(items.len()),
        Value::List(items) | Value::Set(items) => Some(items.borrow().len()),
        Value::Dict(items) => {
            // Duplicate keys collapse in Python.
            let items = items.borrow();
            let mut keys: Vec<String> = items.iter().map(|(k, _)| format!("{k:?}")).collect();
            keys.sort();
            keys.dedup();
            Some(keys.len())
        }
        _ => None,
    };
    (type_name(value), scalar, len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// Python's `str()` of a big int, for the one vector beyond `i128`.
    fn big_to_decimal(bytes: &[u8]) -> String {
        let negative = bytes.last().is_some_and(|b| b & 0x80 != 0);
        let mut magnitude: Vec<u8> = if negative {
            // Two's complement negate.
            let mut v: Vec<u8> = bytes.iter().map(|b| !b).collect();
            for b in &mut v {
                let (sum, carry) = b.overflowing_add(1);
                *b = sum;
                if !carry {
                    break;
                }
            }
            v
        } else {
            bytes.to_vec()
        };
        let mut digits = Vec::new();
        while magnitude.iter().any(|&b| b != 0) {
            let mut rem = 0_u32;
            for b in magnitude.iter_mut().rev() {
                let cur = (rem << 8_u32) | u32::from(*b);
                *b = u8::try_from(cur / 10).expect("digit");
                rem = cur % 10;
            }
            digits.push(char::from_digit(rem, 10).expect("digit"));
        }
        let text: String = digits.iter().rev().collect();
        if negative { format!("-{text}") } else { text }
    }

    #[test]
    fn describes_like_cpython() {
        let vectors = include_str!("../testdata/vectors.json");
        // Minimal field extraction to stay dependency-free.
        let mut checked = 0_usize;
        for block in vectors.split("{\n\"name\": ").skip(1) {
            let field = |key: &str| {
                block.split(&format!("\"{key}\": ")).nth(1).map(|rest| {
                    rest.split([',', '\n', '}'])
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .trim_matches('"')
                        .to_owned()
                })
            };
            let name = block.split('"').nth(1).expect("name");
            let pickle = unhex(&field("pickle").expect("pickle"));
            let root = loads(&pickle).unwrap_or_else(|err| panic!("{name}: {err:?}"));
            let value = root.get("k").expect("k");
            let (ty, scalar, len) = describe(&value);
            assert_eq!(Some(ty.clone()), field("type"), "{name} type");
            if let Some(expected) = field("value") {
                let got = match &value {
                    Value::BigInt(b) => big_to_decimal(b),
                    _ => scalar.unwrap_or_default(),
                };
                if !expected.contains("\\u") {
                    assert_eq!(got, expected, "{name} value");
                }
            }
            if let Some(expected) = field("len") {
                assert_eq!(len.map(|l| l.to_string()), Some(expected), "{name} len");
            }
            checked += 1;
        }
        assert_eq!(checked, 39);
    }
}
