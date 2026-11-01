//! `CPython` 3.14's `set` of `int`s, for its iteration order.
//!
//! Django inserts m2m rows in the order of a set (`_add_items`' missing
//! target ids), and the through table's ids follow that order. This is
//! `Objects/setobject.c`: open addressing with 9 linear probes, then
//! perturbed probing, resized when 3/5 full; `difference` with a non-set
//! iterable copies the table (`set_merge`) and leaves dummies on discard.
//! `tests/pyset_vectors.json` holds orders from the reference image.

const MINSIZE: usize = 8;
const LINEAR_PROBES: usize = 9;
const PERTURB_SHIFT: u32 = 5;
/// `_PyHASH_MODULUS`, the Mersenne prime 2**61 - 1.
const MODULUS: u64 = (1 << 61) - 1;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Unused,
    Dummy,
    Active { key: i64, hash: i64 },
}

/// A `CPython` `set` holding `int`s.
#[derive(Clone)]
pub struct IntSet {
    table: Vec<Slot>,
    fill: usize,
    used: usize,
}

/// `hash(int)`: the value modulo 2**61 - 1, keeping the sign; -1 becomes -2.
fn hash(value: i64) -> i64 {
    let reduced = i64::try_from(value.unsigned_abs() % MODULUS).unwrap_or(0);
    let hash = if value < 0 { -reduced } else { reduced };
    if hash == -1 { -2 } else { hash }
}

/// `(size_t)hash` on a 64-bit target.
fn unsigned(hash: i64) -> usize {
    usize::try_from(hash.cast_unsigned()).unwrap_or(usize::MAX)
}

fn insert_clean(table: &mut [Slot], key: i64, hash: i64) {
    let mask = table.len() - 1;
    let mut perturb = unsigned(hash);
    let mut i = unsigned(hash) & mask;
    loop {
        if table[i] == Slot::Unused {
            table[i] = Slot::Active { key, hash };
            return;
        }
        if i + LINEAR_PROBES <= mask {
            for j in 1..=LINEAR_PROBES {
                if table[i + j] == Slot::Unused {
                    table[i + j] = Slot::Active { key, hash };
                    return;
                }
            }
        }
        perturb >>= PERTURB_SHIFT;
        i = (i.wrapping_mul(5).wrapping_add(1).wrapping_add(perturb)) & mask;
    }
}

impl Default for IntSet {
    fn default() -> Self {
        Self::new()
    }
}

impl IntSet {
    /// `set()`.
    pub fn new() -> Self {
        Self {
            table: vec![Slot::Unused; MINSIZE],
            fill: 0,
            used: 0,
        }
    }

    fn mask(&self) -> usize {
        self.table.len() - 1
    }

    /// `set_table_resize`.
    fn resize(&mut self, minused: usize) {
        let mut size = MINSIZE;
        while size <= minused {
            size *= 2;
        }
        let old = std::mem::replace(&mut self.table, vec![Slot::Unused; size]);
        self.fill = self.used;
        for slot in old {
            if let Slot::Active { key, hash } = slot {
                insert_clean(&mut self.table, key, hash);
            }
        }
    }

    /// `set.add(value)`.
    pub fn add(&mut self, key: i64) {
        let hash = hash(key);
        let mask = self.mask();
        let mut i = unsigned(hash) & mask;
        let mut perturb = unsigned(hash);
        let mut freeslot = None;
        loop {
            let probes = if i + LINEAR_PROBES <= mask {
                LINEAR_PROBES
            } else {
                0
            };
            for j in 0..=probes {
                let index = i + j;
                match self.table[index] {
                    Slot::Unused => {
                        if let Some(free) = freeslot {
                            self.table[free] = Slot::Active { key, hash };
                            self.used += 1;
                            return;
                        }
                        self.table[index] = Slot::Active { key, hash };
                        self.fill += 1;
                        self.used += 1;
                        if self.fill * 5 >= mask * 3 {
                            self.resize(if self.used > 50_000 {
                                self.used * 2
                            } else {
                                self.used * 4
                            });
                        }
                        return;
                    }
                    Slot::Active { key: k, .. } if k == key => return,
                    Slot::Active { .. } => {}
                    Slot::Dummy => {
                        if freeslot.is_none() {
                            freeslot = Some(index);
                        }
                    }
                }
            }
            perturb >>= PERTURB_SHIFT;
            i = (i.wrapping_mul(5).wrapping_add(1).wrapping_add(perturb)) & mask;
        }
    }

    /// `set.discard(value)`.
    pub fn discard(&mut self, key: i64) {
        let hash = hash(key);
        let mask = self.mask();
        let mut i = unsigned(hash) & mask;
        let mut perturb = unsigned(hash);
        loop {
            let probes = if i + LINEAR_PROBES <= mask {
                LINEAR_PROBES
            } else {
                0
            };
            for j in 0..=probes {
                match self.table[i + j] {
                    Slot::Unused => return,
                    Slot::Active { key: k, .. } if k == key => {
                        self.table[i + j] = Slot::Dummy;
                        self.used -= 1;
                        return;
                    }
                    Slot::Active { .. } | Slot::Dummy => {}
                }
            }
            perturb >>= PERTURB_SHIFT;
            i = (i.wrapping_mul(5).wrapping_add(1).wrapping_add(perturb)) & mask;
        }
    }

    /// `set(self)`: `make_new_set` then `set_merge` into an empty table.
    #[must_use]
    pub fn copy(&self) -> Self {
        let mut out = Self::new();
        if self.used == 0 {
            return out;
        }
        if self.used * 5 >= out.mask() * 3 {
            out.resize(self.used * 2);
        }
        if out.mask() == self.mask() && self.fill == self.used {
            out.table.clone_from(&self.table);
        } else {
            for slot in &self.table {
                if let Slot::Active { key, hash } = *slot {
                    insert_clean(&mut out.table, key, hash);
                }
            }
        }
        out.fill = self.used;
        out.used = self.used;
        out
    }

    /// `self.difference(iterable)` for an iterable that is not a set or
    /// dict (`set_copy_and_difference`).
    #[must_use]
    pub fn difference_iter<I: IntoIterator<Item = i64>>(&self, other: I) -> Self {
        let mut out = self.copy();
        for key in other {
            out.discard(key);
        }
        out
    }

    /// The values in iteration order.
    pub fn iter(&self) -> impl Iterator<Item = i64> + '_ {
        self.table.iter().filter_map(|slot| match slot {
            Slot::Active { key, .. } => Some(*key),
            Slot::Unused | Slot::Dummy => None,
        })
    }

    pub fn len(&self) -> usize {
        self.used
    }

    pub fn is_empty(&self) -> bool {
        self.used == 0
    }

    pub fn contains(&self, key: i64) -> bool {
        self.iter().any(|k| k == key)
    }
}

#[cfg(test)]
mod tests {
    use super::IntSet;

    #[test]
    fn matches_cpython_vectors() {
        let raw = include_str!("../tests/pyset_vectors.json");
        let doc: serde_json::Value = serde_json::from_str(raw).expect("vectors");
        let ints = |v: &serde_json::Value| -> Vec<i64> {
            v.as_array()
                .expect("list")
                .iter()
                .map(|x| x.as_i64().expect("i64"))
                .collect()
        };
        let cases = doc["cases"].as_array().expect("cases");
        assert!(cases.len() > 200);
        for case in cases {
            let mut set = IntSet::new();
            for x in ints(&case["objs"]) {
                set.add(x);
            }
            let got: Vec<i64> = set
                .difference_iter(ints(&case["existing"]))
                .iter()
                .collect();
            assert_eq!(got, ints(&case["order"]), "objs {}", case["objs"]);
        }
    }

    #[test]
    fn seeded_difference_is_detected() {
        // Insertion order alone (a sorted Vec) differs from CPython's for
        // values past the table size.
        let mut set = IntSet::new();
        for x in [700, 9, 300, 17] {
            set.add(x);
        }
        let order: Vec<i64> = set.iter().collect();
        // `list(s)` in the reference image.
        assert_eq!(order, vec![9, 700, 300, 17]);
        assert_ne!(order, vec![9, 17, 300, 700]);
    }
}
