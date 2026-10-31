//! authentik's `AutocompletePagination`.
//!
//! That is the Enterprise search app's subclass of
//! `authentik.api.pagination.Pagination` (installed in every image), on
//! DRF's `PageNumberPagination` and Django's `Paginator`.
//!
//! Only views without `get_ql_fields` are paginated here: their
//! `autocomplete` is `{}`. The views that have QL fields produce it from
//! Enterprise code and are not served by this crate.

use serde::Serialize;

use crate::{
    Decline,
    drf::Tenant,
    py::{PyInt, QueryDict, py_int},
};

/// `get_page_size`: a valid positive `page_size`, capped at the tenant's
/// maximum, else the tenant default.
///
/// # Errors
///
/// [`Decline`] for digits `int()` would read but this port does not.
pub fn page_size(query: &QueryDict, tenant: &Tenant) -> Result<i64, Decline> {
    if let Some(raw) = query.get("page_size") {
        // `_positive_int(..., strict=True)`: `ValueError` falls back.
        match py_int(raw).map_err(|_| Decline("page_size digits"))? {
            Some(PyInt::Small(v)) if v > 0 => return Ok(v.min(tenant.max_page_size)),
            Some(PyInt::Big { negative: false }) => return Ok(tenant.max_page_size),
            _ => {}
        }
    }
    Ok(tenant.default_page_size)
}

/// The page to show, or `Err(Ok(()))` for DRF's `NotFound("Invalid page.")`.
pub struct Page {
    pub number: i64,
    pub size: i64,
    pub count: i64,
    pub num_pages: i64,
}

#[derive(Serialize)]
struct Pagination {
    next: i64,
    previous: i64,
    count: i64,
    current: i64,
    total_pages: i64,
    start_index: i64,
    end_index: i64,
}

impl Page {
    /// `paginate_queryset`'s page choice: `Ok(None)` is `InvalidPage`.
    ///
    /// # Errors
    ///
    /// [`Decline`] for digits `int()` would read but this port does not.
    pub fn choose(query: &QueryDict, size: i64, count: i64) -> Result<Option<Self>, Decline> {
        // `num_pages` with `allow_empty_first_page` and no orphans.
        let num_pages = (count.max(1) + size - 1) / size;
        let raw = query.get("page").filter(|v| !v.is_empty());
        let number = match raw {
            None => 1,
            Some("last") => num_pages,
            Some(raw) => match py_int(raw).map_err(|_| Decline("page digits"))? {
                Some(PyInt::Small(v)) => v,
                Some(PyInt::Big { .. }) | None => return Ok(None),
            },
        };
        if number < 1 || number > num_pages {
            return Ok(None);
        }
        Ok(Some(Self {
            number,
            size,
            count,
            num_pages,
        }))
    }

    /// `(LIMIT, OFFSET)` of `object_list[bottom:top]`.
    pub fn slice(&self) -> (i64, i64) {
        let bottom = (self.number - 1) * self.size;
        let top = (bottom + self.size).min(self.count);
        ((top - bottom).max(0), bottom)
    }

    fn pagination(&self) -> Pagination {
        Pagination {
            next: if self.number < self.num_pages {
                self.number + 1
            } else {
                0
            },
            previous: if self.number > 1 { self.number - 1 } else { 0 },
            count: self.count,
            current: self.number,
            total_pages: self.num_pages,
            start_index: if self.count == 0 {
                0
            } else {
                self.size * (self.number - 1) + 1
            },
            end_index: if self.number == self.num_pages {
                self.count
            } else {
                self.number * self.size
            },
        }
    }

    /// `get_paginated_response(data)` for a view without `get_ql_fields`.
    pub fn response<T: Serialize>(&self, results: Vec<T>) -> impl Serialize {
        #[derive(Serialize)]
        #[expect(
            clippy::empty_structs_with_brackets,
            reason = "serializes as {}, not null"
        )]
        struct Empty {}
        self.response_with(results, Empty {})
    }

    /// `get_paginated_response(data)` with the view's `autocomplete`.
    pub fn response_with<T: Serialize, A: Serialize>(
        &self,
        results: Vec<T>,
        autocomplete: A,
    ) -> impl Serialize {
        #[derive(Serialize)]
        struct Paginated<T, A> {
            pagination: Pagination,
            results: Vec<T>,
            autocomplete: A,
        }
        Paginated {
            pagination: self.pagination(),
            results,
            autocomplete,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant() -> Tenant {
        Tenant {
            default_page_size: 20,
            max_page_size: 100,
            avatars: String::new(),
        }
    }

    fn q(s: &str) -> QueryDict {
        QueryDict::parse(s).expect("query")
    }

    #[test]
    fn page_size_matches_drf() {
        assert_eq!(page_size(&q(""), &tenant()), Ok(20));
        assert_eq!(page_size(&q("page_size=5"), &tenant()), Ok(5));
        assert_eq!(page_size(&q("page_size=0"), &tenant()), Ok(20));
        assert_eq!(page_size(&q("page_size=abc"), &tenant()), Ok(20));
        assert_eq!(page_size(&q("page_size=1000"), &tenant()), Ok(100));
        assert_eq!(page_size(&q("page_size=1&page_size=7"), &tenant()), Ok(7));
    }

    #[test]
    fn pages_match_django() {
        let page = |s, size, count| Page::choose(&q(s), size, count).expect("ascii");
        assert!(page("", 20, 0).is_some_and(|p| p.num_pages == 1 && p.slice() == (0, 0)));
        assert!(page("page=last", 3, 10).is_some_and(|p| p.number == 4 && p.slice() == (1, 9)));
        assert!(page("page=0", 3, 10).is_none());
        assert!(page("page=2.0", 3, 10).is_none());
        assert!(page("page=5", 3, 10).is_none());
        assert!(page("page=", 3, 10).is_some_and(|p| p.number == 1));
    }
}
