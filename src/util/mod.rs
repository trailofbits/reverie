mod subset;
mod vec;
mod writer;

pub use subset::*;
pub use vec::VecMap;
pub use writer::*;

use std::mem;

pub const fn log2(x: usize) -> usize {
    (mem::size_of::<usize>() * 8) - (x.leading_zeros() as usize) - 1
}

macro_rules! arr_map_stack {
    ($array:expr, $func:expr) => {{
        use std::mem;

        #[inline(always)]
        #[allow(dead_code)]
        fn map<F: Sized + (Fn(&A) -> B), A: Sized, B: Sized, const L: usize>(
            v: &[A; L],
            m: F,
        ) -> [B; L] {
            let mut res: [mem::MaybeUninit<B>; L] =
                unsafe { mem::MaybeUninit::uninit().assume_init() };
            for (i, e) in v.iter().enumerate() {
                res[i] = mem::MaybeUninit::new(m(e));
            }
            unsafe { mem::transmute_copy(&res) }
        }

        map($array, $func)
    }};
}

macro_rules! arr_map {
    ($array:expr, $func:expr) => {{
        use std::mem;

        #[inline(always)]
        #[allow(dead_code)]
        fn map<F: Sized + (Fn(&A) -> B), A: Sized, B: Sized, const L: usize>(
            v: &[A; L],
            m: F,
        ) -> Box<[mem::MaybeUninit<B>; L]> {
            let mut res: Box<[mem::MaybeUninit<B>; L]> = unsafe { Box::new_uninit().assume_init() };
            for (i, e) in v.iter().enumerate() {
                res[i] = mem::MaybeUninit::new(m(e));
            }
            res
        }

        #[inline(always)]
        #[allow(dead_code)]
        fn type_check<F: Sized + (Fn(&A) -> B), A: Sized, B: Sized, const L: usize>(
            _f: F,
            _src_ptr: *const Box<[mem::MaybeUninit<B>; L]>,
            _dst_ptr: *const Box<[B; L]>,
            _v: &[A; L],
        ) {
        }

        // apply the map and obtain a boxed array of
        let res_maybe = map($array, $func);
        let src_ptr = &res_maybe as *const _;

        // every element is initialized and the outer container is an array
        // hence it is safe to remove the MaybeUninit wrapper.
        let res_muted = unsafe { mem::transmute(res_maybe) };
        let dst_ptr = &res_muted as *const _;

        // enforce type equality
        // (allows the type-checker to infer the type of "res_muted")
        type_check($func, src_ptr, dst_ptr, &$array);
        res_muted
    }};
}

macro_rules! arr_map_owned {
    ($array:expr, $func:expr) => {{
        use std::mem;

        #[inline(always)]
        #[allow(dead_code)]
        fn map<F: Sized + (Fn(A) -> B), A: Sized, B: Sized, const L: usize>(
            v: Box<[A; L]>,
            m: F,
        ) -> Box<[mem::MaybeUninit<B>; L]> {
            // create an array of uninitialized array members
            // MaybeUninit is needed to ensure that a potential destructor is not run
            // when overwriting the uninitialized array members (leading to UB).
            let mut res: Box<[mem::MaybeUninit<B>; L]> = unsafe { Box::new_uninit().assume_init() };
            let mut val: Box<[mem::MaybeUninit<A>; L]> = unsafe { mem::transmute(v) };

            for i in 0..L {
                // replace the next element in the array
                // with an uninitialized value (to avoid Copy)
                let e = mem::replace(&mut val[i], mem::MaybeUninit::uninit());

                // we know that e is initialized (coming from safe Rust)
                res[i] = mem::MaybeUninit::new(m(unsafe { e.assume_init() }));
            }

            res
        }

        #[inline(always)]
        #[allow(dead_code)]
        fn type_check<F: Sized + (Fn(A) -> B), A: Sized, B: Sized, const L: usize>(
            _f: F,
            _src_ptr: *const Box<[mem::MaybeUninit<B>; L]>,
            _dst_ptr: *const Box<[B; L]>,
            _v: *const Box<[A; L]>,
        ) {
        }

        // obtain raw pointer for type check
        let arr_ptr = &$array as *const _;

        // apply the map and obtain a boxed array of
        let res_maybe = map($array, $func);
        let src_ptr = &res_maybe as *const _;

        // every element is initialized and the outer container is an array
        // hence it is safe to remove the MaybeUninit wrapper.
        let res_muted = unsafe { mem::transmute(res_maybe) };
        let dst_ptr = &res_muted as *const _;

        // enforce type equality
        // (allows the type-checker to infer the type of "res_muted")
        type_check($func, src_ptr, dst_ptr, arr_ptr);
        res_muted
    }};
}

/// TODO: Consider a variant with stronger types:
/// Enforce equality between the length of the iter and array at compile time.
macro_rules! arr_from_iter {
    ($iter:expr) => {{
        use std::mem;

        #[inline(always)]
        #[allow(dead_code)]
        fn map<I: Iterator<Item = A>, A: Sized, const L: usize>(
            mut iter: I,
        ) -> Box<[mem::MaybeUninit<A>; L]> {
            let mut res: Box<[mem::MaybeUninit<A>; L]> = unsafe { Box::new_uninit().assume_init() };
            for i in 0..L {
                res[i] = mem::MaybeUninit::new(iter.next().unwrap());
            }
            debug_assert!(iter.next().is_none(), "iterator longer than array");
            res
        }
        #[inline(always)]
        #[allow(dead_code)]
        fn type_check<A: Sized, const L: usize>(
            _src_ptr: *const Box<[mem::MaybeUninit<A>; L]>,
            _dst_ptr: *const Box<[A; L]>,
        ) {
        }

        // apply the map and obtain a boxed array of
        let res_maybe = map($iter);
        let src_ptr = &res_maybe as *const _;

        // every element is initialized and the outer container is an array
        // hence it is safe to remove the MaybeUninit wrapper.
        let res_muted = unsafe { mem::transmute(res_maybe) };
        let dst_ptr = &res_muted as *const _;

        // enforce type equality
        // (allows the type-checker to infer the type of "res_muted")
        type_check(src_ptr, dst_ptr);
        res_muted
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log2() {
        assert_eq!(log2(1024), 10);
    }
}
