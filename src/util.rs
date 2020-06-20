use std::mem;

pub const fn log2(x: usize) -> usize {
    (mem::size_of::<usize>() * 8) - (x.leading_zeros() as usize) - 1
}

macro_rules! arr_map {
    ($array:expr, $func:expr) => {{
        use std::mem;
        pub fn map<F: Sized + (Fn(&A) -> B), A: Sized, B: Sized, const L: usize>(
            v: &[A; L],
            m: F,
        ) -> [B; L] {
            // create an array of uninitialized array members
            // MaybeUninit is needed to ensure that a potential destructor is not run
            // when overwriting the uninitialized array members (leading to UB).
            let mut res: [mem::MaybeUninit<B>; L] =
                unsafe { mem::MaybeUninit::uninit().assume_init() };
            for (i, e) in v.iter().enumerate() {
                res[i] = mem::MaybeUninit::new(m(e));
            }

            // now that everything in res is initialized,
            // we can safely transmute the MaybeUninit wrapper away
            //
            // I can find no way around this copy without boxing the array
            unsafe { mem::transmute_copy(&res) }
        }
        map($array, $func)
    }};
}

macro_rules! arr_map_box {
    ($array:expr, $func:expr) => {{
        use std::mem;

        #[inline(always)]
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
        // hence it should be safe to remove the MaybeUninit wrapper.
        let res_muted = unsafe { mem::transmute(res_maybe) };
        let dst_ptr = &res_muted as *const _;

        // enforce type equality
        // (allows the type-checker to infer the type of "res_muted")
        type_check($func, src_ptr, dst_ptr, &$array);
        res_muted
    }};
}

macro_rules! arr_map_owned_box {
    ($array:expr, $func:expr) => {{
        use std::mem;

        #[inline(always)]
        fn map<F: Sized + (Fn(A) -> B), A: Sized, B: Sized, const L: usize>(
            v: [A; L],
            m: F,
        ) -> Box<[mem::MaybeUninit<B>; L]> {
            // create an array of uninitialized array members
            // MaybeUninit is needed to ensure that a potential destructor is not run
            // when overwriting the uninitialized array members (leading to UB).
            let mut res: Box<[mem::MaybeUninit<B>; L]> = unsafe { Box::new_uninit().assume_init() };
            let mut val: [mem::MaybeUninit<A>; L] = unsafe { mem::transmute_copy(&v) };

            // avoid potentially running the destructor twice
            mem::forget(v);

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
        fn type_check<F: Sized + (Fn(A) -> B), A: Sized, B: Sized, const L: usize>(
            _f: F,
            _src_ptr: *const Box<[mem::MaybeUninit<B>; L]>,
            _dst_ptr: *const Box<[B; L]>,
            _v: *const [A; L],
        ) {
        }

        // obtain raw pointer for type check
        let arr_ptr = &$array as *const _;

        // apply the map and obtain a boxed array of
        let res_maybe = map($array, $func);
        let src_ptr = &res_maybe as *const _;

        // every element is initialized and the outer container is an array
        // hence it should be safe to remove the MaybeUninit wrapper.
        let res_muted = unsafe { mem::transmute(res_maybe) };
        let dst_ptr = &res_muted as *const _;

        // enforce type equality
        // (allows the type-checker to infer the type of "res_muted")
        type_check($func, src_ptr, dst_ptr, arr_ptr);
        res_muted
    }};
}

#[test]
fn test() {
    let v: [u8; 4] = [1, 2, 3, 5];
    let r = arr_map_owned_box!(v, |x| { (x + 1u8) as u8 });
    println!("{:?}", r);
}

pub fn arr_from_iter<I: Iterator<Item = A>, A: Sized, const L: usize>(iter: &mut I) -> [A; L] {
    // create an array of uninitialized array members
    // MaybeUninit is needed to ensure that a potential destructor is not run
    // when overwriting the uninitialized array members (leading to UB).
    let mut res: [mem::MaybeUninit<A>; L] = unsafe { mem::MaybeUninit::uninit().assume_init() };
    for i in 0..L {
        res[i] = mem::MaybeUninit::new(iter.next().unwrap());
    }

    // now that everything in res is initialized,
    // we can safely transmute the MaybeUninit wrapper away
    unsafe { mem::transmute_copy(&res) }
}

pub fn arr_map_owned<F: Sized + (Fn(A) -> B), A: Sized, B: Sized, const L: usize>(
    v: [A; L],
    m: F,
) -> [B; L] {
    // create an array of uninitialized array members
    // MaybeUninit is needed to ensure that a potential destructor is not run
    // when overwriting the uninitialized array members (leading to UB).
    let mut res: [mem::MaybeUninit<B>; L] = unsafe { mem::MaybeUninit::uninit().assume_init() };
    let mut val: [mem::MaybeUninit<A>; L] = unsafe { mem::transmute_copy(&v) };

    // avoid potentially running the destructor twice
    mem::forget(v);

    for i in 0..L {
        // replace the next element in the array
        // with an uninitialized value (to avoid Copy)
        let e = mem::replace(&mut val[i], mem::MaybeUninit::uninit());

        // we know that e is initialized (coming from safe Rust)
        res[i] = mem::MaybeUninit::new(m(unsafe { e.assume_init() }));
    }

    // now that everything in res is initialized,
    // we can safely transmute the MaybeUninit wrapper away
    unsafe { mem::transmute_copy(&res) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log2() {
        assert_eq!(log2(1024), 10);
    }
}
