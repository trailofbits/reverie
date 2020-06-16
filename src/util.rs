use std::mem;
use std::ptr;

pub const fn log2(x: usize) -> usize {
    (mem::size_of::<usize>() * 8) - (x.leading_zeros() as usize) - 1
}

pub fn arr_map<F: Sized + (Fn(&A) -> B), A: Sized, B: Sized, const L: usize>(
    v: &[A; L],
    m: F,
) -> [B; L] {
    // create an array of uninitialized array members
    // MaybeUninit is needed to ensure that a potential destructor is not run
    // when overwriting the uninitialized array members (leading to UB).
    let mut res: [mem::MaybeUninit<B>; L] = unsafe { mem::MaybeUninit::uninit().assume_init() };
    for (i, e) in v.iter().enumerate() {
        res[i] = mem::MaybeUninit::new(m(e));
    }

    // now that everything in res is initialized,
    // we can safely transmute the MaybeUninit wrapper away
    unsafe { mem::transmute_copy(&res) }
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
