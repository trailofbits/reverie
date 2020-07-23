use std::cmp::PartialEq;
use std::iter::Iterator;
use std::ops::{Deref, DerefMut};

use std::fmt::{self, Write};
use std::mem;

// relevant serde implementations for serializing / deserializing
mod serde;

pub struct Array<T: Sized, const L: usize>(Box<[T; L]>);

pub struct ArrayIter<'a, T: Sized, const L: usize> {
    array: &'a Array<T, L>,
    next: usize,
}

impl<T: fmt::Debug, const L: usize> fmt::Debug for Array<T, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_char('[')?;
        for i in 0..L {
            if i == L - 1 {
                write!(f, "{:?}", self.0[i])?;
            } else {
                write!(f, "{:?}, ", self.0[i])?;
            }
        }
        f.write_char(']')
    }
}

impl<T: Sized + PartialEq, const L: usize> PartialEq for Array<T, L> {
    fn eq(&self, other: &Self) -> bool {
        for i in 0..L {
            if self.0[i] != other.0[i] {
                return false;
            }
        }
        true
    }
}

impl<'a, T: Sized, const L: usize> Iterator for ArrayIter<'a, T, L> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= L {
            None
        } else {
            let elem = unsafe { self.array.get_unchecked(self.next) };
            self.next += 1;
            Some(elem)
        }
    }
}

impl<T, const L: usize> Deref for Array<T, L> {
    type Target = [T; L];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T, const L: usize> DerefMut for Array<T, L> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Sized + Copy, const L: usize> Array<T, L> {
    pub fn new(v: T) -> Self {
        Array(Box::new([v; L]))
    }
}

impl<T: Sized, const L: usize> Array<T, L> {
    pub fn unbox(self) -> [T; L] {
        *self.0
    }

    pub fn map<O, F: Fn(&T) -> O>(&self, f: F) -> Array<O, L> {
        let mut res: Box<[mem::MaybeUninit<O>; L]> = unsafe { Box::new_uninit().assume_init() };
        for i in 0..L {
            res[i] = mem::MaybeUninit::new(f(&self.0[i]))
        }
        Array(unsafe { mem::transmute(res) })
    }

    pub fn from_iter<I: Iterator<Item = T>>(mut iter: I) -> Self {
        let mut res: Box<[mem::MaybeUninit<T>; L]> = unsafe { Box::new_uninit().assume_init() };
        for i in 0..L {
            res[i] = mem::MaybeUninit::new(iter.next().unwrap());
        }
        Array(unsafe { mem::transmute(res) })
    }

    pub fn iter(&self) -> ArrayIter<T, L> {
        ArrayIter {
            next: 0,
            array: self,
        }
    }
}
