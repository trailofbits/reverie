use super::Writer;

use std::marker::PhantomData;

pub struct VoidWriter<T> {
    _ph: PhantomData<T>,
}

impl<T> VoidWriter<T> {
    pub fn new() -> Self {
        VoidWriter { _ph: PhantomData }
    }
}

impl<T> Writer<T> for VoidWriter<T> {
    fn write(&mut self, _v: T) {}
}
