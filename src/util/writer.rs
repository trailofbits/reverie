use std::marker::PhantomData;

pub trait Writer<T> {
    fn write(&mut self, v: &T);
}

pub struct VoidWriter<T> {
    _ph: PhantomData<T>,
}

impl<T> VoidWriter<T> {
    pub fn new() -> Self {
        VoidWriter { _ph: PhantomData }
    }
}

impl<T> Writer<T> for VoidWriter<T> {
    fn write(&mut self, v: &T) {}
}
