use std::marker::PhantomData;

use crossbeam::channel::Sender;

pub trait Writer<T> {
    fn write(&mut self, v: T);
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
    fn write(&mut self, _v: T) {}
}

impl<T> Writer<T> for Vec<T> {
    fn write(&mut self, v: T) {
        self.push(v)
    }
}

impl<'a, T> Writer<T> for &'a mut Vec<T> {
    fn write(&mut self, v: T) {
        self.push(v)
    }
}

impl<T> Writer<T> for Sender<T> {
    fn write(&mut self, v: T) {
        let _ = self.send(v); // TODO: extend to propagate errors
    }
}
