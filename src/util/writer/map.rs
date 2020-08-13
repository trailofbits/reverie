use super::Writer;

use std::marker::PhantomData;

pub struct MapWriter<O, T, F: Fn(T) -> O, W: Writer<O>> {
    func: F,
    inner: W,
    _ph: PhantomData<T>,
}

impl<O, T, F: Fn(T) -> O, W: Writer<O>> MapWriter<O, T, F, W> {
    pub fn new(f: F, out: W) -> Self {
        MapWriter {
            func: f,
            inner: out,
            _ph: PhantomData,
        }
    }
}

impl<O, T, F: Fn(T) -> O, W: Writer<O>> Writer<T> for MapWriter<O, T, F, W> {
    fn write(&mut self, v: T) {
        self.inner.write((self.func)(v))
    }
}
