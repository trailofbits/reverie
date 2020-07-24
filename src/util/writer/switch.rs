use super::Writer;

use std::marker::PhantomData;

pub struct SwitchWriter<T, W: Writer<T>> {
    writer: Option<W>,
    _ph: PhantomData<T>,
}

impl<T, W: Writer<T>> SwitchWriter<T, W> {
    pub fn new(writer: W, enabled: bool) -> Self {
        // immediately drop the inner writer if not enabled
        Self {
            writer: if enabled { Some(writer) } else { None },
            _ph: PhantomData,
        }
    }
}

impl<T, W: Writer<T>> Writer<T> for SwitchWriter<T, W> {
    fn write(&mut self, elem: T) {
        if let Some(writer) = self.writer.as_mut() {
            writer.write(elem);
        }
    }
}
