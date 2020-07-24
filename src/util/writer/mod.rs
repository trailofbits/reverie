mod switch;
mod void;

pub use switch::*;
pub use void::*;

pub trait Writer<T> {
    fn write(&mut self, v: T);
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
