pub trait Writer<T> {
    fn write(&mut self, v: &T);
}
