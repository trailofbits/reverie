pub trait Reader<T> {
    fn read(&mut self) -> T;
}
