use serde::de::{Error, SeqAccess, Unexpected, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use std::fmt;
use std::marker::PhantomData;

use super::Array;

struct ArrayVistor<T, const L: usize>(PhantomData<T>);

impl<'de, T: Deserialize<'de>, const L: usize> Visitor<'de> for ArrayVistor<T, L> {
    type Value = Array<T, L>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a sequence of bytes {} exactly elements long", L)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        // read into vector
        let mut res: Vec<T> = Vec::with_capacity(L);
        while let Some(v) = seq.next_element()? {
            res.push(v);
            if res.len() > L {
                break;
            }
        }

        // check length of vector
        if res.len() == L {
            Ok(Array::from_iter(res.into_iter()))
        } else {
            Err(A::Error::invalid_value(Unexpected::Seq, &self))
        }
    }
}

impl<T: Serialize, const L: usize> Serialize for Array<T, L> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tup = serializer.serialize_tuple(L)?;
        for i in 0..L {
            tup.serialize_element(&self.0[i])?;
        }
        tup.end()
    }
}

impl<'de, T: Deserialize<'de>, const L: usize> Deserialize<'de> for Array<T, L> {
    fn deserialize<D>(deserializer: D) -> Result<Array<T, L>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_tuple(L, ArrayVistor::<T, L>(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bincode;

    #[test]
    fn serde_array() {
        {
            let array: Array<u8, 64> = Array::new(1);
            let encoded = bincode::serialize(&array).unwrap();
            let result: Array<u8, 64> = bincode::deserialize(&encoded[..]).unwrap();
            assert_eq!(array, result);
        }

        {
            let array: Array<u64, 75> = Array::new(54);
            let encoded = bincode::serialize(&array).unwrap();
            let result: Array<u64, 75> = bincode::deserialize(&encoded[..]).unwrap();
            assert_eq!(array, result);
        }

        {
            let array: Array<bool, 127> = Array::new(false);
            let encoded = bincode::serialize(&array).unwrap();
            let result: Array<bool, 127> = bincode::deserialize(&encoded[..]).unwrap();
            assert_eq!(array, result);
        }
    }
}
