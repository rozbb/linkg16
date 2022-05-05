//! Implementes serialization and deserialization for `VerifyingKey`

use crate::groth16::VerifyingKey;

use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};

// This is the key that gets serialized. It's the "unprepared" version of VerifyingKey
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
struct SerializedVerifyingKey<E: PairingEngine> {
    pub ark_vk: ark_groth16::VerifyingKey<E>,
    pub g1_gen: E::G1Projective,
    pub delta_g1: E::G1Projective,
}

// To serialize a VerifyingKey, we "unprepare" it and serialize that
impl<E: PairingEngine> CanonicalSerialize for VerifyingKey<E> {
    fn serialize<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        let s = SerializedVerifyingKey {
            ark_vk: self.ark_pvk.vk.clone(),
            g1_gen: self.g1_gen,
            delta_g1: self.delta_g1,
        };
        s.serialize(writer)
    }

    fn serialize_uncompressed<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        let s = SerializedVerifyingKey {
            ark_vk: self.ark_pvk.vk.clone(),
            g1_gen: self.g1_gen,
            delta_g1: self.delta_g1,
        };
        s.serialize_uncompressed(writer)
    }

    // This is inefficient. Whatever
    fn serialized_size(&self) -> usize {
        let s = SerializedVerifyingKey {
            ark_vk: self.ark_pvk.vk.clone(),
            g1_gen: self.g1_gen,
            delta_g1: self.delta_g1,
        };
        s.serialized_size()
    }

    // This is inefficient. Whatever
    fn uncompressed_size(&self) -> usize {
        let s = SerializedVerifyingKey {
            ark_vk: self.ark_pvk.vk.clone(),
            g1_gen: self.g1_gen,
            delta_g1: self.delta_g1,
        };
        s.uncompressed_size()
    }
}

// To deserialize a VerifyingKey, we deserialize the unprepared version, and prepare it
impl<E: PairingEngine> CanonicalDeserialize for VerifyingKey<E> {
    fn deserialize<R: Read>(reader: R) -> Result<Self, SerializationError> {
        let svk = SerializedVerifyingKey::<E>::deserialize(reader)?;

        Ok(VerifyingKey {
            ark_pvk: ark_groth16::prepare_verifying_key(&svk.ark_vk),
            g1_gen: svk.g1_gen,
            delta_g1: svk.delta_g1,
        })
    }

    fn deserialize_unchecked<R: Read>(reader: R) -> Result<Self, SerializationError> {
        let svk = SerializedVerifyingKey::<E>::deserialize_unchecked(reader)?;

        Ok(VerifyingKey {
            ark_pvk: ark_groth16::prepare_verifying_key(&svk.ark_vk),
            g1_gen: svk.g1_gen,
            delta_g1: svk.delta_g1,
        })
    }
}
