window.SIDEBAR_ITEMS = {"attr":[["tagged_blob","Derive serdes for a type which serializes as a binary blob."]],"enum":[["TaggedBlobError",""]],"fn":[["bytes_to_field_elements","One-way, deterministic, infallible conversion between arbitrary bytes (of unknown length and potentially non-canonical) to field elements. This function converts bytes to vector of BaseField."],["compute_len_to_next_multiple",""],["field_switching",""],["fq_to_fr","Convert a base field element to a scalar field element. Perform a mod reduction if the base field element is greater than the modulus of the scalar field."],["fq_to_fr_with_mask","Convert a field element in F(rom) to a field element in T(o), with |T| < |F|; truncating the element via masking the top F::size_in_bits() - T::size_in_bits() with 0s"],["fr_to_fq","Convert a scalar field element to a base field element. Mod reduction is not performed since the conversion occurs for fields on a same curve."],["hash_to_field","Hash a sequence of bytes to into a field element, whose order is less than 256 bits."],["multi_pairing","A simple wrapper of multi-pairing function."],["pad_with_zeros",""]],"macro":[["deserialize_canonical_bytes",""],["test_serde_default",""],["to_bytes","Takes as input a struct, and converts them to a series of bytes. All traits that implement `CanonicalSerialize` can be automatically converted to bytes in this manner."]],"mod":[["field_elem","Serializers for finite field elements."],["par_utils","Utilities for parallel code."],["tagged_blob",""]],"struct":[["CanonicalBytes","A helper for converting CanonicalSerde bytes to standard Serde bytes. use this struct as intermediate target instead of directly deriving serde::Serialize/Deserialize to avoid implementation of Visitors."],["TaggedBlob","Helper type for serializing tagged blobs."],["Vec","A contiguous growable array type, written as `Vec<T>`, short for ‘vector’."]],"trait":[["Tagged","Trait for types whose serialization is not human-readable."]]};