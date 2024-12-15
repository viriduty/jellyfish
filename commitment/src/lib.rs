// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

#![no_std]

use ark_std::{borrow::Borrow, fmt::Debug, hash::Hash, error::Error, UniformRand};

/// A type alias for a result used in the verification process.
/// This type is a `Result` which simplifies the return types for verification functions.
type VerificationResult = Result<(), VerificationError>;

/// Custom error type for the verification process.
/// This allows for more detailed error handling instead of just `()`.
#[derive(Debug)]
pub enum VerificationError {
    /// A specific error if the commitment verification fails.
    InvalidCommitment,
    /// An error representing issues in the commitment process.
    CommitmentError,
}

/// Trait for cryptographic commitment schemes.
/// Provides methods for committing to an input and verifying the commitment.
pub trait CommitmentScheme {
    /// The type of input data to be committed.
    type Input;

    /// The type of the output commitment value.
    type Output: Clone + Debug + PartialEq + Eq + Hash;

    /// The type of randomness (blinding factor) used in the commitment.
    type Randomness: Clone + Debug + PartialEq + Eq + UniformRand;

    /// The error type used in the commitment process.
    type Error: Error;

    /// Commit algorithm that takes `input` and an optional randomness `r`.
    ///
    /// Returns a commitment value based on the input and the optional blinding factor.
    fn commit<T: Borrow<Self::Input>>(
        input: T,
        r: Option<&Self::Randomness>,
    ) -> Result<Self::Output, Self::Error>;

    /// Verification algorithm that checks if the commitment is valid.
    ///
    /// Returns `Ok(())` if the commitment is valid, or `Err(VerificationError)` if it is invalid.
    fn verify<T: Borrow<Self::Input>>(
        input: T,
        r: Option<&Self::Randomness>>,
        comm: &Self::Output,
    ) -> Result<VerificationResult, Self::Error>;
}
