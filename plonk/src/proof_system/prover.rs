// Copyright (c) 2022 TRI (spectrum.xyz)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use core::ops::Neg;

use super::structs::{
    eval_merged_lookup_witness, eval_merged_table, Challenges, Oracles, PlookupEvaluations,
    PlookupOracles, ProofEvaluations, ProvingKey,
};
use crate::{
    bencher::{fft_end, fft_start, msm_end, msm_start, poly_eval_end, poly_eval_start},
    circuit::Arithmetization,
    constants::{domain_size_ratio, GATE_WIDTH},
    errors::{PlonkError, SnarkError::*},
    proof_system::structs::CommitKey,
};
use ark_ec::PairingEngine;
use ark_ff::{FftField, Field, One, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, Polynomial,
    Radix2EvaluationDomain, UVPolynomial,
};
use ark_poly_commit::{
    kzg10::{Commitment, Randomness, KZG10},
    PCRandomness,
};
use ark_std::{
    rand::{CryptoRng, RngCore},
    string::ToString,
    vec,
    vec::Vec,
};
use rayon::prelude::*;

type CommitmentsAndPolys<E> = (
    Vec<Commitment<E>>,
    Vec<DensePolynomial<<E as PairingEngine>::Fr>>,
);

/// A Plonk IOP prover.
pub(crate) struct Prover<E: PairingEngine> {
    domain: Radix2EvaluationDomain<E::Fr>,
    quot_domain: GeneralEvaluationDomain<E::Fr>,
}

impl<E: PairingEngine> Prover<E> {
    /// Construct a Plonk prover that uses a domain with size `domain_size` and
    /// quotient polynomial domain with a size that is larger than the degree of
    /// the quotient polynomial.
    /// * `num_wire_types` - number of wire types in the corresponding
    ///   constraint system.
    pub(crate) fn new(domain_size: usize, num_wire_types: usize) -> Result<Self, PlonkError> {
        let domain = Radix2EvaluationDomain::<E::Fr>::new(domain_size)
            .ok_or(PlonkError::DomainCreationError)?;
        let quot_domain = GeneralEvaluationDomain::<E::Fr>::new(
            domain_size * domain_size_ratio(domain_size, num_wire_types),
        )
        .ok_or(PlonkError::DomainCreationError)?;
        Ok(Self {
            domain,
            quot_domain,
        })
    }

    /// Round 1:
    /// 1. Compute and commit wire witness polynomials.
    /// 2. Compute public input polynomial.
    /// Return the wire witness polynomials and their commitments,
    /// also return the public input polynomial.
    pub(crate) fn run_1st_round<C: Arithmetization<E::Fr>, R: CryptoRng + RngCore>(
        &self,
        prng: &mut R,
        ck: &CommitKey<E>,
        cs: &C,
    ) -> Result<(CommitmentsAndPolys<E>, DensePolynomial<E::Fr>), PlonkError> {
        let wire_polys: Vec<DensePolynomial<E::Fr>> = cs
            .compute_wire_polynomials()?
            .into_iter()
            .map(|poly| self.mask_polynomial(prng, poly, 1))
            .collect();
        msm_start();
        let wires_poly_comms = Self::commit_polynomials(ck, &wire_polys)?;
        msm_end();
        let pub_input_poly = cs.compute_pub_input_polynomial()?;
        Ok(((wires_poly_comms, wire_polys), pub_input_poly))
    }

    /// Round 1.5 (Plookup): Compute and commit the polynomials that interpolate
    /// the sorted concatenation of the (merged) lookup table and the
    /// (merged) witnesses in lookup gates. Return the sorted vector, the
    /// polynomials and their commitments, as well as the merged lookup table.
    /// `cs` is guaranteed to support lookup.
    #[allow(clippy::type_complexity)]
    pub(crate) fn run_plookup_1st_round<C: Arithmetization<E::Fr>, R: CryptoRng + RngCore>(
        &self,
        prng: &mut R,
        ck: &CommitKey<E>,
        cs: &C,
        tau: E::Fr,
    ) -> Result<(CommitmentsAndPolys<E>, Vec<E::Fr>, Vec<E::Fr>), PlonkError> {
        let merged_lookup_table = cs.compute_merged_lookup_table(tau)?;
        let (sorted_vec, h_1_poly, h_2_poly) =
            cs.compute_lookup_sorted_vec_polynomials(tau, &merged_lookup_table)?;
        let h_1_poly = self.mask_polynomial(prng, h_1_poly, 2);
        let h_2_poly = self.mask_polynomial(prng, h_2_poly, 2);
        let h_polys = vec![h_1_poly, h_2_poly];
        msm_start();
        let h_poly_comms = Self::commit_polynomials(ck, &h_polys)?;
        msm_end();
        Ok(((h_poly_comms, h_polys), sorted_vec, merged_lookup_table))
    }

    /// Round 2: Compute and commit the permutation grand product polynomial.
    /// Return the grand product polynomial and its commitment.
    pub(crate) fn run_2nd_round<C: Arithmetization<E::Fr>, R: CryptoRng + RngCore>(
        &self,
        prng: &mut R,
        ck: &CommitKey<E>,
        cs: &C,
        challenges: &Challenges<E::Fr>,
    ) -> Result<(Commitment<E>, DensePolynomial<E::Fr>), PlonkError> {
        let prod_perm_poly = self.mask_polynomial(
            prng,
            cs.compute_prod_permutation_polynomial(&challenges.beta, &challenges.gamma)?,
            2,
        );
        msm_start();
        let prod_perm_comm = Self::commit_polynomial(ck, &prod_perm_poly)?;
        msm_end();
        Ok((prod_perm_comm, prod_perm_poly))
    }

    /// Round 2.5 (Plookup): Compute and commit the Plookup grand product
    /// polynomial. Return the grand product polynomial and its commitment.
    /// `cs` is guaranteed to support lookup
    pub(crate) fn run_plookup_2nd_round<C: Arithmetization<E::Fr>, R: CryptoRng + RngCore>(
        &self,
        prng: &mut R,
        ck: &CommitKey<E>,
        cs: &C,
        challenges: &Challenges<E::Fr>,
        merged_lookup_table: Option<&Vec<E::Fr>>,
        sorted_vec: Option<&Vec<E::Fr>>,
    ) -> Result<(Commitment<E>, DensePolynomial<E::Fr>), PlonkError> {
        if sorted_vec.is_none() {
            return Err(
                ParameterError("Run Plookup with empty sorted lookup vectors".to_string()).into(),
            );
        }

        let prod_lookup_poly = self.mask_polynomial(
            prng,
            cs.compute_lookup_prod_polynomial(
                &challenges.tau,
                &challenges.beta,
                &challenges.gamma,
                merged_lookup_table.unwrap(),
                sorted_vec.unwrap(),
            )?,
            2,
        );
        msm_start();
        let prod_lookup_comm = Self::commit_polynomial(ck, &prod_lookup_poly)?;
        msm_end();
        Ok((prod_lookup_comm, prod_lookup_poly))
    }

    /// Round 3: Return the splitted quotient polynomials and their commitments.
    /// Note that the first `num_wire_types`-1 splitted quotient polynomials
    /// have degree `domain_size`+1.
    pub(crate) fn run_3rd_round(
        &self,
        ck: &CommitKey<E>,
        pks: &[&ProvingKey<E>],
        challenges: &Challenges<E::Fr>,
        online_oracles: &[Oracles<E::Fr>],
        num_wire_types: usize,
    ) -> Result<CommitmentsAndPolys<E>, PlonkError> {
        let quot_poly =
            self.compute_quotient_polynomial(challenges, pks, online_oracles, num_wire_types)?;
        let split_quot_polys = self.split_quotient_polynomial(&quot_poly, num_wire_types)?;
        msm_start();
        let split_quot_poly_comms = Self::commit_polynomials(ck, &split_quot_polys)?;
        msm_end();
        Ok((split_quot_poly_comms, split_quot_polys))
    }

    /// Round 4: Compute linearization polynomial and evaluate polynomials to be
    /// opened.
    ///
    /// Compute the polynomial evaluations for TurboPlonk.
    /// Return evaluations of the Plonk proof.
    pub(crate) fn compute_evaluations(
        &self,
        pk: &ProvingKey<E>,
        challenges: &Challenges<E::Fr>,
        online_oracles: &Oracles<E::Fr>,
        num_wire_types: usize,
    ) -> ProofEvaluations<E::Fr> {
        // TODO: a potential optimization -- dense polynomial evaluations re-computed
        // powers-of-zetas consider pre-compute them and pass them in
        poly_eval_start();
        let wires_evals: Vec<E::Fr> = online_oracles
            .wire_polys
            .par_iter()
            .map(|poly| poly.evaluate(&challenges.zeta))
            .collect();
        let wire_sigma_evals: Vec<E::Fr> = pk
            .sigmas
            .par_iter()
            .take(num_wire_types - 1)
            .map(|poly| poly.evaluate(&challenges.zeta))
            .collect();
        let perm_next_eval = online_oracles
            .prod_perm_poly
            .evaluate(&(challenges.zeta * self.domain.group_gen));

        poly_eval_end();
        ProofEvaluations {
            wires_evals,
            wire_sigma_evals,
            perm_next_eval,
        }
    }

    /// Round 4.5 (Plookup): Compute and return evaluations of Plookup-related
    /// polynomials
    pub(crate) fn compute_plookup_evaluations(
        &self,
        pk: &ProvingKey<E>,
        challenges: &Challenges<E::Fr>,
        online_oracles: &Oracles<E::Fr>,
    ) -> Result<PlookupEvaluations<E::Fr>, PlonkError> {
        poly_eval_start();

        if pk.plookup_pk.is_none() {
            return Err(ParameterError(
                "Evaluate Plookup polynomials without supporting lookup".to_string(),
            )
            .into());
        }
        if online_oracles.plookup_oracles.h_polys.len() != 2 {
            return Err(ParameterError(
                "Evaluate Plookup polynomials without updating sorted lookup vector polynomials"
                    .to_string(),
            )
            .into());
        }

        let range_table_poly_ref = &pk.plookup_pk.as_ref().unwrap().range_table_poly;
        let key_table_poly_ref = &pk.plookup_pk.as_ref().unwrap().key_table_poly;
        let range_table_eval = range_table_poly_ref.evaluate(&challenges.zeta);
        let key_table_eval = key_table_poly_ref.evaluate(&challenges.zeta);
        let h_1_eval = online_oracles.plookup_oracles.h_polys[0].evaluate(&challenges.zeta);
        let q_lookup_eval = pk.q_lookup_poly()?.evaluate(&challenges.zeta);

        // TODO: a potential optimization -- dense polynomial evaluations re-computed
        // powers-of-gs consider pre-compute them and pass them in
        let zeta_mul_g = challenges.zeta * self.domain.group_gen;
        let prod_next_eval = online_oracles
            .plookup_oracles
            .prod_lookup_poly
            .evaluate(&zeta_mul_g);
        let range_table_next_eval = range_table_poly_ref.evaluate(&zeta_mul_g);
        let key_table_next_eval = key_table_poly_ref.evaluate(&zeta_mul_g);
        let h_1_next_eval = online_oracles.plookup_oracles.h_polys[0].evaluate(&zeta_mul_g);
        let h_2_next_eval = online_oracles.plookup_oracles.h_polys[1].evaluate(&zeta_mul_g);
        let q_lookup_next_eval = pk.q_lookup_poly()?.evaluate(&zeta_mul_g);
        let w_3_next_eval = online_oracles.wire_polys[3].evaluate(&zeta_mul_g);
        let w_4_next_eval = online_oracles.wire_polys[4].evaluate(&zeta_mul_g);

        poly_eval_end();
        Ok(PlookupEvaluations {
            range_table_eval,
            key_table_eval,
            h_1_eval,
            q_lookup_eval,
            prod_next_eval,
            range_table_next_eval,
            key_table_next_eval,
            h_1_next_eval,
            h_2_next_eval,
            q_lookup_next_eval,
            w_3_next_eval,
            w_4_next_eval,
        })
    }

    /// Compute linearization polynomial (excluding the quotient part)
    pub(crate) fn compute_non_quotient_component_for_lin_poly(
        &self,
        alpha_base: E::Fr,
        pk: &ProvingKey<E>,
        challenges: &Challenges<E::Fr>,
        online_oracles: &Oracles<E::Fr>,
        poly_evals: &ProofEvaluations<E::Fr>,
        plookup_evals: Option<&PlookupEvaluations<E::Fr>>,
    ) -> Result<DensePolynomial<E::Fr>, PlonkError> {
        let r_circ = Self::compute_lin_poly_circuit_contribution(pk, &poly_evals.wires_evals);
        let r_perm = Self::compute_lin_poly_copy_constraint_contribution(
            pk,
            challenges,
            poly_evals,
            &online_oracles.prod_perm_poly,
        );
        let mut lin_poly = r_circ + r_perm;
        // compute Plookup contribution if support lookup
        let r_lookup = if plookup_evals.is_some() {
            Some(self.compute_lin_poly_plookup_contribution(
                pk,
                challenges,
                &poly_evals.wires_evals,
                plookup_evals.as_ref().unwrap(),
                &online_oracles.plookup_oracles,
            ))
        } else {
            None
        };
        if let Some(lookup_poly) = r_lookup {
            lin_poly = lin_poly + lookup_poly;
        }

        lin_poly = Self::mul_poly(&lin_poly, &alpha_base);
        Ok(lin_poly)
    }

    // Compute the Quotient part of the linearization polynomial:
    //
    // -Z_H(x) * [t1(X) + x^{n+2} * t2(X) + ... + x^{(num_wire_types-1)*(n+2)} *
    // t_{num_wire_types}(X)]
    pub(crate) fn compute_quotient_component_for_lin_poly(
        domain_size: usize,
        zeta: E::Fr,
        quot_polys: &[DensePolynomial<E::Fr>],
    ) -> Result<DensePolynomial<E::Fr>, PlonkError> {
        let vanish_eval = zeta.pow(&[domain_size as u64]) - E::Fr::one();
        let zeta_to_n_plus_2 = (vanish_eval + E::Fr::one()) * zeta * zeta;
        let mut r_quot = quot_polys.first().ok_or(PlonkError::IndexError)?.clone();
        let mut coeff = E::Fr::one();
        for poly in quot_polys.iter().skip(1) {
            coeff *= zeta_to_n_plus_2;
            r_quot = r_quot + Self::mul_poly(poly, &coeff);
        }
        r_quot = Self::mul_poly(&r_quot, &vanish_eval.neg());
        Ok(r_quot)
    }

    /// Compute (aggregated) polynomial opening proofs at point `zeta` and
    /// `zeta * domain_generator`. TODO: Parallelize the computation.
    pub(crate) fn compute_opening_proofs(
        &self,
        ck: &CommitKey<E>,
        pks: &[&ProvingKey<E>],
        zeta: &E::Fr,
        v: &E::Fr,
        online_oracles: &[Oracles<E::Fr>],
        lin_poly: &DensePolynomial<E::Fr>,
    ) -> Result<(Commitment<E>, Commitment<E>), PlonkError> {
        if pks.is_empty() || pks.len() != online_oracles.len() {
            return Err(ParameterError(
                "inconsistent pks/online oracles when computing opening proofs".to_string(),
            )
            .into());
        }
        // List the polynomials to be opened at point `zeta`.
        let mut polys_ref = vec![lin_poly];
        for (pk, oracles) in pks.iter().zip(online_oracles.iter()) {
            for poly in oracles.wire_polys.iter() {
                polys_ref.push(poly);
            }
            // Note we do not add the last wire sigma polynomial.
            for poly in pk.sigmas.iter().take(pk.sigmas.len() - 1) {
                polys_ref.push(poly);
            }

            // Add Plookup related polynomials if support lookup.
            let lookup_flag =
                pk.plookup_pk.is_some() && (oracles.plookup_oracles.h_polys.len() == 2);
            if lookup_flag {
                polys_ref.extend(Self::plookup_open_polys_ref(oracles, pk)?);
            }
        }

        let opening_proof =
            Self::compute_batched_witness_polynomial_commitment(ck, &polys_ref, v, zeta)?;

        // List the polynomials to be opened at point `zeta * w`.
        let mut polys_ref = vec![];
        for (pk, oracles) in pks.iter().zip(online_oracles.iter()) {
            polys_ref.push(&oracles.prod_perm_poly);
            // Add Plookup related polynomials if support lookup
            let lookup_flag =
                pk.plookup_pk.is_some() && (oracles.plookup_oracles.h_polys.len() == 2);
            if lookup_flag {
                polys_ref.extend(Self::plookup_shifted_open_polys_ref(oracles, pk)?);
            }
        }

        let shifted_opening_proof = Self::compute_batched_witness_polynomial_commitment(
            ck,
            &polys_ref,
            v,
            &(self.domain.group_gen * zeta),
        )?;

        Ok((opening_proof, shifted_opening_proof))
    }
}

/// Private helper methods
impl<E: PairingEngine> Prover<E> {
    /// Return the list of plookup polynomials to be opened at point `zeta`
    /// The order should be consistent with the verifier side.
    #[inline]
    fn plookup_open_polys_ref<'a>(
        oracles: &'a Oracles<E::Fr>,
        pk: &'a ProvingKey<E>,
    ) -> Result<Vec<&'a DensePolynomial<E::Fr>>, PlonkError> {
        Ok(vec![
            &pk.plookup_pk.as_ref().unwrap().range_table_poly,
            &pk.plookup_pk.as_ref().unwrap().key_table_poly,
            &oracles.plookup_oracles.h_polys[0],
            pk.q_lookup_poly()?,
        ])
    }

    /// Return the list of plookup polynomials to be opened at point `zeta * g`
    /// The order should be consistent with the verifier side.
    #[inline]
    fn plookup_shifted_open_polys_ref<'a>(
        oracles: &'a Oracles<E::Fr>,
        pk: &'a ProvingKey<E>,
    ) -> Result<Vec<&'a DensePolynomial<E::Fr>>, PlonkError> {
        Ok(vec![
            &oracles.plookup_oracles.prod_lookup_poly,
            &pk.plookup_pk.as_ref().unwrap().range_table_poly,
            &pk.plookup_pk.as_ref().unwrap().key_table_poly,
            &oracles.plookup_oracles.h_polys[0],
            &oracles.plookup_oracles.h_polys[1],
            pk.q_lookup_poly()?,
            &oracles.wire_polys[3],
            &oracles.wire_polys[4],
        ])
    }

    /// Mask the polynomial so that it remains hidden after revealing
    /// `hiding_bound` evaluations.
    fn mask_polynomial<R: CryptoRng + RngCore>(
        &self,
        prng: &mut R,
        poly: DensePolynomial<E::Fr>,
        hiding_bound: usize,
    ) -> DensePolynomial<E::Fr> {
        let mask_poly =
            DensePolynomial::rand(hiding_bound, prng).mul_by_vanishing_poly(self.domain);
        mask_poly + poly
    }

    /// Compute polynomial commitments.
    fn commit_polynomials(
        ck: &CommitKey<E>,
        polys: &[DensePolynomial<E::Fr>],
    ) -> Result<Vec<Commitment<E>>, PlonkError> {
        let poly_comms = polys
            .par_iter()
            .map(|poly| Self::commit_polynomial(ck, poly))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(poly_comms)
    }

    /// Commit a polynomial.
    #[inline]
    fn commit_polynomial(
        ck: &CommitKey<E>,
        poly: &DensePolynomial<E::Fr>,
    ) -> Result<Commitment<E>, PlonkError> {
        let (poly_comm, _) = KZG10::commit(ck, poly, None, None).map_err(PlonkError::PcsError)?;
        Ok(poly_comm)
    }

    /// Return a batched opening proof given a list of polynomials `polys_ref`,
    /// evaluation point `eval_point`, and randomized combiner `r`.
    fn compute_batched_witness_polynomial_commitment(
        ck: &CommitKey<E>,
        polys_ref: &[&DensePolynomial<E::Fr>],
        r: &E::Fr,
        eval_point: &E::Fr,
    ) -> Result<Commitment<E>, PlonkError> {
        // Compute the aggregated polynomial
        let (batch_poly, _) = polys_ref.iter().fold(
            (DensePolynomial::zero(), E::Fr::one()),
            |(acc, coeff), &poly| (acc + Self::mul_poly(poly, &coeff), coeff * r),
        );

        // Compute opening witness polynomial and its commitment
        let empty_rand = Randomness::<E::Fr, DensePolynomial<E::Fr>>::empty();
        let (witness_poly, _) = KZG10::<E, DensePolynomial<E::Fr>>::compute_witness_polynomial(
            &batch_poly,
            *eval_point,
            &empty_rand,
        )?;
        msm_start();
        let res = Self::commit_polynomial(ck, &witness_poly);
        msm_end();
        res
    }

    /// Compute the quotient polynomial via (i)FFTs.
    fn compute_quotient_polynomial(
        &self,
        challenges: &Challenges<E::Fr>,
        pks: &[&ProvingKey<E>],
        online_oracles: &[Oracles<E::Fr>],
        num_wire_types: usize,
    ) -> Result<DensePolynomial<E::Fr>, PlonkError> {
        if pks.is_empty() || pks.len() != online_oracles.len() {
            return Err(ParameterError(
                "inconsistent pks/online oracles when computing quotient polys".to_string(),
            )
            .into());
        }

        let n = self.domain.size();
        let m = self.quot_domain.size();
        let domain_size_ratio = m / n;
        // Compute 1/Z_H(w^i).
        let z_h_inv: Vec<E::Fr> = (0..domain_size_ratio)
            .map(|i| {
                ((E::Fr::multiplicative_generator() * self.quot_domain.element(i)).pow([n as u64])
                    - E::Fr::one())
                .inverse()
                .unwrap()
            })
            .collect();

        // Compute coset evaluations of the quotient polynomial.
        let mut quot_poly_coset_evals_sum = vec![E::Fr::zero(); m];
        let mut alpha_base = E::Fr::one();
        let alpha_3 = challenges.alpha.square() * challenges.alpha;
        let alpha_7 = alpha_3.square() * challenges.alpha;
        // enumerate proving instances
        fft_start();
        for (oracles, pk) in online_oracles.iter().zip(pks.iter()) {
            // lookup_flag = 1 if support Plookup argument.
            let lookup_flag = pk.plookup_pk.is_some();

            // fft_start();
            // Compute coset evaluations.
            let selectors_coset_fft: Vec<Vec<E::Fr>> = pk
                .selectors
                .par_iter()
                .map(|poly| self.quot_domain.coset_fft(poly.coeffs()))
                .collect();
            let sigmas_coset_fft: Vec<Vec<E::Fr>> = pk
                .sigmas
                .par_iter()
                .map(|poly| self.quot_domain.coset_fft(poly.coeffs()))
                .collect();

            let wire_polys_coset_fft: Vec<Vec<E::Fr>> = oracles
                .wire_polys
                .par_iter()
                .map(|poly| self.quot_domain.coset_fft(poly.coeffs()))
                .collect();
            // TODO: (binyi) we can also compute below in parallel with
            // `wire_polys_coset_fft`.
            let prod_perm_poly_coset_fft =
                self.quot_domain.coset_fft(oracles.prod_perm_poly.coeffs());
            let pub_input_poly_coset_fft =
                self.quot_domain.coset_fft(oracles.pub_inp_poly.coeffs());

            // Compute coset evaluations of Plookup online oracles.
            let (
                range_table_coset_fft,
                key_table_coset_fft,
                h_coset_ffts,
                prod_lookup_poly_coset_fft,
            ) = if lookup_flag {
                let range_table_coset_fft = self
                    .quot_domain
                    .coset_fft(pk.plookup_pk.as_ref().unwrap().range_table_poly.coeffs()); // safe unwrap
                let key_table_coset_fft = self
                    .quot_domain
                    .coset_fft(pk.plookup_pk.as_ref().unwrap().key_table_poly.coeffs()); // safe unwrap
                let h_coset_ffts: Vec<Vec<E::Fr>> = oracles
                    .plookup_oracles
                    .h_polys
                    .par_iter()
                    .map(|poly| self.quot_domain.coset_fft(poly.coeffs()))
                    .collect();
                let prod_lookup_poly_coset_fft = self
                    .quot_domain
                    .coset_fft(oracles.plookup_oracles.prod_lookup_poly.coeffs());
                (
                    Some(range_table_coset_fft),
                    Some(key_table_coset_fft),
                    Some(h_coset_ffts),
                    Some(prod_lookup_poly_coset_fft),
                )
            } else {
                (None, None, None, None)
            };

            // fft_end();

            // Compute coset evaluations of the quotient polynomial.
            let quot_poly_coset_evals: Vec<E::Fr> = (0..m)
                .into_par_iter()
                .map(|i| {
                    let w: Vec<E::Fr> = (0..num_wire_types)
                        .map(|j| wire_polys_coset_fft[j][i])
                        .collect();
                    let w_next: Vec<E::Fr> = (0..num_wire_types)
                        .map(|j| wire_polys_coset_fft[j][(i + domain_size_ratio) % m])
                        .collect();

                    let t_circ = Self::compute_quotient_circuit_contribution(
                        i,
                        &w,
                        &pub_input_poly_coset_fft[i],
                        &selectors_coset_fft,
                    );
                    let (t_perm_1, t_perm_2) = Self::compute_quotient_copy_constraint_contribution(
                        i,
                        self.quot_domain.element(i) * E::Fr::multiplicative_generator(),
                        pk,
                        &w,
                        &prod_perm_poly_coset_fft[i],
                        &prod_perm_poly_coset_fft[(i + domain_size_ratio) % m],
                        challenges,
                        &sigmas_coset_fft,
                    );
                    let mut t1 = t_circ + t_perm_1;
                    let mut t2 = t_perm_2;

                    // add Plookup-related terms
                    if lookup_flag {
                        let (t_lookup_1, t_lookup_2) = self.compute_quotient_plookup_contribution(
                            i,
                            self.quot_domain.element(i) * E::Fr::multiplicative_generator(),
                            pk,
                            &w,
                            &w_next,
                            h_coset_ffts.as_ref().unwrap(),
                            prod_lookup_poly_coset_fft.as_ref().unwrap(),
                            range_table_coset_fft.as_ref().unwrap(),
                            key_table_coset_fft.as_ref().unwrap(),
                            selectors_coset_fft.last().unwrap(), // TODO: add a method to extract q_lookup_coset_fft
                            challenges,
                        );
                        t1 += t_lookup_1;
                        t2 += t_lookup_2;
                    }
                    t1 * z_h_inv[i % domain_size_ratio] + t2
                })
                .collect();
            for (a, b) in quot_poly_coset_evals_sum
                .iter_mut()
                .zip(quot_poly_coset_evals.iter())
            {
                *a += alpha_base * b;
            }
            // update the random combiner for aggregating multiple proving instances
            if lookup_flag {
                alpha_base *= alpha_7;
            } else {
                alpha_base *= alpha_3;
            }
        }
        // Compute the coefficient form of the quotient polynomial
        // fft_start();
        let res = DensePolynomial::from_coefficients_vec(
            self.quot_domain.coset_ifft(&quot_poly_coset_evals_sum),
        );
        fft_end();
        Ok(res)
    }

    // Compute the i-th coset evaluation of the circuit part of the quotient
    // polynomial.
    fn compute_quotient_circuit_contribution(
        i: usize,
        w: &[E::Fr],
        pi: &E::Fr,
        selectors_coset_fft: &[Vec<E::Fr>],
    ) -> E::Fr {
        // Selectors
        // The order: q_lc, q_mul, q_hash, q_o, q_c, q_ecc
        // TODO: (binyi) get the order from a function.
        let q_lc: Vec<E::Fr> = (0..GATE_WIDTH).map(|j| selectors_coset_fft[j][i]).collect();
        let q_mul: Vec<E::Fr> = (GATE_WIDTH..GATE_WIDTH + 2)
            .map(|j| selectors_coset_fft[j][i])
            .collect();
        let q_hash: Vec<E::Fr> = (GATE_WIDTH + 2..2 * GATE_WIDTH + 2)
            .map(|j| selectors_coset_fft[j][i])
            .collect();
        let q_o = selectors_coset_fft[2 * GATE_WIDTH + 2][i];
        let q_c = selectors_coset_fft[2 * GATE_WIDTH + 3][i];
        let q_ecc = selectors_coset_fft[2 * GATE_WIDTH + 4][i];

        q_c + pi
            + q_lc[0] * w[0]
            + q_lc[1] * w[1]
            + q_lc[2] * w[2]
            + q_lc[3] * w[3]
            + q_mul[0] * w[0] * w[1]
            + q_mul[1] * w[2] * w[3]
            + q_ecc * w[0] * w[1] * w[2] * w[3] * w[4]
            + q_hash[0] * w[0].pow(&[5])
            + q_hash[1] * w[1].pow(&[5])
            + q_hash[2] * w[2].pow(&[5])
            + q_hash[3] * w[3].pow(&[5])
            - q_o * w[4]
    }

    /// Compute the i-th coset evaluation of the copy constraint part of the
    /// quotient polynomial.
    /// `eval_point` - the evaluation point.
    /// `w` - the wire polynomial coset evaluations at `eval_point`.
    /// `z_x` - the permutation product polynomial evaluation at `eval_point`.
    /// `z_xw`-  the permutation product polynomial evaluation at `eval_point *
    /// g`, where `g` is the root of unity of the original domain.
    #[allow(clippy::too_many_arguments)]
    fn compute_quotient_copy_constraint_contribution(
        i: usize,
        eval_point: E::Fr,
        pk: &ProvingKey<E>,
        w: &[E::Fr],
        z_x: &E::Fr,
        z_xw: &E::Fr,
        challenges: &Challenges<E::Fr>,
        sigmas_coset_fft: &[Vec<E::Fr>],
    ) -> (E::Fr, E::Fr) {
        let num_wire_types = w.len();
        let n = pk.domain_size();

        // The check that:
        //   \prod_i [w_i(X) + beta * k_i * X + gamma] * z(X)
        // - \prod_i [w_i(X) + beta * sigma_i(X) + gamma] * z(wX) = 0
        // on the vanishing set.
        // Delay the division of Z_H(X).
        //
        // Extended permutation values
        let sigmas: Vec<E::Fr> = (0..num_wire_types)
            .map(|j| sigmas_coset_fft[j][i])
            .collect();

        // Compute the 1st term.
        let mut result_1 = challenges.alpha
            * w.iter().enumerate().fold(*z_x, |acc, (j, &w)| {
                acc * (w + pk.k()[j] * eval_point * challenges.beta + challenges.gamma)
            });
        // Minus the 2nd term.
        result_1 -= challenges.alpha
            * w.iter()
                .zip(sigmas.iter())
                .fold(*z_xw, |acc, (&w, &sigma)| {
                    acc * (w + sigma * challenges.beta + challenges.gamma)
                });

        // The check that z(x) = 1 at point 1.
        // (z(x)-1) * L1(x) * alpha^2 / Z_H(x) = (z(x)-1) * alpha^2 / (n * (x - 1))
        let result_2 = challenges.alpha.square() * (*z_x - E::Fr::one())
            / (E::Fr::from(n as u64) * (eval_point - E::Fr::one()));

        (result_1, result_2)
    }

    /// Compute the i-th coset evaluation of the lookup constraint part of the
    /// quotient polynomial.
    /// `eval_point`: the evaluation point.
    /// `pk`: proving key.
    /// `lookup_w`: (merged) lookup witness coset evaluations at `eval_point`.
    /// `h_coset_ffts`: coset evaluations for the sorted lookup vector
    /// polynomials. `prod_lookup_coset_fft`: coset evaluations for the
    /// Plookup product polynomial. `challenges`: Fiat-shamir challenges.
    ///
    /// The coset evaluations should be non-empty. The proving key should be
    /// guaranteed to support lookup.
    #[allow(clippy::too_many_arguments)]
    fn compute_quotient_plookup_contribution(
        &self,
        i: usize,
        eval_point: E::Fr,
        pk: &ProvingKey<E>,
        w: &[E::Fr],
        w_next: &[E::Fr],
        h_coset_ffts: &[Vec<E::Fr>],
        prod_lookup_coset_fft: &[E::Fr],
        range_table_coset_fft: &[E::Fr],
        key_table_coset_fft: &[E::Fr],
        q_lookup_coset_fft: &[E::Fr],
        challenges: &Challenges<E::Fr>,
    ) -> (E::Fr, E::Fr) {
        assert!(pk.plookup_pk.is_some());
        assert_eq!(h_coset_ffts.len(), 2);

        let n = pk.domain_size();
        let m = self.quot_domain.size();
        let domain_size_ratio = m / n;
        let n_field = E::Fr::from(n as u64);
        let lagrange_n_coeff =
            self.domain.group_gen_inv / (n_field * (eval_point - self.domain.group_gen_inv));
        let lagrange_1_coeff = E::Fr::one() / (n_field * (eval_point - E::Fr::one()));
        let mut alpha_power = challenges.alpha * challenges.alpha * challenges.alpha;

        // extract polynomial evaluations
        let h_1_x = h_coset_ffts[0][i];
        let h_1_xw = h_coset_ffts[0][(i + domain_size_ratio) % m];
        let h_2_x = h_coset_ffts[1][i];
        let h_2_xw = h_coset_ffts[1][(i + domain_size_ratio) % m];
        let p_x = prod_lookup_coset_fft[i];
        let p_xw = prod_lookup_coset_fft[(i + domain_size_ratio) % m];
        let range_table_x = range_table_coset_fft[i];
        let key_table_x = key_table_coset_fft[i];
        let range_table_xw = range_table_coset_fft[(i + domain_size_ratio) % m];
        let key_table_xw = key_table_coset_fft[(i + domain_size_ratio) % m];
        let merged_table_x = eval_merged_table::<E>(
            challenges.tau,
            range_table_x,
            key_table_x,
            q_lookup_coset_fft[i],
            w[3],
            w[4],
        );
        let merged_table_xw = eval_merged_table::<E>(
            challenges.tau,
            range_table_xw,
            key_table_xw,
            q_lookup_coset_fft[(i + domain_size_ratio) % m],
            w_next[3],
            w_next[4],
        );
        let merged_lookup_x = eval_merged_lookup_witness::<E>(
            challenges.tau,
            w[5],
            w[0],
            w[1],
            w[2],
            q_lookup_coset_fft[i],
        );

        // The check that h1(X) - h2(wX) = 0 at point w^{n-1}
        //
        // Fh(X)/Z_H(X) = (Ln(X) * (h1(X) - h2(wX))) / Z_H(X) = (h1(X) - h2(wX)) *
        // w^{n-1} / (n * (X - w^{n-1}))
        let term_h = (h_1_x - h_2_xw) * lagrange_n_coeff;
        let mut result_2 = alpha_power * term_h;
        alpha_power *= challenges.alpha;

        // The check that p(X) = 1 at point 1.
        //
        // Fp1(X)/Z_H(X) = (L1(X) * (p(X) - 1)) / Z_H(X) = (p(X) - 1) / (n * (X - 1))
        let term_p_1 = (p_x - E::Fr::one()) * lagrange_1_coeff;
        result_2 += alpha_power * term_p_1;
        alpha_power *= challenges.alpha;

        // The check that p(X) = 1 at point w^{n-1}.
        //
        // Fp2(X)/Z_H(X) = (Ln(X) * (p(X) - 1)) / Z_H(X) = (p(X) - 1) * w^{n-1} / (n *
        // (X - w^{n-1}))
        let term_p_2 = (p_x - E::Fr::one()) * lagrange_n_coeff;
        result_2 += alpha_power * term_p_2;
        alpha_power *= challenges.alpha;

        // The relation check between adjacent points on the vanishing set.
        // Delay the division of Z_H(X).
        //
        // Fp3(X) = (X - w^{n-1}) * p(X) * (1+beta) * (gamma + merged_lookup(X)) *
        // [gamma*(1+beta) + merged_table(X) + beta * merged_table(Xw)]
        //        - (X - w^{n-1}) * p(Xw) * [gamma(1+beta) + h_1(X) + beta * h_1(Xw)] *
        //          [gamma(1+beta) + h_2(X) + beta * h_2(Xw)]
        let beta_plus_one = E::Fr::one() + challenges.beta;
        let gamma_mul_beta_plus_one = beta_plus_one * challenges.gamma;
        let term_p_3 = (eval_point - self.domain.group_gen_inv)
            * (p_x
                * beta_plus_one
                * (challenges.gamma + merged_lookup_x)
                * (gamma_mul_beta_plus_one + merged_table_x + challenges.beta * merged_table_xw)
                - p_xw
                    * (gamma_mul_beta_plus_one + h_1_x + challenges.beta * h_1_xw)
                    * (gamma_mul_beta_plus_one + h_2_x + challenges.beta * h_2_xw));
        let result_1 = alpha_power * term_p_3;

        (result_1, result_2)
    }

    /// Split the quotient polynomial into `num_wire_types` polynomials.
    /// The first `num_wire_types`-1 polynomials have degree `domain_size`+1.
    fn split_quotient_polynomial(
        &self,
        quot_poly: &DensePolynomial<E::Fr>,
        num_wire_types: usize,
    ) -> Result<Vec<DensePolynomial<E::Fr>>, PlonkError> {
        let expected_degree = quotient_polynomial_degree(self.domain.size(), num_wire_types);
        if quot_poly.degree() != expected_degree {
            return Err(WrongQuotientPolyDegree(quot_poly.degree(), expected_degree).into());
        }
        let n = self.domain.size();
        let split_quot_polys = (0..num_wire_types)
            .into_par_iter()
            .map(|i| {
                let end = if i < num_wire_types - 1 {
                    (i + 1) * (n + 2)
                } else {
                    quot_poly.degree() + 1
                };
                // Degree-(n+1) polynomial has n + 2 coefficients.
                DensePolynomial::<E::Fr>::from_coefficients_slice(
                    &quot_poly.coeffs[i * (n + 2)..end],
                )
            })
            .collect();
        Ok(split_quot_polys)
    }

    // Compute the circuit part of the linearization polynomial
    fn compute_lin_poly_circuit_contribution(
        pk: &ProvingKey<E>,
        w_evals: &[E::Fr],
    ) -> DensePolynomial<E::Fr> {
        // The selectors order: q_lc, q_mul, q_hash, q_o, q_c, q_ecc
        // TODO: (binyi) get the order from a function.
        let q_lc = &pk.selectors[..GATE_WIDTH];
        let q_mul = &pk.selectors[GATE_WIDTH..GATE_WIDTH + 2];
        let q_hash = &pk.selectors[GATE_WIDTH + 2..2 * GATE_WIDTH + 2];
        let q_o = &pk.selectors[2 * GATE_WIDTH + 2];
        let q_c = &pk.selectors[2 * GATE_WIDTH + 3];
        let q_ecc = &pk.selectors[2 * GATE_WIDTH + 4];

        // TODO(binyi): add polynomials in parallel.
        // Note we don't need to compute the constant term of the polynomial.
        Self::mul_poly(&q_lc[0], &w_evals[0])
            + Self::mul_poly(&q_lc[1], &w_evals[1])
            + Self::mul_poly(&q_lc[2], &w_evals[2])
            + Self::mul_poly(&q_lc[3], &w_evals[3])
            + Self::mul_poly(&q_mul[0], &(w_evals[0] * w_evals[1]))
            + Self::mul_poly(&q_mul[1], &(w_evals[2] * w_evals[3]))
            + Self::mul_poly(&q_hash[0], &w_evals[0].pow(&[5]))
            + Self::mul_poly(&q_hash[1], &w_evals[1].pow(&[5]))
            + Self::mul_poly(&q_hash[2], &w_evals[2].pow(&[5]))
            + Self::mul_poly(&q_hash[3], &w_evals[3].pow(&[5]))
            + Self::mul_poly(
                q_ecc,
                &(w_evals[0] * w_evals[1] * w_evals[2] * w_evals[3] * w_evals[4]),
            )
            + Self::mul_poly(q_o, &(-w_evals[4]))
            + q_c.clone()
    }

    // Compute the wire permutation part of the linearization polynomial
    fn compute_lin_poly_copy_constraint_contribution(
        pk: &ProvingKey<E>,
        challenges: &Challenges<E::Fr>,
        poly_evals: &ProofEvaluations<E::Fr>,
        prod_perm_poly: &DensePolynomial<E::Fr>,
    ) -> DensePolynomial<E::Fr> {
        let dividend = challenges.zeta.pow(&[pk.domain_size() as u64]) - E::Fr::one();
        let divisor = E::Fr::from(pk.domain_size() as u32) * (challenges.zeta - E::Fr::one());
        let lagrange_1_eval = dividend / divisor;

        // Compute the coefficient of z(X)
        let coeff = poly_evals.wires_evals.iter().enumerate().fold(
            challenges.alpha,
            |acc, (j, &wire_eval)| {
                acc * (wire_eval
                    + challenges.beta * pk.vk.k[j] * challenges.zeta
                    + challenges.gamma)
            },
        ) + challenges.alpha.square() * lagrange_1_eval;
        let mut r_perm = Self::mul_poly(prod_perm_poly, &coeff);

        // Compute the coefficient of the last sigma wire permutation polynomial
        let num_wire_types = poly_evals.wires_evals.len();
        let coeff = -poly_evals
            .wires_evals
            .iter()
            .take(num_wire_types - 1)
            .zip(poly_evals.wire_sigma_evals.iter())
            .fold(
                challenges.alpha * challenges.beta * poly_evals.perm_next_eval,
                |acc, (&wire_eval, &sigma_eval)| {
                    acc * (wire_eval + challenges.beta * sigma_eval + challenges.gamma)
                },
            );
        r_perm = r_perm + Self::mul_poly(&pk.sigmas[num_wire_types - 1], &coeff);
        r_perm
    }

    // Compute the Plookup part of the linearization polynomial
    fn compute_lin_poly_plookup_contribution(
        &self,
        pk: &ProvingKey<E>,
        challenges: &Challenges<E::Fr>,
        w_evals: &[E::Fr],
        plookup_evals: &PlookupEvaluations<E::Fr>,
        oracles: &PlookupOracles<E::Fr>,
    ) -> DensePolynomial<E::Fr> {
        let alpha_2 = challenges.alpha.square();
        let alpha_4 = alpha_2.square();
        let alpha_5 = alpha_4 * challenges.alpha;
        let alpha_6 = alpha_4 * alpha_2;
        let n = pk.domain_size();
        let one = E::Fr::one();
        let vanish_eval = challenges.zeta.pow(&[n as u64]) - one;

        // compute lagrange_1 and lagrange_n
        let divisor = E::Fr::from(n as u32) * (challenges.zeta - one);
        let lagrange_1_eval = vanish_eval / divisor;
        let divisor = E::Fr::from(n as u32) * (challenges.zeta - self.domain.group_gen_inv);
        let lagrange_n_eval = vanish_eval * self.domain.group_gen_inv / divisor;

        // compute the coefficient for polynomial `prod_lookup_poly`
        let merged_table_eval = eval_merged_table::<E>(
            challenges.tau,
            plookup_evals.range_table_eval,
            plookup_evals.key_table_eval,
            plookup_evals.q_lookup_eval,
            w_evals[3],
            w_evals[4],
        );
        let merged_table_next_eval = eval_merged_table::<E>(
            challenges.tau,
            plookup_evals.range_table_next_eval,
            plookup_evals.key_table_next_eval,
            plookup_evals.q_lookup_next_eval,
            plookup_evals.w_3_next_eval,
            plookup_evals.w_4_next_eval,
        );
        let merged_lookup_eval = eval_merged_lookup_witness::<E>(
            challenges.tau,
            w_evals[5],
            w_evals[0],
            w_evals[1],
            w_evals[2],
            plookup_evals.q_lookup_eval,
        );

        let beta_plus_one = one + challenges.beta;
        let zeta_minus_g_inv = challenges.zeta - self.domain.group_gen_inv;
        let coeff = alpha_4 * lagrange_1_eval
            + alpha_5 * lagrange_n_eval
            + alpha_6
                * zeta_minus_g_inv
                * beta_plus_one
                * (challenges.gamma + merged_lookup_eval)
                * (challenges.gamma * beta_plus_one
                    + merged_table_eval
                    + challenges.beta * merged_table_next_eval);
        let mut r_lookup = Self::mul_poly(&oracles.prod_lookup_poly, &coeff);

        // compute the coefficient for polynomial `h_2_poly`
        let coeff = -alpha_6
            * zeta_minus_g_inv
            * plookup_evals.prod_next_eval
            * (challenges.gamma * beta_plus_one
                + plookup_evals.h_1_eval
                + challenges.beta * plookup_evals.h_1_next_eval);
        r_lookup = r_lookup + Self::mul_poly(&oracles.h_polys[1], &coeff);

        r_lookup
    }

    #[inline]
    fn mul_poly(poly: &DensePolynomial<E::Fr>, coeff: &E::Fr) -> DensePolynomial<E::Fr> {
        DensePolynomial::<E::Fr>::from_coefficients_vec(
            poly.coeffs.par_iter().map(|c| *coeff * c).collect(),
        )
    }
}

#[inline]
fn quotient_polynomial_degree(domain_size: usize, num_wire_types: usize) -> usize {
    num_wire_types * (domain_size + 1) + 2
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_377::Bls12_377;
    use ark_bls12_381::Bls12_381;
    use ark_bn254::Bn254;
    use ark_bw6_761::BW6_761;
    use ark_std::test_rng;

    #[test]
    fn test_split_quotient_polynomial_wrong_degree() -> Result<(), PlonkError> {
        test_split_quotient_polynomial_wrong_degree_helper::<Bn254>()?;
        test_split_quotient_polynomial_wrong_degree_helper::<Bls12_377>()?;
        test_split_quotient_polynomial_wrong_degree_helper::<Bls12_381>()?;
        test_split_quotient_polynomial_wrong_degree_helper::<BW6_761>()
    }

    fn test_split_quotient_polynomial_wrong_degree_helper<E: PairingEngine>(
    ) -> Result<(), PlonkError> {
        let prover = Prover::<E>::new(4, GATE_WIDTH + 1)?;
        let rng = &mut test_rng();
        let bad_quot_poly = DensePolynomial::<E::Fr>::rand(25, rng);
        assert!(prover
            .split_quotient_polynomial(&bad_quot_poly, GATE_WIDTH + 1)
            .is_err());
        Ok(())
    }
}
