// modified_from := https://github.com/mir-protocol/plonky2-ecdsa/blob/main/src/curve/curve_types.rs
use core::fmt::Debug;
use core::hash::{Hash, Hasher};
use core::ops::Neg;

use plonky2::field::ops::Square;
use plonky2::field::types::{Field, PrimeField};
use serde::{Deserialize, Serialize};

// To avoid implementation conflicts from associated types,
// see https://github.com/rust-lang/rust/issues/20400
pub struct CurveScalar<C: Curve>(pub <C as Curve>::ScalarField);

/// A Twisted Edwards Curve.
pub trait Curve: 'static + Sync + Sized + Copy + Debug + Default {
    type BaseField: PrimeField;
    type ScalarField: PrimeField;

    // A * x^2 + y^2 = 1 + D * x^2* y^2
    const A: Self::BaseField;
    const D: Self::BaseField;

    const GENERATOR_AFFINE: AffinePoint<Self>;

    const GENERATOR_PROJECTIVE: ProjectivePoint<Self> = ProjectivePoint {
        x: Self::GENERATOR_AFFINE.x,
        y: Self::GENERATOR_AFFINE.y,
        z: Self::BaseField::ONE,
    };

    fn convert(x: Self::ScalarField) -> CurveScalar<Self> {
        CurveScalar(x)
    }

    fn is_safe_curve() -> bool {
        (Self::A - Self::D).is_nonzero()
    }
}

/// A point on a short Weierstrass curve, represented in affine coordinates.
#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct AffinePoint<C: Curve> {
    pub x: C::BaseField,
    pub y: C::BaseField,
    pub zero: bool,
}

impl<C: Curve> AffinePoint<C> {
    pub const ZERO: Self = Self {
        x: C::BaseField::ZERO,
        y: C::BaseField::ZERO,
        zero: true,
    };

    pub fn nonzero(x: C::BaseField, y: C::BaseField) -> Self {
        let point = Self { x, y, zero: false };
        debug_assert!(point.is_valid());
        point
    }

    pub fn is_valid(&self) -> bool {
        let Self { x, y, zero } = *self;
        zero || C::A * x.square() + y.square() == C::BaseField::ONE + C::D * x.square() * y.square()
    }

    pub fn to_projective(&self) -> ProjectivePoint<C> {
        let Self { x, y, zero } = *self;
        let z = if zero {
            C::BaseField::ZERO
        } else {
            C::BaseField::ONE
        };

        ProjectivePoint { x, y, z }
    }

    pub fn batch_to_projective(affine_points: &[Self]) -> Vec<ProjectivePoint<C>> {
        affine_points.iter().map(Self::to_projective).collect()
    }

    // Pg 38, https://bibliotecadigital.ipb.pt/bitstream/10198/24067/1/Nakai_Eduardo.pdf
    #[must_use]
    pub fn double(&self) -> Self {
        let AffinePoint { x, y, zero } = *self;

        if zero {
            return AffinePoint::ZERO;
        }

        let x_sq = x * x;
        let y_sq = y * y;
        let x_y = x * y;
        let two_x_y = x_y.double();
        let d_x_sq_y_sq = C::D * x_sq * y_sq;
        let a_x_sq = C::A * x_sq;

        let x3 = two_x_y / (C::BaseField::ONE + d_x_sq_y_sq);
        let y3 = (y_sq - a_x_sq) / (C::BaseField::TWO - a_x_sq - y_sq);

        Self {
            x: x3,
            y: y3,
            zero: false,
        }
    }
}

impl<C: Curve> PartialEq for AffinePoint<C> {
    fn eq(&self, other: &Self) -> bool {
        let AffinePoint {
            x: x1,
            y: y1,
            zero: zero1,
        } = *self;
        let AffinePoint {
            x: x2,
            y: y2,
            zero: zero2,
        } = *other;
        if zero1 || zero2 {
            return zero1 == zero2;
        }
        x1 == x2 && y1 == y2
    }
}

impl<C: Curve> Eq for AffinePoint<C> {}

impl<C: Curve> Hash for AffinePoint<C> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        if self.zero {
            self.zero.hash(state);
        } else {
            self.x.hash(state);
            self.y.hash(state);
        }
    }
}

/// A point on a short Weierstrass curve, represented in projective coordinates.
#[derive(Copy, Clone, Debug)]
pub struct ProjectivePoint<C: Curve> {
    pub x: C::BaseField,
    pub y: C::BaseField,
    pub z: C::BaseField,
}

impl<C: Curve> ProjectivePoint<C> {
    pub const ZERO: Self = Self {
        x: C::BaseField::ZERO,
        y: C::BaseField::ONE,
        z: C::BaseField::ZERO,
    };

    pub fn nonzero(x: C::BaseField, y: C::BaseField, z: C::BaseField) -> Self {
        let point = Self { x, y, z };
        debug_assert!(point.is_valid());
        point
    }

    pub fn is_valid(&self) -> bool {
        let Self { x, y, z } = *self;
        z.is_zero() || C::A * x.square() * z.square() + y.square() * z.square()
                            == z.square().square() + C::D * x.square() * y.square()
    }

    pub fn to_affine(&self) -> AffinePoint<C> {
        let Self { x, y, z } = *self;
        if z == C::BaseField::ZERO {
            AffinePoint::ZERO
        } else {
            let z_inv = z.inverse();
            AffinePoint::nonzero(x * z_inv, y * z_inv)
        }
    }

    pub fn batch_to_affine(proj_points: &[Self]) -> Vec<AffinePoint<C>> {
        let n = proj_points.len();
        let zs: Vec<C::BaseField> = proj_points.iter().map(|pp| pp.z).collect();
        let z_invs = C::BaseField::batch_multiplicative_inverse(&zs);

        let mut result = Vec::with_capacity(n);
        for i in 0..n {
            let Self { x, y, z } = proj_points[i];
            result.push(if z == C::BaseField::ZERO {
                AffinePoint::ZERO
            } else {
                let z_inv = z_invs[i];
                AffinePoint::nonzero(x * z_inv, y * z_inv)
            });
        }
        result
    }


    #[must_use]
    pub fn double(&self) -> Self {
        let Self { x, y, z } = *self;
        if z == C::BaseField::ZERO {
            return ProjectivePoint::ZERO;
        }

        // "dbl-20080-bbjlp" https://www.hyperelliptic.org/EFD/g1p/auto-twisted-projective.html
        // B = (X1+Y1)^2
        // C = X1^2
        // D = Y1^2
        // E = a*C
        // F = E+D
        // H = Z1^2
        // J = F-2*H
        // X3 = (B-C-D)*J
        // Y3 = F*(E-D)
        // Z3 = F*J
        let b = (x + y).square();
        let c = x.square();
        let d = y.square();
        let e = C::A * c;
        let f = e + d;
        let h = z.square();
        let j = f - C::BaseField::TWO * h;
        let x3 = (b-c-d) * j;
        let y3 = f * (e-d);
        let z3 = f * j;

        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    pub fn add_slices(a: &[Self], b: &[Self]) -> Vec<Self> {
        assert_eq!(a.len(), b.len());
        a.iter()
            .zip(b.iter())
            .map(|(&a_i, &b_i)| a_i + b_i)
            .collect()
    }

    #[must_use]
    pub fn neg(&self) -> Self {
        Self {
            x: -self.x,
            y: self.y,
            z: self.z,
        }
    }
}

impl<C: Curve> PartialEq for ProjectivePoint<C> {
    fn eq(&self, other: &Self) -> bool {
        let ProjectivePoint {
            x: x1,
            y: y1,
            z: z1,
        } = *self;
        let ProjectivePoint {
            x: x2,
            y: y2,
            z: z2,
        } = *other;
        if z1 == C::BaseField::ZERO || z2 == C::BaseField::ZERO {
            return z1 == z2;
        }

        // We want to compare (x1/z1, y1/z1) == (x2/z2, y2/z2).
        // But to avoid field division, it is better to compare (x1*z2, y1*z2) == (x2*z1, y2*z1).
        x1 * z2 == x2 * z1 && y1 * z2 == y2 * z1
    }
}

impl<C: Curve> Eq for ProjectivePoint<C> {}

impl<C: Curve> Neg for AffinePoint<C> {
    type Output = AffinePoint<C>;

    fn neg(self) -> Self::Output {
        let AffinePoint { x, y, zero } = self;
        AffinePoint { x: -x, y, zero }
    }
}

impl<C: Curve> Neg for ProjectivePoint<C> {
    type Output = ProjectivePoint<C>;

    fn neg(self) -> Self::Output {
        let ProjectivePoint { x, y, z } = self;
        ProjectivePoint { x: -x, y, z }
    }
}

pub fn base_to_scalar<C: Curve>(x: C::BaseField) -> C::ScalarField {
    C::ScalarField::from_noncanonical_biguint(x.to_canonical_biguint())
}

pub fn scalar_to_base<C: Curve>(x: C::ScalarField) -> C::BaseField {
    C::BaseField::from_noncanonical_biguint(x.to_canonical_biguint())
}
