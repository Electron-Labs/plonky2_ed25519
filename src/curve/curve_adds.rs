// modified_from := https://github.com/mir-protocol/plonky2-ecdsa/blob/main/src/curve/curve_adds.rs
use core::ops::Add;

use plonky2::field::ops::Square;
use plonky2::field::types::Field;

use crate::curve::curve_types::{AffinePoint, Curve, ProjectivePoint};

impl<C: Curve> Add<ProjectivePoint<C>> for ProjectivePoint<C> {
    type Output = ProjectivePoint<C>;

    fn add(self, rhs: ProjectivePoint<C>) -> Self::Output {
        let ProjectivePoint {
            x: x1,
            y: y1,
            z: z1,
        } = self;
        let ProjectivePoint {
            x: x2,
            y: y2,
            z: z2,
        } = rhs;

        // Check for point doubling or adding inverses.
        if z1 == C::BaseField::ZERO {
            return rhs;
        }
        if z2 == C::BaseField::ZERO {
            return self;
        }

        let x1z2 = x1 * z2;
        let y1z2 = y1 * z2;
        let x2z1 = x2 * z1;
        let y2z1 = y2 * z1;

        if x1z2 == x2z1 {
            if y1z2 == y2z1 {
                return self.double();
            }
            if y1z2 == -y2z1 {
                return ProjectivePoint::ZERO;
            }
        }

        // General point addition formulae
        let common_z = z1 * z2;
        let square_z = common_z.square();
        let prod_x = x1 * x2;
        let prod_y = y1 * y2;
        let twist = C::D * (prod_x * prod_y);

        let f = square_z - twist;
        let g = square_z + twist;
        let x3 = common_z * f * ((x1 + y1) * (x2 + y2) - prod_x - prod_y);
        let y3 = common_z * g * (prod_y - C::A * prod_x);
        let z3 = f * g;

        ProjectivePoint::nonzero(x3, y3, z3)
    }
}

// adds Affine point to Projective point
impl<C: Curve> Add<AffinePoint<C>> for ProjectivePoint<C> {
    type Output = ProjectivePoint<C>;

    fn add(self, rhs: AffinePoint<C>) -> Self::Output {
        let ProjectivePoint {
            x: x1,
            y: y1,
            z: z1,
        } = self;
        let AffinePoint {
            x: x2,
            y: y2,
            zero: zero2,
        } = rhs;

        if z1 == C::BaseField::ZERO {
            return rhs.to_projective();
        }
        if zero2 {
            return self;
        }

        let x2z1 = x2 * z1;
        let y2z1 = y2 * z1;

        // Check if we're doubling or adding inverses.
        if x1 == x2z1 {
            if y1 == y2z1 {
                // TODO: inline to avoid redundant muls.
                return self.double();
            }
            if y1 == -y2z1 {
                return ProjectivePoint::ZERO;
            }
        }

        let rhs_projective = rhs.to_projective();
        self + rhs_projective
    }
}

impl<C: Curve> Add<AffinePoint<C>> for AffinePoint<C> {
    type Output = ProjectivePoint<C>;
    // why would the output be affine not projective point here

    fn add(self, rhs: AffinePoint<C>) -> Self::Output {
        return self.to_projective()+rhs.to_projective();
    }
}
