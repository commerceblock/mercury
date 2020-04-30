#[cfg(test)]
mod tests {

    use curv::elliptic::curves::traits::{ECPoint, ECScalar};
    use curv::{FE, GE};

    #[test]
    fn math() {
        let g: GE = ECPoint::generator();

        //owner1 share
        let o1_s: FE = ECScalar::new_random();

        // SE share
        let s1_s: FE = ECScalar::new_random();
        let s1_p: GE = g * s1_s;

        // deposit P
        let p_p = s1_p*o1_s;
        println!("P1: {:?}",p_p);


        // transfer
        // SE new random key x1
        let x1_s: FE = ECScalar::new_random();

        // owner2 share
        let o2_s: FE = ECScalar::new_random();
        let o2_p: GE = g * o2_s;

        // t1 = o1*x1*o2_inv
        let t1 = o1_s*x1_s*(o2_s.invert());

        // t2 = t1*x1_inv*s1
        let s2_s = t1*(x1_s.invert())*s1_s;

        println!("P2: {:?}",o2_p*s2_s);
    }
}
