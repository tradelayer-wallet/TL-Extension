//! Coin selection and fee/change accounting: boundaries and a deterministic property sweep.
mod common;
use common::*;
use tl_wallet_core::coin::*;
use tl_wallet_core::*;

fn mk(values: &[u64]) -> Vec<Utxo> {
    static SCRIPT: std::sync::OnceLock<bitcoin::ScriptBuf> = std::sync::OnceLock::new();
    let script = SCRIPT
        .get_or_init(|| {
            account(Network::LtcTest)
                .receive_address()
                .script_pubkey()
                .to_owned()
        })
        .clone();
    values
        .iter()
        .enumerate()
        .map(|(i, v)| plain_utxo(i as u8 + 1, 0, *v, script.clone()))
        .collect()
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo + 1)
    }
}

#[test]
fn largest_first_prefix_and_conservation_sweep() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let dust = Sats(5_460);
    let mut oks = 0;
    let mut insufficient = 0;
    let mut over_bound = 0;
    for _ in 0..3_000 {
        let n = rng.range(0, 8) as usize;
        let values: Vec<u64> = (0..n).map(|_| rng.range(1, 2_000_000)).collect();
        let utxos = mk(&values);
        let target = Sats(rng.range(1, 3_000_000));
        let fee = Sats(rng.range(0, 30_000));
        let max_fee = Sats(rng.range(0, 24_000).max(fee.0));
        let res = select_largest_first(&utxos, target, &FeePolicy::Fixed(fee), max_fee, dust);
        let total_all: u64 = values.iter().sum();
        match res {
            Ok(sel) => {
                oks += 1;
                // value conservation
                assert_eq!(sel.total_in.0, target.0 + sel.change.0 + sel.fee.0);
                assert_eq!(
                    sel.total_in.0,
                    sel.selected.iter().map(|u| u.value.0).sum::<u64>()
                );
                // bounds
                assert!(sel.fee <= max_fee);
                assert!(sel.fee >= fee);
                assert!(sel.change.0 == 0 || sel.change >= dust);
                // selected is a prefix of the descending order and minimal
                let mut sorted = values.clone();
                sorted.sort_unstable_by(|a, b| b.cmp(a));
                let got: Vec<u64> = sel.selected.iter().map(|u| u.value.0).collect();
                assert_eq!(got, sorted[..got.len()].to_vec());
                if got.len() > 1 {
                    let without_last: u64 = got[..got.len() - 1].iter().sum();
                    assert!(without_last < target.0 + fee.0, "not minimal");
                }
            }
            Err(Error::InsufficientFunds { needed, available }) => {
                insufficient += 1;
                assert_eq!(available, total_all);
                assert_eq!(needed, target.0 + fee.0);
                assert!(total_all < needed);
            }
            Err(Error::FeeAboveBound { fee: f, bound }) => {
                over_bound += 1;
                assert!(f > bound);
                assert_eq!(bound, max_fee.0);
            }
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    assert!(
        oks > 100 && insufficient > 100 && over_bound > 0,
        "{oks} {insufficient} {over_bound}"
    );
}

#[test]
fn boundaries() {
    let d = Sats(5_460);
    let f = FeePolicy::Fixed(Sats(10_000));
    let mf = Sats(100_000);
    // exact amount + fee, no change
    let s = select_largest_first(&mk(&[40_000]), Sats(30_000), &f, mf, d).unwrap();
    assert_eq!((s.change, s.fee), (Sats(0), Sats(10_000)));
    // one satoshi short
    assert_eq!(
        select_largest_first(&mk(&[39_999]), Sats(30_000), &f, mf, d).unwrap_err(),
        Error::InsufficientFunds {
            needed: 40_000,
            available: 39_999
        }
    );
    // empty set
    assert_eq!(
        select_largest_first(&[], Sats(1), &f, mf, d).unwrap_err(),
        Error::InsufficientFunds {
            needed: 10_001,
            available: 0
        }
    );
    // zero target
    assert!(select_largest_first(&mk(&[10]), Sats(0), &f, mf, d).is_err());
    // dust boundary
    let s = select_largest_first(&mk(&[45_460]), Sats(30_000), &f, mf, d).unwrap();
    assert_eq!((s.change, s.fee), (Sats(5_460), Sats(10_000)));
    let s = select_largest_first(&mk(&[45_459]), Sats(30_000), &f, mf, d).unwrap();
    assert_eq!((s.change, s.fee), (Sats(0), Sats(15_459)));
    // duplicate outpoints
    let mut dup = mk(&[50_000, 50_000]);
    dup[1].txid = dup[0].txid;
    assert_eq!(
        select_largest_first(&dup, Sats(1_000), &f, mf, d).unwrap_err(),
        Error::InvalidInput("duplicate outpoint")
    );
    // candidate list bound
    let many = mk(&[1; 10]);
    let mut big = Vec::new();
    for _ in 0..(MAX_UTXOS / 10 + 1) {
        big.extend(many.clone());
    }
    assert_eq!(
        select_largest_first(&big, Sats(1), &f, mf, d).unwrap_err(),
        Error::InvalidInput("too many candidate inputs")
    );
}

#[test]
fn overflow_is_an_error_not_a_wrap() {
    let d = Sats(5_460);
    let f = FeePolicy::Fixed(Sats(10_000));
    let huge = mk(&[u64::MAX, 1]);
    assert_eq!(
        select_largest_first(&huge, Sats(u64::MAX), &f, Sats(u64::MAX), d).unwrap_err(),
        Error::AmountOverflow
    );
    // target + fee overflow
    assert_eq!(
        select_largest_first(&mk(&[1]), Sats(u64::MAX), &f, Sats(u64::MAX), d).unwrap_err(),
        Error::AmountOverflow
    );
    // sum of inputs overflow
    let two = mk(&[u64::MAX - 5, 10]);
    assert_eq!(
        select_largest_first(
            &two,
            Sats(u64::MAX - 3),
            &FeePolicy::Fixed(Sats(0)),
            Sats(u64::MAX),
            d
        )
        .unwrap_err(),
        Error::AmountOverflow
    );
    // fee policy arithmetic overflow
    let p = FeePolicy::PerVbyte {
        sats_per_vb: u64::MAX,
        fixed_vbytes: 10,
        input_vbytes: 68,
    };
    assert_eq!(p.fee_for_inputs(2), Err(Error::AmountOverflow));
}

#[test]
fn per_vbyte_policy_adds_inputs_until_covered() {
    let d = Sats(546);
    let p = FeePolicy::PerVbyte {
        sats_per_vb: 2,
        fixed_vbytes: 100,
        input_vbytes: 68,
    };
    assert_eq!(p.fee_for_inputs(1), Ok(Sats(2 * 168)));
    assert_eq!(p.fee_for_inputs(3), Ok(Sats(2 * 304)));
    // 1 input: need 10_000 + 336; 2 inputs: need 10_000 + 472
    let s = select_largest_first(&mk(&[6_000, 5_000]), Sats(10_000), &p, Sats(10_000), d).unwrap();
    assert_eq!(s.selected.len(), 2);
    assert_eq!(s.fee, Sats(472 + (11_000 - 10_000 - 472)));
    assert_eq!(s.change, Sats(0)); // 528 left over is below dust (546): folded into the fee
    assert_eq!(s.total_in.0, 10_000 + s.fee.0);
}

#[test]
fn ties_are_broken_deterministically() {
    let d = Sats(5_460);
    let f = FeePolicy::Fixed(Sats(0));
    let a = mk(&[10_000, 10_000, 10_000]);
    let mut rev = a.clone();
    rev.reverse();
    let s1 = select_largest_first(&a, Sats(15_000), &f, Sats(1_000_000), d).unwrap();
    let s2 = select_largest_first(&rev, Sats(15_000), &f, Sats(1_000_000), d).unwrap();
    assert_eq!(s1.selected, s2.selected);
}

/// Concrete vectors shared with `lean/TlWalletCore/Coin.lean` (`example : select ... = ...`).
#[test]
fn lean_model_vectors() {
    let d = Sats(5_460);
    let f = FeePolicy::Fixed(Sats(10_000));
    let s =
        select_largest_first(&mk(&[50_000, 60_000]), Sats(80_000), &f, Sats(10_000), d).unwrap();
    let got: Vec<u64> = s.selected.iter().map(|u| u.value.0).collect();
    assert_eq!(got, vec![60_000, 50_000]);
    assert_eq!(
        (s.total_in, s.change, s.fee),
        (Sats(110_000), Sats(20_000), Sats(10_000))
    );
    let s = select_largest_first(&mk(&[40_000]), Sats(30_000), &f, Sats(100_000), d).unwrap();
    assert_eq!(
        (s.total_in, s.change, s.fee),
        (Sats(40_000), Sats(0), Sats(10_000))
    );
    assert_eq!(
        select_largest_first(&mk(&[39_999]), Sats(30_000), &f, Sats(100_000), d).unwrap_err(),
        Error::InsufficientFunds {
            needed: 40_000,
            available: 39_999
        }
    );
    let s = select_largest_first(&mk(&[45_460]), Sats(30_000), &f, Sats(100_000), d).unwrap();
    assert_eq!((s.change, s.fee), (Sats(5_460), Sats(10_000)));
    let s = select_largest_first(&mk(&[45_459]), Sats(30_000), &f, Sats(100_000), d).unwrap();
    assert_eq!((s.change, s.fee), (Sats(0), Sats(15_459)));
    assert_eq!(
        select_largest_first(&mk(&[45_459]), Sats(30_000), &f, Sats(12_000), d).unwrap_err(),
        Error::FeeAboveBound {
            fee: 15_459,
            bound: 12_000
        }
    );
}
