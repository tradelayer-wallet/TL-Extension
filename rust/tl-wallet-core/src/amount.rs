//! Money is `u64` satoshis with checked arithmetic. Decimal coin strings are parsed exactly
//! (legacy code used `Math.round(amount * 1e8)` on floats).

use crate::error::{Error, Result};

pub const COIN: u64 = 100_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Sats(pub u64);

impl Sats {
    pub fn checked_add(self, other: Sats) -> Result<Sats> {
        self.0
            .checked_add(other.0)
            .map(Sats)
            .ok_or(Error::AmountOverflow)
    }

    pub fn checked_sub(self, other: Sats) -> Result<Sats> {
        self.0
            .checked_sub(other.0)
            .map(Sats)
            .ok_or(Error::AmountOverflow)
    }

    /// Sum with overflow detection.
    pub fn sum<I: IntoIterator<Item = Sats>>(it: I) -> Result<Sats> {
        it.into_iter().try_fold(Sats(0), Sats::checked_add)
    }

    /// Parse a plain decimal coin amount such as `"0.0001"` or `"12"`: digits, at most one
    /// `.`, at most 8 fractional digits, no sign, no exponent, no whitespace.
    pub fn from_coin_str(s: &str) -> Result<Sats> {
        let (int_part, frac_part) = match s.split_once('.') {
            Some((i, f)) => (i, f),
            None => (s, ""),
        };
        if int_part.is_empty() || !int_part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::InvalidAmount("integer part must be digits"));
        }
        if !frac_part.bytes().all(|b| b.is_ascii_digit())
            || (s.contains('.') && frac_part.is_empty())
        {
            return Err(Error::InvalidAmount("fractional part must be digits"));
        }
        if frac_part.len() > 8 {
            return Err(Error::InvalidAmount("more than 8 decimal places"));
        }
        let int_val: u64 = int_part
            .parse()
            .map_err(|_| Error::InvalidAmount("integer part out of range"))?;
        let mut frac = frac_part.to_string();
        while frac.len() < 8 {
            frac.push('0');
        }
        let frac_val: u64 = frac
            .parse()
            .map_err(|_| Error::InvalidAmount("fraction"))?;
        int_val
            .checked_mul(COIN)
            .and_then(|v| v.checked_add(frac_val))
            .map(Sats)
            .ok_or(Error::AmountOverflow)
    }

    /// Exact decimal rendering with 8 places.
    pub fn to_coin_string(self) -> String {
        format!("{}.{:08}", self.0 / COIN, self.0 % COIN)
    }
}
