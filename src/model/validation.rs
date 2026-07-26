/// A text field is outside its permitted character-count range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("text contains {actual} characters; expected between {min} and {max}")]
pub struct TextLengthError {
    /// Actual character count.
    pub actual: usize,
    /// Minimum permitted character count.
    pub min: usize,
    /// Maximum permitted character count.
    pub max: usize,
}

pub(crate) fn validate_char_count(
    value: &str,
    min: usize,
    max: usize,
) -> Result<(), TextLengthError> {
    let actual = value.chars().count();
    if (min..=max).contains(&actual) {
        Ok(())
    } else {
        Err(TextLengthError { actual, min, max })
    }
}

/// A credits amount is below its permitted minimum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("amount is {actual} credits; minimum is {minimum} credits")]
pub struct AmountTooLowError {
    /// Actual amount, in credits.
    pub actual: u64,
    /// Minimum permitted amount, in credits.
    pub minimum: u64,
}

pub(crate) fn validate_min_amount(value: u64, minimum: u64) -> Result<(), AmountTooLowError> {
    if value >= minimum {
        Ok(())
    } else {
        Err(AmountTooLowError {
            actual: value,
            minimum,
        })
    }
}
