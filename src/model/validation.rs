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

/// RTL/LTR override and isolate control characters — can reorder or hide
/// surrounding text without changing its underlying bytes.
fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

/// Zero-width joiner/non-joiner/space and the zero-width no-break
/// space/BOM — none has a legitimate use in a short display string, and
/// each can be used to visually misrepresent text without changing its
/// underlying bytes.
fn is_zero_width(character: char) -> bool {
    matches!(character, '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{feff}')
}

/// Strip characters that can visually misrepresent text without changing
/// its underlying bytes: C0/C1 control codes, bidi-override/isolate
/// characters, and zero-width joiners/spaces/BOM. Safe to apply to any text
/// before it's rendered or (re-)encrypted. Never truncates length — callers
/// that need a length cap apply their own `.take()` afterward.
pub fn strip_unsafe_display_characters(text: &str) -> String {
    text.chars()
        .filter(|character| {
            !character.is_control() && !is_bidi_control(*character) && !is_zero_width(*character)
        })
        .collect()
}

#[cfg(test)]
mod display_sanitizer_tests {
    use super::strip_unsafe_display_characters;

    #[test]
    fn leaves_ordinary_text_unchanged() {
        assert_eq!(
            strip_unsafe_display_characters("hello world"),
            "hello world"
        );
    }

    #[test]
    fn strips_bidi_override_characters() {
        let input = "10\u{202e}HSAD 0000\u{202c} DASH";
        let stripped = strip_unsafe_display_characters(input);
        assert!(!stripped.contains('\u{202e}'));
        assert!(!stripped.contains('\u{202c}'));
        assert_eq!(stripped, "10HSAD 0000 DASH");
    }

    #[test]
    fn strips_zero_width_characters() {
        let input = "he\u{200b}llo\u{200d}world\u{feff}";
        assert_eq!(strip_unsafe_display_characters(input), "helloworld");
    }

    #[test]
    fn strips_control_characters() {
        let input = "hello\u{0007}world\u{001b}";
        assert_eq!(strip_unsafe_display_characters(input), "helloworld");
    }

    #[test]
    fn preserves_ordinary_unicode() {
        assert_eq!(
            strip_unsafe_display_characters("héllo 日本語"),
            "héllo 日本語"
        );
    }
}
