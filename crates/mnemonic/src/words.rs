use once_cell::sync::Lazy;
use rust_embed::RustEmbed;
use std::{
    borrow::Cow,
    io::{Error, ErrorKind, Result},
};

static WORDS_2048: Lazy<Vec<String>> = Lazy::new(|| read_words().unwrap());

#[derive(RustEmbed)]
#[folder = "resources/words"]
struct Words;

fn read_words() -> Result<Vec<String>> {
    Words::get("english.txt")
        .ok_or_else(|| Error::from(ErrorKind::NotFound))
        .and_then(|file| {
            let bytes = match file.data {
                Cow::Borrowed(bs) => bs.into(),
                Cow::Owned(bs) => bs,
            };
            std::str::from_utf8(bytes.as_ref())
                .map(|ss| ss.lines().map(|s| s.to_string()).collect())
                .map_err(|err| Error::new(ErrorKind::InvalidInput, err))
        })
}

pub fn convert_to_nums(mnemonic: &[&str]) -> Result<Vec<u16>> {
    mnemonic
        .iter()
        .map(|w| {
            WORDS_2048
                .iter()
                .position(|s| s.eq_ignore_ascii_case(w))
                .map(|i| i as u16)
                .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "Unknown word"))
        })
        .collect()
}

pub fn get_word(index: usize) -> Result<&'static str> {
    WORDS_2048
        .get(index)
        .map(|s| s.as_str())
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "Out of index"))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn word_length() {
        assert_eq!(WORDS_2048.len(), 2048);
    }

    #[test]
    fn check_word_indeces() {
        let expected_indeces = vec![0u16, 3, 108, 2047];
        let samples: Vec<_> = expected_indeces
            .iter()
            .map(|&i| WORDS_2048[i as usize].as_str())
            .collect();
        let actual_indexes = convert_to_nums(&samples).unwrap();
        assert_eq!(expected_indeces, actual_indexes);
    }

    #[test]
    fn check_word_indeces_ignorecase() {
        let expected_indeces = vec![0u16, 23, 1085, 2047];
        let originals: Vec<_> = expected_indeces
            .iter()
            .map(|&i| WORDS_2048[i as usize].to_uppercase())
            .collect();
        let samples: Vec<_> = originals.iter().map(|s| s.as_str()).collect();
        let actual_indexes = convert_to_nums(&samples).unwrap();
        assert_eq!(expected_indeces, actual_indexes);
    }
}
