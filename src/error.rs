use core::fmt::{Display, Formatter, Result};

/// Custom error type for operations happening with hash transcripts
#[derive(Debug, PartialEq)]
pub enum TranscriptError {
    /// Failed to read a transcript challenge
    FailedToReadChallenge,
    /// Failed to write a transcript challenge
    FailedToWriteChallenge,
}

impl Display for TranscriptError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            Self::FailedToReadChallenge => {
                write!(f, "failed to read a valid challenge from the transcript",)
            }
            Self::FailedToWriteChallenge => {
                write!(f, "failed to write a valid challenge to the transcript",)
            }
        }
    }
}
