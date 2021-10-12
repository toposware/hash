use super::error::TranscriptError;
use stark_curve::FieldElement;

// TODO: To support different kind of fields, we'd need them to
// implement some Field Trait which we can refer to here.

/// Trait for interacting with an IOP
pub trait Transcript {
    /// Read challenge from the transcript
    fn read_challenge() -> Result<FieldElement, TranscriptError>;
    /// Write challenge to the transcript
    fn write_challenge() -> Result<FieldElement, TranscriptError>;
}
