/// Errors which can occur during serialization methods.
#[derive(Debug, PartialEq)]
pub enum SerializationError {
    /// The bytes do not represent a valid field element.
    InvalidFieldElement,
}
