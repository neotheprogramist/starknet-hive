const DEFAULT_ASSERTION_ERROR: &str = "Assertion failed";
/// Evaluates a boolean condition and returns a Result instead of panicking.
///
/// # Arguments
/// * `condition` - The boolean expression to evaluate.
/// * `message` (optional) - Custom error message for failure case.
///
/// # Returns
/// * `Ok(())` if the condition is true.
/// * `Err(AssertionNoPanicError)` if the condition is false or if evaluation causes a panic.
///
/// # Examples
/// ```
/// let result = assert_result!(1 + 1 == 2);
/// assert!(result.is_ok());
///
/// let result = assert_result!(1 + 1 == 3, "Math is broken");
/// assert!(result.is_err());
/// ```
#[macro_export]
macro_rules! assert_result {
    ($cond:expr) => {{
        if let Ok(result) = std::panic::catch_unwind(|| $cond) {
            if result {
                Ok(())
            } else {
                Err(
                    $crate::macros::errors::AssertionNoPanicError::AssertionNoPanicFailed(
                        crate::macros::assert_no_panic::DEFAULT_ASSERTION_ERROR.to_string(),
                    ),
                )
            }
        } else {
            Err(
                $crate::macros::errors::AssertionNoPanicError::AssertionNoPanicFailed(
                    "Expression evaluation panicked".to_string(),
                ),
            )
        }
    }};
    ($cond:expr, $msg:expr) => {{
        if let Ok(result) = std::panic::catch_unwind(|| $cond) {
            if result {
                Ok(())
            } else {
                Err(
                    $crate::macros::errors::AssertionNoPanicError::AssertionNoPanicFailed(
                        $msg.to_string(),
                    ),
                )
            }
        } else {
            Err(
                $crate::macros::errors::AssertionNoPanicError::AssertionNoPanicFailed(
                    "Expression evaluation panicked".to_string(),
                ),
            )
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::DEFAULT_ASSERTION_ERROR;
    use crate::macros::errors::AssertionNoPanicError;

    #[test]
    fn test_assert_result_success() {
        let result = assert_result!(1 + 1 == 2);
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
    }

    #[test]
    fn test_assert_result_failure_default_message() {
        let result = assert_result!(1 + 1 == 3);
        assert!(
            matches!(result, Err(AssertionNoPanicError::AssertionNoPanicFailed(ref msg)) if msg == "Assertion failed"),
            "Expected AssertionNoPanicFailed with default message, got {:?}",
            result
        );
    }

    #[test]
    fn test_assert_result_failure_custom_message() {
        let custom_message = "Custom error message";
        let result = assert_result!(1 + 1 == 3, custom_message);
        assert!(
            matches!(result, Err(AssertionNoPanicError::AssertionNoPanicFailed(ref msg)) if msg == custom_message),
            "Expected AssertionNoPanicFailed with custom message, got {:?}",
            result
        );
    }

    #[test]
    fn test_assert_no_panic_with_complex_condition() {
        let vec = vec![1, 2, 3];
        let result = assert_result!(vec.iter().sum::<i32>() == 6);
        assert!(result.is_ok());
    }

    #[test]
    fn test_assert_no_panic_handles_panic() {
        let result = assert_result!(vec![1, 2, 3][5] == 1);
        assert!(matches!(
            result,
            Err(AssertionNoPanicError::AssertionNoPanicFailed(ref msg))
                if msg == "Expression evaluation panicked"
        ));
    }

    #[test]
    fn test_assert_no_panic_failure_default_message() {
        let result = assert_result!(1 + 1 == 3);
        assert!(
            matches!(result, Err(AssertionNoPanicError::AssertionNoPanicFailed(ref msg)) if msg == DEFAULT_ASSERTION_ERROR),
            "Expected AssertionNoPanicFailed with default message, got {:?}",
            result
        );
    }
}