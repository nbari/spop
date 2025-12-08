use crate::types::TypedData;

/// <https://github.com/haproxy/haproxy/blob/master/doc/SPOE.txt#L1053>
///
/// ```text
/// 3.4. Actions
/// -------------
///
/// An agent must acknowledge each NOTIFY frame by sending the corresponding ACK
/// frame. Actions can be added in these frames to dynamically take action on the
/// processing of a stream.
///
/// Here is the list of supported actions:
///
///   * set-var    set the value for an existing variable. 3 arguments must be
///                attached to this action: the variable scope (proc, sess, txn,
///                req or res), the variable name (a string) and its value.
///
///     ACTION-SET-VAR  : <SET-VAR:1 byte><NB-ARGS:1 byte><VAR-SCOPE:1 byte><VAR-NAME><VAR-VALUE>
///
///     SET-VAR     : <1>
///     NB-ARGS     : <3>
///     VAR-SCOPE   : <PROCESS> | <SESSION> | <TRANSACTION> | <REQUEST> | <RESPONSE>
///     VAR-NAME    : <STRING>
///     VAR-VALUE   : <TYPED-DATA>
///
///     PROCESS     : <0>
///     SESSION     : <1>
///     TRANSACTION : <2>
///     REQUEST     : <3>
///     RESPONSE    : <4>
///
///   * unset-var    unset the value for an existing variable. 2 arguments must be
///                  attached to this action: the variable scope (proc, sess, txn,
///                  req or res) and the variable name (a string).
///
///     ACTION-UNSET-VAR  : <UNSET-VAR:1 byte><NB-ARGS:1 byte><VAR-SCOPE:1 byte><VAR-NAME>
///
///     UNSET-VAR   : <2>
///     NB-ARGS     : <2>
///     VAR-SCOPE   : <PROCESS> | <SESSION> | <TRANSACTION> | <REQUEST> | <RESPONSE>
///     VAR-NAME    : <STRING>
///
///     PROCESS     : <0>
///     SESSION     : <1>
///     TRANSACTION : <2>
///     REQUEST     : <3>
///     RESPONSE    : <4>
///
///
/// NOTE: Name of the variables will be automatically prefixed by HAProxy to avoid
///       name clashes with other variables used in HAProxy. Moreover, unknown
///       variable will be silently ignored.
/// ```
#[derive(Debug, Clone)]
pub enum Action {
    SetVar {
        scope: VarScope,
        name: String,
        value: TypedData,
    },
    UnSetVar {
        scope: VarScope,
        name: String,
    },
}

/// ```text
/// VAR-SCOPE: <PROCESS> | <SESSION> | <TRANSACTION> | <REQUEST> | <RESPONSE>
/// ```
#[derive(Debug, Clone)]
pub enum VarScope {
    Process = 0,
    Session = 1,
    Transaction = 2,
    Request = 3,
    Response = 4,
}

impl VarScope {
    /// Converts `FrameType` to its corresponding u8 value
    #[must_use]
    pub const fn to_u8(&self) -> u8 {
        match self {
            Self::Process => 0,
            Self::Session => 1,
            Self::Transaction => 2,
            Self::Request => 3,
            Self::Response => 4,
        }
    }
}
