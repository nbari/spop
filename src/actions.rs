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
    /// Set a variable whose name and any string or binary payload have static storage.
    SetVarStatic {
        scope: VarScope,
        name: &'static str,
        value: crate::TypedDataRef<'static>,
    },
    UnSetVar {
        scope: VarScope,
        name: String,
    },
}

impl Action {
    pub(crate) fn encode_into(&self, buf: &mut Vec<u8>) {
        let mut header = |kind, args, scope: VarScope, name: &str| {
            buf.extend_from_slice(&[kind, args, scope.to_u8()]);
            crate::encode_varint_into(name.len() as u64, buf);
            buf.extend_from_slice(name.as_bytes());
        };
        match self {
            Self::SetVar { scope, name, value } => {
                header(1, 3, *scope, name);
                value.to_bytes(buf);
            }
            Self::SetVarStatic { scope, name, value } => {
                header(1, 3, *scope, name);
                value.to_bytes(buf);
            }
            Self::UnSetVar { scope, name } => header(2, 2, *scope, name),
        }
    }

    pub(crate) fn serialized_len(&self) -> usize {
        let (name, value_len) = match self {
            Self::SetVar { name, value, .. } => (name.as_str(), value.serialized_len()),
            Self::SetVarStatic { name, value, .. } => (*name, value.serialized_len()),
            Self::UnSetVar { name, .. } => (name.as_str(), 0),
        };
        3 + crate::varint_len(name.len() as u64) + name.len() + value_len
    }
}

/// ```text
/// VAR-SCOPE: <PROCESS> | <SESSION> | <TRANSACTION> | <REQUEST> | <RESPONSE>
/// ```
#[derive(Debug, Clone, Copy)]
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
