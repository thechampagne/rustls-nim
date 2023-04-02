# Copyright 2023 XXIV
#
# Licensed under the Apache License, Version 2.0 (the "License"),
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
type
  rustls_result* = enum
    RUSTLS_RESULT_OK = 7000, RUSTLS_RESULT_IO = 7001,
    RUSTLS_RESULT_NULL_PARAMETER = 7002,
    RUSTLS_RESULT_INVALID_DNS_NAME_ERROR = 7003, RUSTLS_RESULT_PANIC = 7004,
    RUSTLS_RESULT_CERTIFICATE_PARSE_ERROR = 7005,
    RUSTLS_RESULT_PRIVATE_KEY_PARSE_ERROR = 7006,
    RUSTLS_RESULT_INSUFFICIENT_SIZE = 7007, RUSTLS_RESULT_NOT_FOUND = 7008,
    RUSTLS_RESULT_INVALID_PARAMETER = 7009, RUSTLS_RESULT_UNEXPECTED_EOF = 7010,
    RUSTLS_RESULT_PLAINTEXT_EMPTY = 7011, RUSTLS_RESULT_ACCEPTOR_NOT_READY = 7012,
    RUSTLS_RESULT_ALREADY_USED = 7013,
    RUSTLS_RESULT_NO_CERTIFICATES_PRESENTED = 7101,
    RUSTLS_RESULT_DECRYPT_ERROR = 7102,
    RUSTLS_RESULT_FAILED_TO_GET_CURRENT_TIME = 7103,
    RUSTLS_RESULT_HANDSHAKE_NOT_COMPLETE = 7104,
    RUSTLS_RESULT_PEER_SENT_OVERSIZED_RECORD = 7105,
    RUSTLS_RESULT_NO_APPLICATION_PROTOCOL = 7106,
    RUSTLS_RESULT_PEER_INCOMPATIBLE_ERROR = 7107,
    RUSTLS_RESULT_PEER_MISBEHAVED_ERROR = 7108,
    RUSTLS_RESULT_INAPPROPRIATE_MESSAGE = 7109,
    RUSTLS_RESULT_INAPPROPRIATE_HANDSHAKE_MESSAGE = 7110,
    RUSTLS_RESULT_GENERAL = 7112, RUSTLS_RESULT_FAILED_TO_GET_RANDOM_BYTES = 7113,
    RUSTLS_RESULT_BAD_MAX_FRAGMENT_SIZE = 7114,
    RUSTLS_RESULT_UNSUPPORTED_NAME_TYPE = 7115, RUSTLS_RESULT_ENCRYPT_ERROR = 7116,
    RUSTLS_RESULT_CERT_ENCODING_BAD = 7121, RUSTLS_RESULT_CERT_EXPIRED = 7122,
    RUSTLS_RESULT_CERT_NOT_YET_VALID = 7123, RUSTLS_RESULT_CERT_REVOKED = 7124,
    RUSTLS_RESULT_CERT_UNHANDLED_CRITICAL_EXTENSION = 7125,
    RUSTLS_RESULT_CERT_UNKNOWN_ISSUER = 7126,
    RUSTLS_RESULT_CERT_BAD_SIGNATURE = 7127,
    RUSTLS_RESULT_CERT_NOT_VALID_FOR_NAME = 7128,
    RUSTLS_RESULT_CERT_INVALID_PURPOSE = 7129,
    RUSTLS_RESULT_CERT_APPLICATION_VERIFICATION_FAILURE = 7130,
    RUSTLS_RESULT_CERT_OTHER_ERROR = 7131,
    RUSTLS_RESULT_MESSAGE_HANDSHAKE_PAYLOAD_TOO_LARGE = 7133,
    RUSTLS_RESULT_MESSAGE_INVALID_CCS = 7134,
    RUSTLS_RESULT_MESSAGE_INVALID_CONTENT_TYPE = 7135,
    RUSTLS_RESULT_MESSAGE_INVALID_CERT_STATUS_TYPE = 7136,
    RUSTLS_RESULT_MESSAGE_INVALID_CERT_REQUEST = 7137,
    RUSTLS_RESULT_MESSAGE_INVALID_DH_PARAMS = 7138,
    RUSTLS_RESULT_MESSAGE_INVALID_EMPTY_PAYLOAD = 7139,
    RUSTLS_RESULT_MESSAGE_INVALID_KEY_UPDATE = 7140,
    RUSTLS_RESULT_MESSAGE_INVALID_SERVER_NAME = 7141,
    RUSTLS_RESULT_MESSAGE_TOO_LARGE = 7142, RUSTLS_RESULT_MESSAGE_TOO_SHORT = 7143,
    RUSTLS_RESULT_MESSAGE_MISSING_DATA = 7144,
    RUSTLS_RESULT_MESSAGE_MISSING_KEY_EXCHANGE = 7145,
    RUSTLS_RESULT_MESSAGE_NO_SIGNATURE_SCHEMES = 7146,
    RUSTLS_RESULT_MESSAGE_TRAILING_DATA = 7147,
    RUSTLS_RESULT_MESSAGE_UNEXPECTED_MESSAGE = 7148,
    RUSTLS_RESULT_MESSAGE_UNKNOWN_PROTOCOL_VERSION = 7149,
    RUSTLS_RESULT_MESSAGE_UNSUPPORTED_COMPRESSION = 7150,
    RUSTLS_RESULT_MESSAGE_UNSUPPORTED_CURVE_TYPE = 7151,
    RUSTLS_RESULT_MESSAGE_UNSUPPORTED_KEY_EXCHANGE_ALGORITHM = 7152,
    RUSTLS_RESULT_MESSAGE_INVALID_OTHER = 7153,
    RUSTLS_RESULT_ALERT_CLOSE_NOTIFY = 7200,
    RUSTLS_RESULT_ALERT_UNEXPECTED_MESSAGE = 7201,
    RUSTLS_RESULT_ALERT_BAD_RECORD_MAC = 7202,
    RUSTLS_RESULT_ALERT_DECRYPTION_FAILED = 7203,
    RUSTLS_RESULT_ALERT_RECORD_OVERFLOW = 7204,
    RUSTLS_RESULT_ALERT_DECOMPRESSION_FAILURE = 7205,
    RUSTLS_RESULT_ALERT_HANDSHAKE_FAILURE = 7206,
    RUSTLS_RESULT_ALERT_NO_CERTIFICATE = 7207,
    RUSTLS_RESULT_ALERT_BAD_CERTIFICATE = 7208,
    RUSTLS_RESULT_ALERT_UNSUPPORTED_CERTIFICATE = 7209,
    RUSTLS_RESULT_ALERT_CERTIFICATE_REVOKED = 7210,
    RUSTLS_RESULT_ALERT_CERTIFICATE_EXPIRED = 7211,
    RUSTLS_RESULT_ALERT_CERTIFICATE_UNKNOWN = 7212,
    RUSTLS_RESULT_ALERT_ILLEGAL_PARAMETER = 7213,
    RUSTLS_RESULT_ALERT_UNKNOWN_CA = 7214,
    RUSTLS_RESULT_ALERT_ACCESS_DENIED = 7215,
    RUSTLS_RESULT_ALERT_DECODE_ERROR = 7216,
    RUSTLS_RESULT_ALERT_DECRYPT_ERROR = 7217,
    RUSTLS_RESULT_ALERT_EXPORT_RESTRICTION = 7218,
    RUSTLS_RESULT_ALERT_PROTOCOL_VERSION = 7219,
    RUSTLS_RESULT_ALERT_INSUFFICIENT_SECURITY = 7220,
    RUSTLS_RESULT_ALERT_INTERNAL_ERROR = 7221,
    RUSTLS_RESULT_ALERT_INAPPROPRIATE_FALLBACK = 7222,
    RUSTLS_RESULT_ALERT_USER_CANCELED = 7223,
    RUSTLS_RESULT_ALERT_NO_RENEGOTIATION = 7224,
    RUSTLS_RESULT_ALERT_MISSING_EXTENSION = 7225,
    RUSTLS_RESULT_ALERT_UNSUPPORTED_EXTENSION = 7226,
    RUSTLS_RESULT_ALERT_CERTIFICATE_UNOBTAINABLE = 7227,
    RUSTLS_RESULT_ALERT_UNRECOGNISED_NAME = 7228,
    RUSTLS_RESULT_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE = 7229,
    RUSTLS_RESULT_ALERT_BAD_CERTIFICATE_HASH_VALUE = 7230,
    RUSTLS_RESULT_ALERT_UNKNOWN_PSK_IDENTITY = 7231,
    RUSTLS_RESULT_ALERT_CERTIFICATE_REQUIRED = 7232,
    RUSTLS_RESULT_ALERT_NO_APPLICATION_PROTOCOL = 7233,
    RUSTLS_RESULT_ALERT_UNKNOWN = 7234, RUSTLS_RESULT_CERT_SCT_MALFORMED = 7319,
    RUSTLS_RESULT_CERT_SCT_INVALID_SIGNATURE = 7320,
    RUSTLS_RESULT_CERT_SCT_TIMESTAMP_IN_FUTURE = 7321,
    RUSTLS_RESULT_CERT_SCT_UNSUPPORTED_VERSION = 7322,
    RUSTLS_RESULT_CERT_SCT_UNKNOWN_LOG = 7323


type
  ##  Definitions of known TLS protocol versions.
  rustls_tls_version* = enum
    RUSTLS_TLS_VERSION_SSLV2 = 512, RUSTLS_TLS_VERSION_SSLV3 = 768,
    RUSTLS_TLS_VERSION_TLSV1_0 = 769, RUSTLS_TLS_VERSION_TLSV1_1 = 770,
    RUSTLS_TLS_VERSION_TLSV1_2 = 771, RUSTLS_TLS_VERSION_TLSV1_3 = 772
  ##  A parsed ClientHello produced by a rustls_acceptor. It is used to check
  ##  server name indication (SNI), ALPN protocols, signature schemes, and
  ##  cipher suites. It can be combined with a rustls_server_config to build a
  ##  rustls_connection.
  rustls_accepted* {.bycopy.} = object
  ##  A buffer and parser for ClientHello bytes. This allows reading ClientHello
  ##  before choosing a rustls_server_config. It's useful when the server
  ##  config will be based on parameters in the ClientHello: server name
  ##  indication (SNI), ALPN protocols, signature schemes, and cipher suites. In
  ##  particular, if a server wants to do some potentially expensive work to load a
  ##  certificate for a given hostname, rustls_acceptor allows doing that asynchronously,
  ##  as opposed to rustls_server_config_builder_set_hello_callback(), which doesn't
  ##  work well for asynchronous I/O.
  ##
  ##  The general flow is:
  ##   - rustls_acceptor_new()
  ##   - Loop:
  ##     - Read bytes from the network it with rustls_acceptor_read_tls().
  ##     - If successful, parse those bytes with rustls_acceptor_accept().
  ##     - If that returns RUSTLS_RESULT_ACCEPTOR_NOT_READY, continue.
  ##     - Otherwise, break.
  ##   - If rustls_acceptor_accept() returned RUSTLS_RESULT_OK:
  ##     - Examine the resulting rustls_accepted.
  ##     - Create or select a rustls_server_config.
  ##     - Call rustls_accepted_into_connection().
  ##   - Otherwise, there was a problem with the ClientHello data and the
  ##     connection should be rejected.
  rustls_acceptor* {.bycopy.} = object
  ##  An X.509 certificate, as used in rustls.
  ##  Corresponds to `Certificate` in the Rust API.
  ##  <https://docs.rs/rustls/latest/rustls/struct.Certificate.html>
  rustls_certificate* {.bycopy.} = object
  ##  The complete chain of certificates to send during a TLS handshake,
  ##  plus a private key that matches the end-entity (leaf) certificate.
  ##  Corresponds to `CertifiedKey` in the Rust API.
  ##  <https://docs.rs/rustls/latest/rustls/sign/struct.CertifiedKey.html>
  rustls_certified_key* {.bycopy.} = object
  ##  A verifier of client certificates that requires all certificates to be
  ##  trusted based on a given `rustls_root_cert_store`. Usable in building server
  ##  configurations. Connections without such a client certificate will not
  ##  be accepted.
  rustls_client_cert_verifier* {.bycopy.} = object
  ##  Alternative to `rustls_client_cert_verifier` that allows connections
  ##  with or without a client certificate. If the client offers a certificate,
  ##  it will be verified (and rejected if it is not valid). If the client
  ##  does not offer a certificate, the connection will succeed.
  ##
  ##  The application can retrieve the certificate, if any, with
  ##  rustls_connection_get_peer_certificate.
  rustls_client_cert_verifier_optional* {.bycopy.} = object
  ##  A client config that is done being constructed and is now read-only.
  ##  Under the hood, this object corresponds to an `Arc<ClientConfig>`.
  ##  <https://docs.rs/rustls/latest/rustls/struct.ClientConfig.html>
  rustls_client_config* {.bycopy.} = object
  ##  A client config being constructed. A builder can be modified by,
  ##  e.g. rustls_client_config_builder_load_roots_from_file. Once you're
  ##  done configuring settings, call rustls_client_config_builder_build
  ##  to turn it into a *rustls_client_config. This object is not safe
  ##  for concurrent mutation. Under the hood, it corresponds to a
  ##  `Box<ClientConfig>`.
  ##  <https://docs.rs/rustls/latest/rustls/struct.ConfigBuilder.html>
  rustls_client_config_builder* {.bycopy.} = object
  rustls_connection* {.bycopy.} = object
  ##  An alias for `struct iovec` from uio.h (on Unix) or `WSABUF` on Windows. You should cast
  ##  `const struct rustls_iovec *` to `const struct iovec *` on Unix, or `const *LPWSABUF`
  ##  on Windows. See [`std::io::IoSlice`] for details on interoperability with platform
  ##  specific vectored IO.
  rustls_iovec* {.bycopy.} = object
  ##  A root certificate store.
  ##  <https://docs.rs/rustls/latest/rustls/struct.RootCertStore.html>
  rustls_root_cert_store* {.bycopy.} = object
  ##  A server config that is done being constructed and is now read-only.
  ##  Under the hood, this object corresponds to an `Arc<ServerConfig>`.
  ##  <https://docs.rs/rustls/latest/rustls/struct.ServerConfig.html>
  rustls_server_config* {.bycopy.} = object
  ##  A server config being constructed. A builder can be modified by,
  ##  e.g. rustls_server_config_builder_load_native_roots. Once you're
  ##  done configuring settings, call rustls_server_config_builder_build
  ##  to turn it into a *const rustls_server_config. This object is not safe
  ##  for concurrent mutation.
  ##  <https://docs.rs/rustls/latest/rustls/struct.ConfigBuilder.html>
  rustls_server_config_builder* {.bycopy.} = object
  ##  A read-only view of a slice of Rust byte slices.
  ##
  ##  This is used to pass data from rustls-ffi to callback functions provided
  ##  by the user of the API. Because Vec and slice are not `#[repr(C)]`, we
  ##  provide access via a pointer to an opaque struct and an accessor method
  ##  that acts on that struct to get entries of type `rustls_slice_bytes`.
  ##  Internally, the pointee is a `&[&[u8]]`.
  ##
  ##  The memory exposed is available as specified by the function
  ##  using this in its signature. For instance, when this is a parameter to a
  ##  callback, the lifetime will usually be the duration of the callback.
  ##  Functions that receive one of these must not call its methods beyond the
  ##  allowed lifetime.
  rustls_slice_slice_bytes* {.bycopy.} = object
  ##  A read-only view of a slice of multiple Rust `&str`'s (that is, multiple
  ##  strings). Like `rustls_str`, this guarantees that each string contains
  ##  UTF-8 and no NUL bytes. Strings are not NUL-terminated.
  ##
  ##  This is used to pass data from rustls-ffi to callback functions provided
  ##  by the user of the API. Because Vec and slice are not `#[repr(C)]`, we
  ##  can't provide a straightforward `data` and `len` structure. Instead, we
  ##  provide access via a pointer to an opaque struct and accessor methods.
  ##  Internally, the pointee is a `&[&str]`.
  ##
  ##  The memory exposed is available as specified by the function
  ##  using this in its signature. For instance, when this is a parameter to a
  ##  callback, the lifetime will usually be the duration of the callback.
  ##  Functions that receive one of these must not call its methods beyond the
  ##  allowed lifetime.
  rustls_slice_str* {.bycopy.} = object
  ##  A cipher suite supported by rustls.
  rustls_supported_ciphersuite* {.bycopy.} = object
  ##  A read-only view on a Rust `&str`. The contents are guaranteed to be valid
  ##  UTF-8. As an additional guarantee on top of Rust's normal UTF-8 guarantee,
  ##  a `rustls_str` is guaranteed not to contain internal NUL bytes, so it is
  ##  safe to interpolate into a C string or compare using strncmp. Keep in mind
  ##  that it is not NUL-terminated.
  ##
  ##  The memory exposed is available as specified by the function
  ##  using this in its signature. For instance, when this is a parameter to a
  ##  callback, the lifetime will usually be the duration of the callback.
  ##  Functions that receive one of these must not dereference the data pointer
  ##  beyond the allowed lifetime.
  rustls_str* {.bycopy.} = object
    data*: cstring
    len*: csize_t
  ##  A return value for a function that may return either success (0) or a
  ##  non-zero value representing an error. The values should match socket
  ##  error numbers for your operating system - for example, the integers for
  ##  ETIMEDOUT, EAGAIN, or similar.
  rustls_io_result* = cint
  ##  A callback for rustls_connection_read_tls.
  ##  An implementation of this callback should attempt to read up to n bytes from the
  ##  network, storing them in `buf`. If any bytes were stored, the implementation should
  ##  set out_n to the number of bytes stored and return 0. If there was an error,
  ##  the implementation should return a nonzero rustls_io_result, which will be
  ##  passed through to the caller. On POSIX systems, returning `errno` is convenient.
  ##  On other systems, any appropriate error code works.
  ##  It's best to make one read attempt to the network per call. Additional reads will
  ##  be triggered by subsequent calls to one of the `_read_tls` methods.
  ##  `userdata` is set to the value provided to `rustls_connection_set_userdata`. In most
  ##  cases that should be a struct that contains, at a minimum, a file descriptor.
  ##  The buf and out_n pointers are borrowed and should not be retained across calls.
  rustls_read_callback* = proc (userdata: pointer, buf: ptr uint8, n: csize_t,
                             out_n: ptr csize_t): rustls_io_result {.cdecl.}
  ##  A read-only view on a Rust byte slice.
  ##
  ##  This is used to pass data from rustls-ffi to callback functions provided
  ##  by the user of the API.
  ##  `len` indicates the number of bytes than can be safely read.
  ##
  ##  The memory exposed is available as specified by the function
  ##  using this in its signature. For instance, when this is a parameter to a
  ##  callback, the lifetime will usually be the duration of the callback.
  ##  Functions that receive one of these must not dereference the data pointer
  ##  beyond the allowed lifetime.
  rustls_slice_bytes* {.bycopy.} = object
    data*: ptr uint8
    len*: csize_t
  ##  User-provided input to a custom certificate verifier callback. See
  ##  rustls_client_config_builder_dangerous_set_certificate_verifier().
  rustls_verify_server_cert_user_data* = pointer
  ##  Input to a custom certificate verifier callback. See
  ##  rustls_client_config_builder_dangerous_set_certificate_verifier().
  ##
  ##  server_name can contain a hostname, an IPv4 address in textual form, or an
  ##  IPv6 address in textual form.
  rustls_verify_server_cert_params* {.bycopy.} = object
    end_entity_cert_der*: rustls_slice_bytes
    intermediate_certs_der*: ptr rustls_slice_slice_bytes
    server_name*: rustls_str
    ocsp_response*: rustls_slice_bytes
  rustls_verify_server_cert_callback* = proc (
      userdata: rustls_verify_server_cert_user_data,
      params: ptr rustls_verify_server_cert_params): uint32 {.cdecl.}
  rustls_log_level* = csize_t
  rustls_log_params* {.bycopy.} = object
    level*: rustls_log_level
    message*: rustls_str

  rustls_log_callback* = proc (userdata: pointer, params: ptr rustls_log_params) {.cdecl.}
  ##  A callback for rustls_connection_write_tls.
  ##  An implementation of this callback should attempt to write the `n` bytes in buf
  ##  to the network. If any bytes were written, the implementation should
  ##  set out_n to the number of bytes stored and return 0. If there was an error,
  ##  the implementation should return a nonzero rustls_io_result, which will be
  ##  passed through to the caller. On POSIX systems, returning `errno` is convenient.
  ##  On other systems, any appropriate error code works.
  ##  It's best to make one write attempt to the network per call. Additional writes will
  ##  be triggered by subsequent calls to rustls_connection_write_tls.
  ##  `userdata` is set to the value provided to `rustls_connection_set_userdata`. In most
  ##  cases that should be a struct that contains, at a minimum, a file descriptor.
  ##  The buf and out_n pointers are borrowed and should not be retained across calls.
  rustls_write_callback* = proc (userdata: pointer, buf: ptr uint8, n: csize_t,
                              out_n: ptr csize_t): rustls_io_result {.cdecl.}
  ##  A callback for rustls_connection_write_tls_vectored.
  ##  An implementation of this callback should attempt to write the bytes in
  ##  the given `count` iovecs to the network. If any bytes were written,
  ##  the implementation should set out_n to the number of bytes written and return 0.
  ##  If there was an error, the implementation should return a nonzero rustls_io_result,
  ##  which will be passed through to the caller. On POSIX systems, returning `errno` is convenient.
  ##  On other systems, any appropriate error code works.
  ##  It's best to make one write attempt to the network per call. Additional write will
  ##  be triggered by subsequent calls to one of the `_write_tls` methods.
  ##  `userdata` is set to the value provided to `rustls_*_session_set_userdata`. In most
  ##  cases that should be a struct that contains, at a minimum, a file descriptor.
  ##  The buf and out_n pointers are borrowed and should not be retained across calls.
  rustls_write_vectored_callback* = proc (userdata: pointer, iov: ptr rustls_iovec,
                                       count: csize_t, out_n: ptr csize_t): rustls_io_result {.cdecl.}
  ##  Any context information the callback will receive when invoked.
  rustls_client_hello_userdata* = pointer
  ##  A read-only view on a Rust slice of 16-bit integers in platform endianness.
  ##
  ##  This is used to pass data from rustls-ffi to callback functions provided
  ##  by the user of the API.
  ##  `len` indicates the number of bytes than can be safely read.
  ##
  ##  The memory exposed is available as specified by the function
  ##  using this in its signature. For instance, when this is a parameter to a
  ##  callback, the lifetime will usually be the duration of the callback.
  ##  Functions that receive one of these must not dereference the data pointer
  ##  beyond the allowed lifetime.
  rustls_slice_u16* {.bycopy.} = object
    data*: ptr uint16
    len*: csize_t
  ##  The TLS Client Hello information provided to a ClientHelloCallback function.
  ##  `server_name` is the value of the ServerNameIndication extension provided
  ##  by the client. If the client did not send an SNI, the length of this
  ##  `rustls_string` will be 0. The signature_schemes field carries the values
  ##  supplied by the client or, if the client did not send this TLS extension,
  ##  the default schemes in the rustls library. See:
  ##
  ## <https://docs.rs/rustls/latest/rustls/internal/msgs/enums/enum.SignatureScheme.html>.
  ##  `alpn` carries the list of ALPN protocol names that the client proposed to
  ##  the server. Again, the length of this list will be 0 if none were supplied.
  ##
  ##  All this data, when passed to a callback function, is only accessible during
  ##  the call and may not be modified. Users of this API must copy any values that
  ##  they want to access when the callback returned.
  ##
  ##  EXPERIMENTAL: this feature of rustls-ffi is likely to change in the future, as
  ##  the rustls library is re-evaluating their current approach to client hello handling.
  rustls_client_hello* {.bycopy.} = object
    server_name*: rustls_str
    signature_schemes*: rustls_slice_u16
    alpn*: ptr rustls_slice_slice_bytes
  ##  Prototype of a callback that can be installed by the application at the
  ##  `rustls_server_config`. This callback will be invoked by a `rustls_connection`
  ##  once the TLS client hello message has been received.
  ##  `userdata` will be set based on rustls_connection_set_userdata.
  ##  `hello` gives the value of the available client announcements, as interpreted
  ##  by rustls. See the definition of `rustls_client_hello` for details.
  ##
  ##  NOTE:
  ##  - the passed in `hello` and all its values are only available during the
  ##    callback invocations.
  ##  - the passed callback function must be safe to call multiple times concurrently
  ##    with the same userdata, unless there is only a single config and connection
  ##    where it is installed.
  ##
  ##  EXPERIMENTAL: this feature of rustls-ffi is likely to change in the future, as
  ##  the rustls library is re-evaluating their current approach to client hello handling.
  rustls_client_hello_callback* = proc (userdata: rustls_client_hello_userdata,
                                     hello: ptr rustls_client_hello): ptr rustls_certified_key {.cdecl.}
  ##  Any context information the callback will receive when invoked.
  rustls_session_store_userdata* = pointer
  ##  Prototype of a callback that can be installed by the application at the
  ##  `rustls_server_config` or `rustls_client_config`. This callback will be
  ##  invoked by a TLS session when looking up the data for a TLS session id.
  ##  `userdata` will be supplied based on rustls_{client,server}_session_set_userdata.
  ##
  ##  The `buf` points to `count` consecutive bytes where the
  ##  callback is expected to copy the result to. The number of copied bytes
  ##  needs to be written to `out_n`. The callback should not read any
  ##  data from `buf`.
  ##
  ##  If the value to copy is larger than `count`, the callback should never
  ##  do a partial copy but instead remove the value from its store and
  ##  act as if it was never found.
  ##
  ##  The callback should return RUSTLS_RESULT_OK to indicate that a value was
  ##  retrieved and written in its entirety into `buf`, or RUSTLS_RESULT_NOT_FOUND
  ##  if no session was retrieved.
  ##
  ##  When `remove_after` is != 0, the returned data needs to be removed
  ##  from the store.
  ##
  ##  NOTE: the passed in `key` and `buf` are only available during the
  ##  callback invocation.
  ##  NOTE: callbacks used in several sessions via a common config
  ##  must be implemented thread-safe.
  rustls_session_store_get_callback* = proc (
      userdata: rustls_session_store_userdata, key: ptr rustls_slice_bytes,
      remove_after: cint, buf: ptr uint8, count: csize_t, out_n: ptr csize_t): uint32 {.cdecl.}
  ##  Prototype of a callback that can be installed by the application at the
  ##  `rustls_server_config` or `rustls_client_config`. This callback will be
  ##  invoked by a TLS session when a TLS session has been created and an id
  ##  for later use is handed to the client/has been received from the server.
  ##  `userdata` will be supplied based on rustls_{client,server}_session_set_userdata.
  ##
  ##  The callback should return RUSTLS_RESULT_OK to indicate that a value was
  ##  successfully stored, or RUSTLS_RESULT_IO on failure.
  ##
  ##  NOTE: the passed in `key` and `val` are only available during the
  ##  callback invocation.
  ##  NOTE: callbacks used in several sessions via a common config
  ##  must be implemented thread-safe.
  rustls_session_store_put_callback* = proc (
      userdata: rustls_session_store_userdata, key: ptr rustls_slice_bytes,
      val: ptr rustls_slice_bytes): uint32 {.cdecl.}

let RUSTLS_ALL_CIPHER_SUITES* {.importc.}: array[9, ptr rustls_supported_ciphersuite]

let RUSTLS_ALL_CIPHER_SUITES_LEN* {.importc.}: csize_t

let RUSTLS_DEFAULT_CIPHER_SUITES* {.importc.}: array[9, ptr rustls_supported_ciphersuite]

let RUSTLS_DEFAULT_CIPHER_SUITES_LEN* {.importc.}: csize_t

let RUSTLS_ALL_VERSIONS* {.importc.}: array[2, uint16]

let RUSTLS_ALL_VERSIONS_LEN* {.importc.}: csize_t

let RUSTLS_DEFAULT_VERSIONS* {.importc.}: array[2, uint16]

let RUSTLS_DEFAULT_VERSIONS_LEN* {.importc.}: csize_t

##
##  Returns a static string containing the rustls-ffi version as well as the
##  rustls version. The string is alive for the lifetime of the program and does
##  not need to be freed.
##

proc rustls_version*(): rustls_str {.importc.}
##
##  Create and return a new rustls_acceptor.
##
##  Caller owns the pointed-to memory and must eventually free it with
##  `rustls_acceptor_free()`.
##

proc rustls_acceptor_new*(): ptr rustls_acceptor {.importc.}
##
##  Free a rustls_acceptor.
##
##  Parameters:
##
##  acceptor: The rustls_acceptor to free.
##
##  Calling with NULL is fine. Must not be called twice with the same value.
##

proc rustls_acceptor_free*(acceptor: ptr rustls_acceptor) {.importc.}
##
##  Read some TLS bytes from the network into internal buffers. The actual network
##  I/O is performed by `callback`, which you provide. Rustls will invoke your
##  callback with a suitable buffer to store the read bytes into. You don't have
##  to fill it up, just fill with as many bytes as you get in one syscall.
##
##  Parameters:
##
##  acceptor: The rustls_acceptor to read bytes into.
##  callback: A function that will perform the actual network I/O.
##    Must be valid to call with the given userdata parameter until
##    this function call returns.
##  userdata: An opaque parameter to be passed directly to `callback`.
##    Note: this is distinct from the `userdata` parameter set with
##    `rustls_connection_set_userdata`.
##  out_n: An output parameter. This will be passed through to `callback`,
##    which should use it to store the number of bytes written.
##
##  Returns:
##
##  - 0: Success. You should call `rustls_acceptor_accept()` next.
##  - Any non-zero value: error.
##
##  This function passes through return values from `callback`. Typically
##  `callback` should return an errno value. See `rustls_read_callback()` for
##  more details.
##

proc rustls_acceptor_read_tls*(acceptor: ptr rustls_acceptor,
                              callback: rustls_read_callback, userdata: pointer,
                              out_n: ptr csize_t): rustls_io_result {.importc.}
##
##  Parse all TLS bytes read so far.  If those bytes make up a ClientHello,
##  create a rustls_accepted from them.
##
##  Parameters:
##
##  acceptor: The rustls_acceptor to access.
##  out_accepted: An output parameter. The pointed-to pointer will be set
##    to a new rustls_accepted only when the function returns
##    RUSTLS_RESULT_OK. The memory is owned by the caller and must eventually
##    be freed.
##
##  Returns:
##
##  - RUSTLS_RESULT_OK: a ClientHello has successfully been parsed.
##    A pointer to a newly allocated rustls_accepted has been written to
##    *out_accepted.
##  - RUSTLS_RESULT_ACCEPTOR_NOT_READY: a full ClientHello has not yet been read.
##    Read more TLS bytes to continue.
##  - Any other rustls_result: the TLS bytes read so far cannot be parsed
##    as a ClientHello, and reading additional bytes won't help.
##
##  Memory and lifetimes:
##
##  After this method returns RUSTLS_RESULT_OK, `acceptor` is
##  still allocated and valid. It needs to be freed regardless of success
##  or failure of this function.
##
##  Calling `rustls_acceptor_accept()` multiple times on the same
##  `rustls_acceptor` is acceptable from a memory perspective but pointless
##  from a protocol perspective.
##

proc rustls_acceptor_accept*(acceptor: ptr rustls_acceptor,
                            out_accepted: ptr ptr rustls_accepted): rustls_result {.importc.}
##
##  Get the server name indication (SNI) from the ClientHello.
##
##  Parameters:
##
##  accepted: The rustls_accepted to access.
##
##  Returns:
##
##  A rustls_str containing the SNI field.
##
##  The returned value is valid until rustls_accepted_into_connection or
##  rustls_accepted_free is called on the same `accepted`. It is not owned
##  by the caller and does not need to be freed.
##
##  This will be a zero-length rustls_str in these error cases:
##
##   - The SNI contains a NUL byte.
##   - The `accepted` parameter was NULL.
##   - The `accepted` parameter was already transformed into a connection
##       with rustls_accepted_into_connection.
##

proc rustls_accepted_server_name*(accepted: ptr rustls_accepted): rustls_str {.importc.}
##
##  Get the i'th in the list of signature schemes offered in the ClientHello.
##  This is useful in selecting a server certificate when there are multiple
##  available for the same server name, for instance when selecting
##  between an RSA and an ECDSA certificate.
##
##  Parameters:
##
##  accepted: The rustls_accepted to access.
##  i: Fetch the signature scheme at this offset.
##
##  Returns:
##
##  A TLS Signature Scheme from
## <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme>
##
##  This will be 0 in these cases:
##    - i is greater than the number of available cipher suites.
##    - accepted is NULL.
##    - rustls_accepted_into_connection has already been called with `accepted`.
##

proc rustls_accepted_signature_scheme*(accepted: ptr rustls_accepted, i: csize_t): uint16 {.importc.}
##
##  Get the i'th in the list of cipher suites offered in the ClientHello.
##
##  Parameters:
##
##  accepted: The rustls_accepted to access.
##  i: Fetch the cipher suite at this offset.
##
##  Returns:
##
##  A cipher suite value from
## <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4.>
##
##  This will be 0 in these cases:
##    - i is greater than the number of available cipher suites.
##    - accepted is NULL.
##    - rustls_accepted_into_connection has already been called with `accepted`.
##
##  Note that 0 is technically a valid cipher suite "TLS_NULL_WITH_NULL_NULL",
##  but this library will never support null ciphers.
##

proc rustls_accepted_cipher_suite*(accepted: ptr rustls_accepted, i: csize_t): uint16 {.importc.}
##
##  Get the i'th in the list of ALPN protocols requested in the ClientHello.
##
##  accepted: The rustls_accepted to access.
##  i: Fetch the ALPN value at this offset.
##
##  Returns:
##
##  A rustls_slice_bytes containing the i'th ALPN protocol. This may
##  contain internal NUL bytes and is not guaranteed to contain valid
##  UTF-8.
##
##  This will be a zero-length rustls_slice bytes in these cases:
##    - i is greater than the number of offered ALPN protocols.
##    - The client did not offer the ALPN extension.
##    - The `accepted` parameter was already transformed into a connection
##       with rustls_accepted_into_connection.
##
##  The returned value is valid until rustls_accepted_into_connection or
##  rustls_accepted_free is called on the same `accepted`. It is not owned
##  by the caller and does not need to be freed.
##
##  If you are calling this from Rust, note that the `'static` lifetime
##  in the return signature is fake and must not be relied upon.
##

proc rustls_accepted_alpn*(accepted: ptr rustls_accepted, i: csize_t): rustls_slice_bytes {.importc.}
##
##  Turn a rustls_accepted into a rustls_connection, given the provided
##  rustls_server_config.
##
##  Parameters:
##
##  accepted: The rustls_accepted to transform.
##  config: The configuration with which to create this connection.
##  out_conn: An output parameter. The pointed-to pointer will be set
##    to a new rustls_connection only when the function returns
##    RUSTLS_RESULT_OK.
##
##  Returns:
##
##  - RUSTLS_RESULT_OK: The `accepted` parameter was successfully
##    transformed into a rustls_connection, and *out_conn was written to.
##  - RUSTLS_RESULT_ALREADY_USED: This function was called twice on the
##    same rustls_connection.
##  - RUSTLS_RESULT_NULL_PARAMETER: One of the input parameters was NULL.
##
##  Memory and lifetimes:
##
##  In both success and failure cases, this consumes the contents of
##  `accepted` but does not free its allocated memory. In either case,
##  call rustls_accepted_free to avoid a memory leak.
##
##  Calling accessor methods on an `accepted` after consuming it will
##  return zero or default values.
##
##  The rustls_connection emitted by this function in the success case
##  is owned by the caller and must eventually be freed.
##
##  This function does not take ownership of `config`. It does increment
##  `config`'s internal reference count, indicating that the
##  rustls_connection may hold a reference to it until it is done.
##  See the documentation for rustls_connection for details.
##

proc rustls_accepted_into_connection*(accepted: ptr rustls_accepted,
                                     config: ptr rustls_server_config,
                                     out_conn: ptr ptr rustls_connection): rustls_result {.importc.}
##
##  Free a rustls_accepted.
##
##  Parameters:
##
##  accepted: The rustls_accepted to free.
##
##  Calling with NULL is fine. Must not be called twice with the same value.
##

proc rustls_accepted_free*(accepted: ptr rustls_accepted) {.importc.}
##
##  Get the DER data of the certificate itself.
##  The data is owned by the certificate and has the same lifetime.
##

proc rustls_certificate_get_der*(cert: ptr rustls_certificate,
                                out_der_data: ptr ptr uint8,
                                out_der_len: ptr csize_t): rustls_result {.importc.}
##
##  Return a 16-bit unsigned integer corresponding to this cipher suite's assignment from
##
## <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4>.
##  The bytes from the assignment are interpreted in network order.
##

proc rustls_supported_ciphersuite_get_suite*(
    supported_ciphersuite: ptr rustls_supported_ciphersuite): uint16 {.importc.}
##
##  Returns the name of the ciphersuite as a `rustls_str`. If the provided
##  ciphersuite is invalid, the rustls_str will contain the empty string. The
##  lifetime of the `rustls_str` is the lifetime of the program, it does not
##  need to be freed.
##

proc rustls_supported_ciphersuite_get_name*(
    supported_ciphersuite: ptr rustls_supported_ciphersuite): rustls_str {.importc.}
##
##  Return the length of rustls' list of supported cipher suites.
##

proc rustls_all_ciphersuites_len*(): csize_t {.importc.}
##
##  Get a pointer to a member of rustls' list of supported cipher suites. This will return non-NULL
##  for i < rustls_all_ciphersuites_len().
##  The returned pointer is valid for the lifetime of the program and may be used directly when
##  building a ClientConfig or ServerConfig.
##

proc rustls_all_ciphersuites_get_entry*(i: csize_t): ptr rustls_supported_ciphersuite {.importc.}
##
##  Return the length of rustls' list of default cipher suites.
##

proc rustls_default_ciphersuites_len*(): csize_t {.importc.}
##
##  Get a pointer to a member of rustls' list of supported cipher suites. This will return non-NULL
##  for i < rustls_default_ciphersuites_len().
##  The returned pointer is valid for the lifetime of the program and may be used directly when
##  building a ClientConfig or ServerConfig.
##

proc rustls_default_ciphersuites_get_entry*(i: csize_t): ptr rustls_supported_ciphersuite {.importc.}
##
##  Build a `rustls_certified_key` from a certificate chain and a private key.
##  `cert_chain` must point to a buffer of `cert_chain_len` bytes, containing
##  a series of PEM-encoded certificates, with the end-entity (leaf)
##  certificate first.
##
##  `private_key` must point to a buffer of `private_key_len` bytes, containing
##  a PEM-encoded private key in either PKCS#1 or PKCS#8 format.
##
##  On success, this writes a pointer to the newly created
##  `rustls_certified_key` in `certified_key_out`. That pointer must later
##  be freed with `rustls_certified_key_free` to avoid memory leaks. Note that
##  internally, this is an atomically reference-counted pointer, so even after
##  the original caller has called `rustls_certified_key_free`, other objects
##  may retain a pointer to the object. The memory will be freed when all
##  references are gone.
##
##  This function does not take ownership of any of its input pointers. It
##  parses the pointed-to data and makes a copy of the result. You may
##  free the cert_chain and private_key pointers after calling it.
##
##  Typically, you will build a `rustls_certified_key`, use it to create a
##  `rustls_server_config` (which increments the reference count), and then
##  immediately call `rustls_certified_key_free`. That leaves the
##  `rustls_server_config` in possession of the sole reference, so the
##  `rustls_certified_key`'s memory will automatically be released when
##  the `rustls_server_config` is freed.
##

proc rustls_certified_key_build*(cert_chain: ptr uint8, cert_chain_len: csize_t,
                                private_key: ptr uint8, private_key_len: csize_t,
                                certified_key_out: ptr ptr rustls_certified_key): rustls_result {.importc.}
##
##  Return the i-th rustls_certificate in the rustls_certified_key. 0 gives the
##  end-entity certificate. 1 and higher give certificates from the chain.
##  Indexes higher than the last available certificate return NULL.
##
##  The returned certificate is valid until the rustls_certified_key is freed.
##

proc rustls_certified_key_get_certificate*(
    certified_key: ptr rustls_certified_key, i: csize_t): ptr rustls_certificate {.importc.}
##
##  Create a copy of the rustls_certified_key with the given OCSP response data
##  as DER encoded bytes. The OCSP response may be given as NULL to clear any
##  possibly present OCSP data from the cloned key.
##  The cloned key is independent from its original and needs to be freed
##  by the application.
##

proc rustls_certified_key_clone_with_ocsp*(
    certified_key: ptr rustls_certified_key, ocsp_response: ptr rustls_slice_bytes,
    cloned_key_out: ptr ptr rustls_certified_key): rustls_result {.importc.}
##
##  "Free" a certified_key previously returned from
##  rustls_certified_key_build. Since certified_key is actually an
##  atomically reference-counted pointer, extant certified_key may still
##  hold an internal reference to the Rust object. However, C code must
##  consider this pointer unusable after "free"ing it.
##  Calling with NULL is fine. Must not be called twice with the same value.
##

proc rustls_certified_key_free*(key: ptr rustls_certified_key) {.importc.}
##
##  Create a rustls_root_cert_store. Caller owns the memory and must
##  eventually call rustls_root_cert_store_free. The store starts out empty.
##  Caller must add root certificates with rustls_root_cert_store_add_pem.
##  <https://docs.rs/rustls/latest/rustls/struct.RootCertStore.html#method.empty>
##

proc rustls_root_cert_store_new*(): ptr rustls_root_cert_store {.importc.}
##
##  Add one or more certificates to the root cert store using PEM encoded data.
##
##  When `strict` is true an error will return a `CertificateParseError`
##  result. So will an attempt to parse data that has zero certificates.
##
##  When `strict` is false, unparseable root certificates will be ignored.
##  This may be useful on systems that have syntactically invalid root
##  certificates.
##

proc rustls_root_cert_store_add_pem*(store: ptr rustls_root_cert_store,
                                    pem: ptr uint8, pem_len: csize_t, strict: bool): rustls_result {.importc.}
##
##  Free a rustls_root_cert_store previously returned from rustls_root_cert_store_builder_build.
##  Calling with NULL is fine. Must not be called twice with the same value.
##

proc rustls_root_cert_store_free*(store: ptr rustls_root_cert_store) {.importc.}
##
##  Create a new client certificate verifier for the root store. The verifier
##  can be used in several rustls_server_config instances. Must be freed by
##  the application when no longer needed. See the documentation of
##  rustls_client_cert_verifier_free for details about lifetime.
##  This copies the contents of the rustls_root_cert_store. It does not take
##  ownership of the pointed-to memory.
##

proc rustls_client_cert_verifier_new*(store: ptr rustls_root_cert_store): ptr rustls_client_cert_verifier {.importc.}
##
##  "Free" a verifier previously returned from
##  rustls_client_cert_verifier_new. Since rustls_client_cert_verifier is actually an
##  atomically reference-counted pointer, extant server_configs may still
##  hold an internal reference to the Rust object. However, C code must
##  consider this pointer unusable after "free"ing it.
##  Calling with NULL is fine. Must not be called twice with the same value.
##

proc rustls_client_cert_verifier_free*(verifier: ptr rustls_client_cert_verifier) {.importc.}
##
##  Create a new rustls_client_cert_verifier_optional for the root store. The
##  verifier can be used in several rustls_server_config instances. Must be
##  freed by the application when no longer needed. See the documentation of
##  rustls_client_cert_verifier_optional_free for details about lifetime.
##  This copies the contents of the rustls_root_cert_store. It does not take
##  ownership of the pointed-to data.
##

proc rustls_client_cert_verifier_optional_new*(store: ptr rustls_root_cert_store): ptr rustls_client_cert_verifier_optional {.importc.}
##
##  "Free" a verifier previously returned from
##  rustls_client_cert_verifier_optional_new. Since rustls_client_cert_verifier_optional
##  is actually an atomically reference-counted pointer, extant server_configs may still
##  hold an internal reference to the Rust object. However, C code must
##  consider this pointer unusable after "free"ing it.
##  Calling with NULL is fine. Must not be called twice with the same value.
##

proc rustls_client_cert_verifier_optional_free*(
    verifier: ptr rustls_client_cert_verifier_optional) {.importc.}
##
##  Create a rustls_client_config_builder. Caller owns the memory and must
##  eventually call rustls_client_config_builder_build, then free the
##  resulting rustls_client_config.
##  This uses rustls safe default values
##  for the cipher suites, key exchange groups and protocol versions.
##  This starts out with no trusted roots.
##  Caller must add roots with rustls_client_config_builder_load_roots_from_file
##  or provide a custom verifier.
##

proc rustls_client_config_builder_new*(): ptr rustls_client_config_builder {.importc.}
##
##  Create a rustls_client_config_builder. Caller owns the memory and must
##  eventually call rustls_client_config_builder_build, then free the
##  resulting rustls_client_config. Specify cipher suites in preference
##  order, the `cipher_suites` parameter must point to an array containing
##  `len` pointers to `rustls_supported_ciphersuite` previously obtained
##  from `rustls_all_ciphersuites_get_entry()`, or to a provided array,
##  RUSTLS_DEFAULT_CIPHER_SUITES or RUSTLS_ALL_CIPHER_SUITES. Set the TLS
##  protocol versions to use when negotiating a TLS session.
##
##  `tls_version` is the version of the protocol, as defined in rfc8446,
##  ch. 4.2.1 and end of ch. 5.1. Some values are defined in
##  `rustls_tls_version` for convenience, and the arrays
##  RUSTLS_DEFAULT_VERSIONS or RUSTLS_ALL_VERSIONS can be used directly.
##
##  `versions` will only be used during the call and the application retains
##  ownership. `len` is the number of consecutive `uint16` pointed to by `versions`.
##

proc rustls_client_config_builder_new_custom*(
    cipher_suites: ptr ptr rustls_supported_ciphersuite, cipher_suites_len: csize_t,
    tls_versions: ptr uint16, tls_versions_len: csize_t,
    builder_out: ptr ptr rustls_client_config_builder): rustls_result {.importc.}
##
##  Set a custom server certificate verifier.
##
##  The callback must not capture any of the pointers in its
##  rustls_verify_server_cert_params.
##  If `userdata` has been set with rustls_connection_set_userdata, it
##  will be passed to the callback. Otherwise the userdata param passed to
##  the callback will be NULL.
##
##  The callback must be safe to call on any thread at any time, including
##  multiple concurrent calls. So, for instance, if the callback mutates
##  userdata (or other shared state), it must use synchronization primitives
##  to make such mutation safe.
##
##  The callback receives certificate chain information as raw bytes.
##  Currently this library offers no functions to parse the certificates,
##  so you'll need to bring your own certificate parsing library
##  if you need to parse them.
##
##  If the custom verifier accepts the certificate, it should return
##  RUSTLS_RESULT_OK. Otherwise, it may return any other rustls_result error.
##  Feel free to use an appropriate error from the RUSTLS_RESULT_CERT_*
##  section.
##
##
## <https://docs.rs/rustls/latest/rustls/client/struct.DangerousClientConfig.html#method.set_certificate_verifier>
##

proc rustls_client_config_builder_dangerous_set_certificate_verifier*(
    config_builder: ptr rustls_client_config_builder,
    callback: rustls_verify_server_cert_callback): rustls_result {.importc.}
##
##  Use the trusted root certificates from the provided store.
##
##  This replaces any trusted roots already configured with copies
##  from `roots`. This adds 1 to the refcount for `roots`. When you
##  call rustls_client_config_free or rustls_client_config_builder_free,
##  those will subtract 1 from the refcount for `roots`.
##

proc rustls_client_config_builder_use_roots*(
    config_builder: ptr rustls_client_config_builder,
    roots: ptr rustls_root_cert_store): rustls_result {.importc.}
##
##  Add trusted root certificates from the named file, which should contain
##  PEM-formatted certificates.
##

proc rustls_client_config_builder_load_roots_from_file*(
    config_builder: ptr rustls_client_config_builder, filename: cstring): rustls_result {.importc.}
##
##  Set the ALPN protocol list to the given protocols. `protocols` must point
##  to a buffer of `rustls_slice_bytes` (built by the caller) with `len`
##  elements. Each element of the buffer must be a rustls_slice_bytes whose
##  data field points to a single ALPN protocol ID. Standard ALPN protocol
##  IDs are defined at
##
## <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids>.
##
##  This function makes a copy of the data in `protocols` and does not retain
##  any pointers, so the caller can free the pointed-to memory after calling.
##
##
## <https://docs.rs/rustls/latest/rustls/client/struct.ClientConfig.html#structfield.alpn_protocols>
##

proc rustls_client_config_builder_set_alpn_protocols*(
    builder: ptr rustls_client_config_builder, protocols: ptr rustls_slice_bytes,
    len: csize_t): rustls_result {.importc.}
##
##  Enable or disable SNI.
##
## <https://docs.rs/rustls/latest/rustls/struct.ClientConfig.html#structfield.enable_sni>
##

proc rustls_client_config_builder_set_enable_sni*(
    config: ptr rustls_client_config_builder, enable: bool) {.importc.}
##
##  Provide the configuration a list of certificates where the connection
##  will select the first one that is compatible with the server's signature
##  verification capabilities. Clients that want to support both ECDSA and
##  RSA certificates will want the ECSDA to go first in the list.
##
##  The built configuration will keep a reference to all certified keys
##  provided. The client may `rustls_certified_key_free()` afterwards
##  without the configuration losing them. The same certified key may also
##  be used in multiple configs.
##
##  EXPERIMENTAL: installing a client authentication callback will replace any
##  configured certified keys and vice versa.
##

proc rustls_client_config_builder_set_certified_key*(
    builder: ptr rustls_client_config_builder,
    certified_keys: ptr ptr rustls_certified_key, certified_keys_len: csize_t): rustls_result {.importc.}
##
##  Turn a *rustls_client_config_builder (mutable) into a const *rustls_client_config
##  (read-only).
##

proc rustls_client_config_builder_build*(builder: ptr rustls_client_config_builder): ptr rustls_client_config {.importc.}
##
##  "Free" a client_config_builder without building it into a rustls_client_config.
##  Normally builders are built into rustls_client_config via `rustls_client_config_builder_build`
##  and may not be free'd or otherwise used afterwards.
##  Use free only when the building of a config has to be aborted before a config
##  was created.
##

proc rustls_client_config_builder_free*(config: ptr rustls_client_config_builder) {.importc.}
##
##  "Free" a rustls_client_config previously returned from
##  rustls_client_config_builder_build. Since rustls_client_config is actually an
##  atomically reference-counted pointer, extant client connections may still
##  hold an internal reference to the Rust object. However, C code must
##  consider this pointer unusable after "free"ing it.
##  Calling with NULL is fine. Must not be called twice with the same value.
##

proc rustls_client_config_free*(config: ptr rustls_client_config) {.importc.}
##
##  Create a new rustls_connection containing a client connection and return
##  it in the output parameter `out`. If this returns an error code, the
##  memory pointed to by `conn_out` remains unchanged. If this returns a
##  non-error, the memory pointed to by `conn_out` is modified to point at a
##  valid rustls_connection. The caller now owns the rustls_connection and must
##  call `rustls_connection_free` when done with it.
##
##  The server_name parameter can contain a hostname or an IP address in
##  textual form (IPv4 or IPv6). This function will return an error if it
##  cannot be parsed as one of those types.
##

proc rustls_client_connection_new*(config: ptr rustls_client_config,
                                  server_name: cstring,
                                  conn_out: ptr ptr rustls_connection): rustls_result {.importc.}
##
##  Set the userdata pointer associated with this connection. This will be passed
##  to any callbacks invoked by the connection, if you've set up callbacks in the config.
##  The pointed-to data must outlive the connection.
##

proc rustls_connection_set_userdata*(conn: ptr rustls_connection, userdata: pointer) {.importc.}
##
##  Set the logging callback for this connection. The log callback will be invoked
##  with the userdata parameter previously set by rustls_connection_set_userdata, or
##  NULL if no userdata was set.
##

proc rustls_connection_set_log_callback*(conn: ptr rustls_connection,
                                        cb: rustls_log_callback) {.importc.}
##
##  Read some TLS bytes from the network into internal buffers. The actual network
##  I/O is performed by `callback`, which you provide. Rustls will invoke your
##  callback with a suitable buffer to store the read bytes into. You don't have
##  to fill it up, just fill with as many bytes as you get in one syscall.
##  The `userdata` parameter is passed through directly to `callback`. Note that
##  this is distinct from the `userdata` parameter set with
##  `rustls_connection_set_userdata`.
##  Returns 0 for success, or an errno value on error. Passes through return values
##  from callback. See rustls_read_callback for more details.
##  <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.read_tls>
##

proc rustls_connection_read_tls*(conn: ptr rustls_connection,
                                callback: rustls_read_callback, userdata: pointer,
                                out_n: ptr csize_t): rustls_io_result {.importc.}
##
##  Write some TLS bytes to the network. The actual network I/O is performed by
##  `callback`, which you provide. Rustls will invoke your callback with a
##  suitable buffer containing TLS bytes to send. You don't have to write them
##  all, just as many as you can in one syscall.
##  The `userdata` parameter is passed through directly to `callback`. Note that
##  this is distinct from the `userdata` parameter set with
##  `rustls_connection_set_userdata`.
##  Returns 0 for success, or an errno value on error. Passes through return values
##  from callback. See rustls_write_callback for more details.
##  <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.write_tls>
##

proc rustls_connection_write_tls*(conn: ptr rustls_connection,
                                 callback: rustls_write_callback,
                                 userdata: pointer, out_n: ptr csize_t): rustls_io_result {.importc.}
##
##  Write all available TLS bytes to the network. The actual network I/O is performed by
##  `callback`, which you provide. Rustls will invoke your callback with an array
##  of rustls_slice_bytes, each containing a buffer with TLS bytes to send.
##  You don't have to write them all, just as many as you are willing.
##  The `userdata` parameter is passed through directly to `callback`. Note that
##  this is distinct from the `userdata` parameter set with
##  `rustls_connection_set_userdata`.
##  Returns 0 for success, or an errno value on error. Passes through return values
##  from callback. See rustls_write_callback for more details.
##  <https://docs.rs/rustls/latest/rustls/struct.Writer.html#method.write_vectored>
##

proc rustls_connection_write_tls_vectored*(conn: ptr rustls_connection,
    callback: rustls_write_vectored_callback, userdata: pointer, out_n: ptr csize_t): rustls_io_result {.importc.}
##
##  Decrypt any available ciphertext from the internal buffer and put it
##  into the internal plaintext buffer, potentially making bytes available
##  for rustls_connection_read().
##
## <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.process_new_packets>
##

proc rustls_connection_process_new_packets*(conn: ptr rustls_connection): rustls_result {.importc.}
##
##  <https://docs.rs/rustls/latest/rustls/struct.CommonState.html#method.wants_read>
##

proc rustls_connection_wants_read*(conn: ptr rustls_connection): bool {.importc.}
##
##
## <https://docs.rs/rustls/latest/rustls/struct.CommonState.html#method.wants_write>
##

proc rustls_connection_wants_write*(conn: ptr rustls_connection): bool {.importc.}
##
##
## <https://docs.rs/rustls/latest/rustls/struct.CommonState.html#method.is_handshaking>
##

proc rustls_connection_is_handshaking*(conn: ptr rustls_connection): bool {.importc.}
##
##  Sets a limit on the internal buffers used to buffer unsent plaintext (prior
##  to completing the TLS handshake) and unsent TLS records. By default, there
##  is no limit. The limit can be set at any time, even if the current buffer
##  use is higher.
##
## <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.set_buffer_limit>
##

proc rustls_connection_set_buffer_limit*(conn: ptr rustls_connection, n: csize_t) {.importc.}
##
##  Queues a close_notify fatal alert to be sent in the next write_tls call.
##
## <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.send_close_notify>
##

proc rustls_connection_send_close_notify*(conn: ptr rustls_connection) {.importc.}
##
##  Return the i-th certificate provided by the peer.
##  Index 0 is the end entity certificate. Higher indexes are certificates
##  in the chain. Requesting an index higher than what is available returns
##  NULL.
##  The returned pointer is valid until the next mutating function call
##  affecting the connection. A mutating function call is one where the
##  first argument has type `struct rustls_connection *` (as opposed to
##   `const struct rustls_connection *`).
##
## <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.peer_certificates>
##

proc rustls_connection_get_peer_certificate*(conn: ptr rustls_connection, i: csize_t): ptr rustls_certificate {.importc.}
##
##  Get the ALPN protocol that was negotiated, if any. Stores a pointer to a
##  borrowed buffer of bytes, and that buffer's len, in the output parameters.
##  The borrow lives as long as the connection.
##  If the connection is still handshaking, or no ALPN protocol was negotiated,
##  stores NULL and 0 in the output parameters.
##  The provided pointer is valid until the next mutating function call
##  affecting the connection. A mutating function call is one where the
##  first argument has type `struct rustls_connection *` (as opposed to
##   `const struct rustls_connection *`).
##  <https://www.iana.org/assignments/tls-parameters/>
##  <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.alpn_protocol>
##

proc rustls_connection_get_alpn_protocol*(conn: ptr rustls_connection,
    protocol_out: ptr ptr uint8, protocol_out_len: ptr csize_t) {.importc.}
##
##  Return the TLS protocol version that has been negotiated. Before this
##  has been decided during the handshake, this will return 0. Otherwise,
##  the u16 version number as defined in the relevant RFC is returned.
##
## <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.protocol_version>
##
## <https://docs.rs/rustls/latest/rustls/internal/msgs/enums/enum.ProtocolVersion.html>
##

proc rustls_connection_get_protocol_version*(conn: ptr rustls_connection): uint16 {.importc.}
##
##  Retrieves the cipher suite agreed with the peer.
##  This returns NULL until the ciphersuite is agreed.
##  The returned pointer lives as long as the program.
##
## <https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.negotiated_cipher_suite>
##

proc rustls_connection_get_negotiated_ciphersuite*(conn: ptr rustls_connection): ptr rustls_supported_ciphersuite {.importc.}
##
##  Write up to `count` plaintext bytes from `buf` into the `rustls_connection`.
##  This will increase the number of output bytes available to
##  `rustls_connection_write_tls`.
##  On success, store the number of bytes actually written in *out_n
##  (this may be less than `count`).
##  <https://docs.rs/rustls/latest/rustls/struct.Writer.html#method.write>
##

proc rustls_connection_write*(conn: ptr rustls_connection, buf: ptr uint8,
                             count: csize_t, out_n: ptr csize_t): rustls_result {.importc.}
##
##  Read up to `count` plaintext bytes from the `rustls_connection` into `buf`.
##  On success, store the number of bytes read in *out_n (this may be less
##  than `count`). A success with *out_n set to 0 means "all bytes currently
##  available have been read, but more bytes may become available after
##  subsequent calls to rustls_connection_read_tls and
##  rustls_connection_process_new_packets."
##
##  Subtle note: Even though this function only writes to `buf` and does not
##  read from it, the memory in `buf` must be initialized before the call (for
##  Rust-internal reasons). Initializing a buffer once and then using it
##  multiple times without zeroizing before each call is fine.
##  <https://docs.rs/rustls/latest/rustls/struct.Reader.html#method.read>
##

proc rustls_connection_read*(conn: ptr rustls_connection, buf: ptr uint8,
                            count: csize_t, out_n: ptr csize_t): rustls_result {.importc.}
when defined(DEFINE_READ_BUF):
  ##
  ##  Read up to `count` plaintext bytes from the `rustls_connection` into `buf`.
  ##  On success, store the number of bytes read in *out_n (this may be less
  ##  than `count`). A success with *out_n set to 0 means "all bytes currently
  ##  available have been read, but more bytes may become available after
  ##  subsequent calls to rustls_connection_read_tls and
  ##  rustls_connection_process_new_packets."
  ##
  ##  This experimental API is only available when using a nightly Rust compiler
  ##  and enabling the `read_buf` Cargo feature. It will be deprecated and later
  ##  removed in future versions.
  ##
  ##  Unlike with `rustls_connection_read`, this function may be called with `buf`
  ##  pointing to an uninitialized memory buffer.
  ##
  proc rustls_connection_read_2*(conn: ptr rustls_connection, buf: ptr uint8,
                                count: csize_t, out_n: ptr csize_t): rustls_result {.
      importc.}
##
##  Free a rustls_connection. Calling with NULL is fine.
##  Must not be called twice with the same value.
##

proc rustls_connection_free*(conn: ptr rustls_connection) {.importc.}
##
##  After a rustls function returns an error, you may call
##  this to get a pointer to a buffer containing a detailed error
##  message. The contents of the error buffer will be out_n bytes long,
##  UTF-8 encoded, and not NUL-terminated.
##

proc rustls_error*(result: cuint, buf: cstring, len: csize_t, out_n: ptr csize_t) {.importc.}
proc rustls_result_is_cert_error*(result: cuint): bool {.importc.}
##
##  Return a rustls_str containing the stringified version of a log level.
##

proc rustls_log_level_str*(level: rustls_log_level): rustls_str {.importc.}
##
##  Return the length of the outer slice. If the input pointer is NULL,
##  returns 0.
##

proc rustls_slice_slice_bytes_len*(input: ptr rustls_slice_slice_bytes): csize_t {.importc.}
##
##  Retrieve the nth element from the input slice of slices. If the input
##  pointer is NULL, or n is greater than the length of the
##  rustls_slice_slice_bytes, returns rustls_slice_bytes{NULL, 0}.
##

proc rustls_slice_slice_bytes_get*(input: ptr rustls_slice_slice_bytes, n: csize_t): rustls_slice_bytes {.importc.}
##
##  Return the length of the outer slice. If the input pointer is NULL,
##  returns 0.
##

proc rustls_slice_str_len*(input: ptr rustls_slice_str): csize_t {.importc.}
##
##  Retrieve the nth element from the input slice of `&str`s. If the input
##  pointer is NULL, or n is greater than the length of the
##  rustls_slice_str, returns rustls_str{NULL, 0}.
##

proc rustls_slice_str_get*(input: ptr rustls_slice_str, n: csize_t): rustls_str {.importc.}
##
##  Create a rustls_server_config_builder. Caller owns the memory and must
##  eventually call rustls_server_config_builder_build, then free the
##  resulting rustls_server_config. This uses rustls safe default values
##  for the cipher suites, key exchange groups and protocol versions.
##

proc rustls_server_config_builder_new*(): ptr rustls_server_config_builder {.importc.}
##
##  Create a rustls_server_config_builder. Caller owns the memory and must
##  eventually call rustls_server_config_builder_build, then free the
##  resulting rustls_server_config. Specify cipher suites in preference
##  order, the `cipher_suites` parameter must point to an array containing
##  `len` pointers to `rustls_supported_ciphersuite` previously obtained
##  from `rustls_all_ciphersuites_get_entry()`. Set the TLS protocol
##  versions to use when negotiating a TLS session.
##
##  `tls_version` is the version of the protocol, as defined in rfc8446,
##  ch. 4.2.1 and end of ch. 5.1. Some values are defined in
##  `rustls_tls_version` for convenience.
##
##  `versions` will only be used during the call and the application retains
##  ownership. `len` is the number of consecutive `uint16` pointed to by `versions`.
##

proc rustls_server_config_builder_new_custom*(
    cipher_suites: ptr ptr rustls_supported_ciphersuite, cipher_suites_len: csize_t,
    tls_versions: ptr uint16, tls_versions_len: csize_t,
    builder_out: ptr ptr rustls_server_config_builder): rustls_result {.importc.}
##
##  Create a rustls_server_config_builder for TLS sessions that require
##  valid client certificates. The passed rustls_client_cert_verifier may
##  be used in several builders.
##  For memory lifetime, see rustls_server_config_builder_new.
##

proc rustls_server_config_builder_set_client_verifier*(
    builder: ptr rustls_server_config_builder,
    verifier: ptr rustls_client_cert_verifier) {.importc.}
##
##  Create a rustls_server_config_builder for TLS sessions that accept
##  valid client certificates, but do not require them. The passed
##  rustls_client_cert_verifier_optional may be used in several builders.
##  For memory lifetime, see rustls_server_config_builder_new.
##

proc rustls_server_config_builder_set_client_verifier_optional*(
    builder: ptr rustls_server_config_builder,
    verifier: ptr rustls_client_cert_verifier_optional) {.importc.}
##
##  "Free" a server_config_builder without building it into a rustls_server_config.
##  Normally builders are built into rustls_server_configs via `rustls_server_config_builder_build`
##  and may not be free'd or otherwise used afterwards.
##  Use free only when the building of a config has to be aborted before a config
##  was created.
##

proc rustls_server_config_builder_free*(config: ptr rustls_server_config_builder) {.importc.}
##
##  With `ignore` != 0, the server will ignore the client ordering of cipher
##  suites, aka preference, during handshake and respect its own ordering
##  as configured.
##
## <https://docs.rs/rustls/latest/rustls/struct.ServerConfig.html#structfield.ignore_client_order>
##

proc rustls_server_config_builder_set_ignore_client_order*(
    builder: ptr rustls_server_config_builder, ignore: bool): rustls_result {.importc.}
##
##  Set the ALPN protocol list to the given protocols. `protocols` must point
##  to a buffer of `rustls_slice_bytes` (built by the caller) with `len`
##  elements. Each element of the buffer must point to a slice of bytes that
##  contains a single ALPN protocol from
##
## <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids>.
##
##  This function makes a copy of the data in `protocols` and does not retain
##  any pointers, so the caller can free the pointed-to memory after calling.
##
##
## <https://docs.rs/rustls/latest/rustls/server/struct.ServerConfig.html#structfield.alpn_protocols>
##

proc rustls_server_config_builder_set_alpn_protocols*(
    builder: ptr rustls_server_config_builder, protocols: ptr rustls_slice_bytes,
    len: csize_t): rustls_result {.importc.}
##
##  Provide the configuration a list of certificates where the connection
##  will select the first one that is compatible with the client's signature
##  verification capabilities. Servers that want to support both ECDSA and
##  RSA certificates will want the ECSDA to go first in the list.
##
##  The built configuration will keep a reference to all certified keys
##  provided. The client may `rustls_certified_key_free()` afterwards
##  without the configuration losing them. The same certified key may also
##  be used in multiple configs.
##
##  EXPERIMENTAL: installing a client_hello callback will replace any
##  configured certified keys and vice versa.
##

proc rustls_server_config_builder_set_certified_keys*(
    builder: ptr rustls_server_config_builder,
    certified_keys: ptr ptr rustls_certified_key, certified_keys_len: csize_t): rustls_result {.importc.}
##
##  Turn a *rustls_server_config_builder (mutable) into a const *rustls_server_config
##  (read-only).
##

proc rustls_server_config_builder_build*(builder: ptr rustls_server_config_builder): ptr rustls_server_config {.importc.}
##
##  "Free" a rustls_server_config previously returned from
##  rustls_server_config_builder_build. Since rustls_server_config is actually an
##  atomically reference-counted pointer, extant server connections may still
##  hold an internal reference to the Rust object. However, C code must
##  consider this pointer unusable after "free"ing it.
##  Calling with NULL is fine. Must not be called twice with the same value.
##

proc rustls_server_config_free*(config: ptr rustls_server_config) {.importc.}
##
##  Create a new rustls_connection containing a server connection, and return it
##  in the output parameter `out`. If this returns an error code, the memory
##  pointed to by `conn_out` remains unchanged. If this returns a non-error,
##  the memory pointed to by `conn_out` is modified to point
##  at a valid rustls_connection. The caller now owns the rustls_connection
##  and must call `rustls_connection_free` when done with it.
##

proc rustls_server_connection_new*(config: ptr rustls_server_config,
                                  conn_out: ptr ptr rustls_connection): rustls_result {.importc.}
##
##  Copy the server name from the server name indication (SNI) extension to `buf` which can
##  hold up  to `count` bytes, and the length of that server name in `out_n`. The string is
##  stored in UTF-8 with no terminating NUL byte.
##  Returns RUSTLS_RESULT_INSUFFICIENT_SIZE if the SNI hostname is longer than `count`.
##  Returns Ok with *out_n == 0 if there is no SNI hostname available on this connection
##  because it hasn't been processed yet, or because the client did not send SNI.
##
## <https://docs.rs/rustls/latest/rustls/server/struct.ServerConnection.html#method.server_name>
##

proc rustls_server_connection_get_server_name*(conn: ptr rustls_connection,
    buf: ptr uint8, count: csize_t, out_n: ptr csize_t): rustls_result {.importc.}
##
##  Register a callback to be invoked when a connection created from this config
##  sees a TLS ClientHello message. If `userdata` has been set with
##  rustls_connection_set_userdata, it will be passed to the callback.
##  Otherwise the userdata param passed to the callback will be NULL.
##
##  Any existing `ResolvesServerCert` implementation currently installed in the
##  `rustls_server_config` will be replaced. This also means registering twice
##  will overwrite the first registration. It is not permitted to pass a NULL
##  value for `callback`.
##
##  EXPERIMENTAL: this feature of rustls-ffi is likely to change in the future, as
##  the rustls library is re-evaluating their current approach to client hello handling.
##  Installing a client_hello callback will replace any configured certified keys
##  and vice versa. Same holds true for the set_certified_keys variant.
##

proc rustls_server_config_builder_set_hello_callback*(
    builder: ptr rustls_server_config_builder,
    callback: rustls_client_hello_callback): rustls_result {.importc.}
##
##  Select a `rustls_certified_key` from the list that matches the cryptographic
##  parameters of a TLS client hello. Note that this does not do any SNI matching.
##  The input certificates should already have been filtered to ones matching the
##  SNI from the client hello.
##
##  This is intended for servers that are configured with several keys for the
##  same domain name(s), for example ECDSA and RSA types. The presented keys are
##  inspected in the order given and keys first in the list are given preference,
##  all else being equal. However rustls is free to choose whichever it considers
##  to be the best key with its knowledge about security issues and possible future
##  extensions of the protocol.
##
##  Return RUSTLS_RESULT_OK if a key was selected and RUSTLS_RESULT_NOT_FOUND
##  if none was suitable.
##

proc rustls_client_hello_select_certified_key*(hello: ptr rustls_client_hello,
    certified_keys: ptr ptr rustls_certified_key, certified_keys_len: csize_t,
    out_key: ptr ptr rustls_certified_key): rustls_result {.importc.}
##
##  Register callbacks for persistence of TLS session IDs and secrets. Both
##  keys and values are highly sensitive data, containing enough information
##  to break the security of the connections involved.
##
##  If `userdata` has been set with rustls_connection_set_userdata, it
##  will be passed to the callbacks. Otherwise the userdata param passed to
##  the callbacks will be NULL.
##

proc rustls_server_config_builder_set_persistence*(
    builder: ptr rustls_server_config_builder,
    get_cb: rustls_session_store_get_callback,
    put_cb: rustls_session_store_put_callback): rustls_result {.importc.}
