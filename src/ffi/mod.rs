use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::ptr;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tracing::{error, info, warn};

use crate::client::{QuicClient, QuicClientConfig};
use crate::server::{QuicServer, QuicServerConfig};

// Opaque handles for FFI
pub struct GQuicClient {
    client: QuicClient,
    runtime: Arc<Runtime>,
}

pub struct GQuicServer {
    server: QuicServer,
    runtime: Arc<Runtime>,
}

// Error codes
pub const GQUIC_OK: c_int = 0;
pub const GQUIC_ERROR: c_int = -1;
pub const GQUIC_INVALID_PARAM: c_int = -2;
pub const GQUIC_CONNECTION_FAILED: c_int = -3;
pub const GQUIC_STREAM_ERROR: c_int = -4;

// Callback types for Zig integration
pub type GQuicConnectionCallback = extern "C" fn(*const c_void, c_int);
pub type GQuicDataCallback = extern "C" fn(*const c_void, *const u8, usize);

#[repr(C)]
pub struct GQuicConfig {
    pub bind_addr: *const c_char,
    pub cert_path: *const c_char,
    pub key_path: *const c_char,
    pub alpn_protocols: *const *const c_char,
    pub alpn_count: usize,
    pub max_connections: c_uint,
    pub use_self_signed: c_int,
}

// Client FFI functions
#[no_mangle]
pub extern "C" fn gquic_client_new(
    server_name: *const c_char,
    client_out: *mut *mut GQuicClient,
) -> c_int {
    if server_name.is_null() || client_out.is_null() {
        return GQUIC_INVALID_PARAM;
    }

    let server_name = match unsafe { CStr::from_ptr(server_name) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return GQUIC_INVALID_PARAM,
    };

    let runtime = match Runtime::new() {
        Ok(rt) => Arc::new(rt),
        Err(e) => {
            error!("Failed to create runtime: {}", e);
            return GQUIC_ERROR;
        }
    };

    let config = QuicClientConfig::default();
    let mut config = config;
    config.server_name = server_name;

    let client = match QuicClient::new(config) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create client: {}", e);
            return GQUIC_ERROR;
        }
    };

    let gquic_client = Box::new(GQuicClient {
        client,
        runtime,
    });

    unsafe {
        *client_out = Box::into_raw(gquic_client);
    }

    GQUIC_OK
}

#[no_mangle]
pub extern "C" fn gquic_client_connect(
    client: *mut GQuicClient,
    addr: *const c_char,
    connection_out: *mut *mut c_void,
) -> c_int {
    if client.is_null() || addr.is_null() || connection_out.is_null() {
        return GQUIC_INVALID_PARAM;
    }

    let client = unsafe { &*client };
    
    let addr_str = match unsafe { CStr::from_ptr(addr) }.to_str() {
        Ok(s) => s,
        Err(_) => return GQUIC_INVALID_PARAM,
    };

    let socket_addr: SocketAddr = match addr_str.parse() {
        Ok(addr) => addr,
        Err(e) => {
            error!("Invalid address format: {}", e);
            return GQUIC_INVALID_PARAM;
        }
    };

    let connection = match client.runtime.block_on(client.client.connect(socket_addr)) {
        Ok(conn) => conn,
        Err(e) => {
            error!("Connection failed: {}", e);
            return GQUIC_CONNECTION_FAILED;
        }
    };

    let connection_ptr = Box::into_raw(Box::new(connection)) as *mut c_void;
    unsafe {
        *connection_out = connection_ptr;
    }

    GQUIC_OK
}

#[no_mangle]
pub extern "C" fn gquic_client_send_data(
    client: *mut GQuicClient,
    connection: *mut c_void,
    data: *const u8,
    data_len: usize,
) -> c_int {
    if client.is_null() || connection.is_null() || data.is_null() {
        return GQUIC_INVALID_PARAM;
    }

    // TODO: Implement data sending through stream
    // This requires storing active streams and managing their lifecycle
    info!("Sending {} bytes of data", data_len);
    GQUIC_OK
}

#[no_mangle]
pub extern "C" fn gquic_client_destroy(client: *mut GQuicClient) {
    if !client.is_null() {
        unsafe {
            let _ = Box::from_raw(client);
        }
    }
}

// Server FFI functions
#[no_mangle]
pub extern "C" fn gquic_server_new(
    config: *const GQuicConfig,
    server_out: *mut *mut GQuicServer,
) -> c_int {
    if config.is_null() || server_out.is_null() {
        return GQUIC_INVALID_PARAM;
    }

    let config = unsafe { &*config };
    
    let bind_addr = if config.bind_addr.is_null() {
        "0.0.0.0:443".to_string()
    } else {
        match unsafe { CStr::from_ptr(config.bind_addr) }.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return GQUIC_INVALID_PARAM,
        }
    };

    let socket_addr: SocketAddr = match bind_addr.parse() {
        Ok(addr) => addr,
        Err(_) => return GQUIC_INVALID_PARAM,
    };

    let runtime = match Runtime::new() {
        Ok(rt) => Arc::new(rt),
        Err(e) => {
            error!("Failed to create runtime: {}", e);
            return GQUIC_ERROR;
        }
    };

    let mut server_config = QuicServerConfig::builder().bind(socket_addr);

    // Handle TLS configuration
    if config.use_self_signed != 0 {
        server_config = match server_config.with_self_signed_cert() {
            Ok(cfg) => cfg,
            Err(e) => {
                error!("Failed to generate self-signed cert: {}", e);
                return GQUIC_ERROR;
            }
        };
    } else if !config.cert_path.is_null() && !config.key_path.is_null() {
        let cert_path = match unsafe { CStr::from_ptr(config.cert_path) }.to_str() {
            Ok(s) => s,
            Err(_) => return GQUIC_INVALID_PARAM,
        };
        let key_path = match unsafe { CStr::from_ptr(config.key_path) }.to_str() {
            Ok(s) => s,
            Err(_) => return GQUIC_INVALID_PARAM,
        };

        server_config = match server_config.with_tls_files(cert_path, key_path) {
            Ok(cfg) => cfg,
            Err(e) => {
                error!("Failed to load TLS files: {}", e);
                return GQUIC_ERROR;
            }
        };
    } else {
        warn!("No TLS configuration provided, using self-signed");
        server_config = match server_config.with_self_signed_cert() {
            Ok(cfg) => cfg,
            Err(e) => {
                error!("Failed to generate self-signed cert: {}", e);
                return GQUIC_ERROR;
            }
        };
    }

    // Add ALPN protocols
    if !config.alpn_protocols.is_null() && config.alpn_count > 0 {
        for i in 0..config.alpn_count {
            let alpn_ptr = unsafe { *config.alpn_protocols.add(i) };
            if !alpn_ptr.is_null() {
                if let Ok(alpn) = unsafe { CStr::from_ptr(alpn_ptr) }.to_str() {
                    server_config = server_config.with_alpn(alpn);
                }
            }
        }
    }

    let server = match server_config.build() {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to create server: {}", e);
            return GQUIC_ERROR;
        }
    };

    let gquic_server = Box::new(GQuicServer {
        server,
        runtime,
    });

    unsafe {
        *server_out = Box::into_raw(gquic_server);
    }

    GQUIC_OK
}

#[no_mangle]
pub extern "C" fn gquic_server_start(
    server: *mut GQuicServer,
    callback: GQuicConnectionCallback,
    user_data: *const c_void,
) -> c_int {
    if server.is_null() {
        return GQUIC_INVALID_PARAM;
    }

    let server = unsafe { &*server };
    
    // Run server in the background
    // TODO: Implement proper callback integration with connection handler
    info!("Starting QUIC server");
    
    match server.runtime.block_on(async {
        // For now, just start the server - full callback integration needs more work
        server.server.run().await
    }) {
        Ok(_) => GQUIC_OK,
        Err(e) => {
            error!("Server error: {}", e);
            GQUIC_ERROR
        }
    }
}

#[no_mangle]
pub extern "C" fn gquic_server_destroy(server: *mut GQuicServer) {
    if !server.is_null() {
        unsafe {
            let _ = Box::from_raw(server);
        }
    }
}

// Utility functions
#[no_mangle]
pub extern "C" fn gquic_version() -> *const c_char {
    static VERSION: &str = env!("CARGO_PKG_VERSION");
    VERSION.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn gquic_init_logging(level: c_int) -> c_int {
    let log_level = match level {
        0 => tracing::Level::ERROR,
        1 => tracing::Level::WARN,
        2 => tracing::Level::INFO,
        3 => tracing::Level::DEBUG,
        4 => tracing::Level::TRACE,
        _ => tracing::Level::INFO,
    };

    match tracing_subscriber::fmt()
        .with_max_level(log_level)
        .try_init()
    {
        Ok(_) => GQUIC_OK,
        Err(_) => GQUIC_ERROR, // Already initialized
    }
}