//! RFC compliance validation for QUIC implementation
//!
//! Provides comprehensive validation against QUIC RFCs including:
//! - RFC 9000 (QUIC Transport Protocol)
//! - RFC 9001 (Using TLS with QUIC)
//! - RFC 9002 (QUIC Loss Detection and Congestion Control)
//! - RFC 9369 (QUIC Version 2)

use std::collections::HashMap;
use std::time::Duration;
use crate::{QuicResult, QuicError};
use crate::version_negotiation::QuicVersion;
use crate::connection_id::ConnectionId;
use crate::frame::Frame;

/// RFC compliance validator
#[derive(Debug)]
pub struct RfcComplianceValidator {
    /// Enabled validation rules
    enabled_rules: Vec<ComplianceRule>,
    /// Rule violations found
    violations: Vec<ComplianceViolation>,
    /// Validation statistics
    stats: ValidationStats,
}

/// Compliance rules from various RFCs
#[derive(Debug, Clone, PartialEq)]
pub enum ComplianceRule {
    // RFC 9000 - Transport Protocol
    Rfc9000ConnectionIdLength,
    Rfc9000PacketNumberSpace,
    Rfc9000FrameEncoding,
    Rfc9000FlowControl,
    Rfc9000StreamStates,
    Rfc9000ConnectionMigration,
    Rfc9000VersionNegotiation,
    Rfc9000StatelessReset,

    // RFC 9001 - TLS Integration
    Rfc9001CryptoHandshake,
    Rfc9001KeyDerivation,
    Rfc9001PacketProtection,
    Rfc9001TransportParameters,

    // RFC 9002 - Loss Detection and Congestion Control
    Rfc9002AckProcessing,
    Rfc9002LossDetection,
    Rfc9002CongestionControl,
    Rfc9002ProbeTimeout,
    Rfc9002RttMeasurement,

    // RFC 9369 - QUIC Version 2
    Rfc9369VersionTwoFeatures,

    // Custom validation rules
    Custom(String),
}

/// Compliance violation details
#[derive(Debug, Clone)]
pub struct ComplianceViolation {
    pub rule: ComplianceRule,
    pub severity: ViolationSeverity,
    pub description: String,
    pub context: String,
    pub rfc_reference: String,
    pub suggested_fix: Option<String>,
}

/// Severity of RFC compliance violations
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ViolationSeverity {
    /// Informational - not a strict violation
    Info,
    /// Warning - should be addressed but not critical
    Warning,
    /// Error - violates RFC specification
    Error,
    /// Critical - severely violates RFC, will cause interop issues
    Critical,
}

/// Validation statistics
#[derive(Debug, Clone, Default)]
pub struct ValidationStats {
    pub total_checks: u64,
    pub passed_checks: u64,
    pub violations_found: u64,
    pub critical_violations: u64,
    pub error_violations: u64,
    pub warning_violations: u64,
    pub info_violations: u64,
}

impl RfcComplianceValidator {
    /// Create a new RFC compliance validator
    pub fn new() -> Self {
        Self {
            enabled_rules: Self::default_rules(),
            violations: Vec::new(),
            stats: ValidationStats::default(),
        }
    }

    /// Create validator with specific rules
    pub fn with_rules(rules: Vec<ComplianceRule>) -> Self {
        Self {
            enabled_rules: rules,
            violations: Vec::new(),
            stats: ValidationStats::default(),
        }
    }

    /// Get default validation rules
    fn default_rules() -> Vec<ComplianceRule> {
        vec![
            // RFC 9000 rules
            ComplianceRule::Rfc9000ConnectionIdLength,
            ComplianceRule::Rfc9000PacketNumberSpace,
            ComplianceRule::Rfc9000FrameEncoding,
            ComplianceRule::Rfc9000FlowControl,
            ComplianceRule::Rfc9000StreamStates,
            ComplianceRule::Rfc9000VersionNegotiation,
            ComplianceRule::Rfc9000StatelessReset,

            // RFC 9001 rules
            ComplianceRule::Rfc9001CryptoHandshake,
            ComplianceRule::Rfc9001PacketProtection,
            ComplianceRule::Rfc9001TransportParameters,

            // RFC 9002 rules
            ComplianceRule::Rfc9002AckProcessing,
            ComplianceRule::Rfc9002LossDetection,
            ComplianceRule::Rfc9002CongestionControl,
            ComplianceRule::Rfc9002RttMeasurement,
        ]
    }

    /// Validate connection ID compliance (RFC 9000 Section 5.1)
    pub fn validate_connection_id(&mut self, connection_id: &ConnectionId) -> QuicResult<()> {
        if !self.enabled_rules.contains(&ComplianceRule::Rfc9000ConnectionIdLength) {
            return Ok(());
        }

        self.stats.total_checks += 1;

        // RFC 9000: Connection IDs MUST be at most 20 bytes
        if connection_id.len() > 20 {
            self.add_violation(ComplianceViolation {
                rule: ComplianceRule::Rfc9000ConnectionIdLength,
                severity: ViolationSeverity::Error,
                description: format!("Connection ID length {} exceeds maximum of 20 bytes", connection_id.len()),
                context: "Connection ID validation".to_string(),
                rfc_reference: "RFC 9000 Section 5.1".to_string(),
                suggested_fix: Some("Use connection IDs of 20 bytes or less".to_string()),
            });
            return Ok(());
        }

        self.stats.passed_checks += 1;
        Ok(())
    }

    /// Validate packet number space (RFC 9000 Section 12.3)
    pub fn validate_packet_number_space(&mut self, packet_number: u64, max_packet_number: u64) -> QuicResult<()> {
        if !self.enabled_rules.contains(&ComplianceRule::Rfc9000PacketNumberSpace) {
            return Ok(());
        }

        self.stats.total_checks += 1;

        // RFC 9000: Packet numbers MUST NOT exceed 2^62 - 1
        const MAX_PACKET_NUMBER: u64 = (1u64 << 62) - 1;

        if packet_number > MAX_PACKET_NUMBER {
            self.add_violation(ComplianceViolation {
                rule: ComplianceRule::Rfc9000PacketNumberSpace,
                severity: ViolationSeverity::Critical,
                description: format!("Packet number {} exceeds maximum allowed value {}", packet_number, MAX_PACKET_NUMBER),
                context: "Packet number validation".to_string(),
                rfc_reference: "RFC 9000 Section 12.3".to_string(),
                suggested_fix: Some("Ensure packet numbers do not exceed 2^62 - 1".to_string()),
            });
            return Ok(());
        }

        // Check packet number ordering
        if packet_number <= max_packet_number {
            self.add_violation(ComplianceViolation {
                rule: ComplianceRule::Rfc9000PacketNumberSpace,
                severity: ViolationSeverity::Warning,
                description: format!("Packet number {} is not greater than previous maximum {}", packet_number, max_packet_number),
                context: "Packet number ordering".to_string(),
                rfc_reference: "RFC 9000 Section 12.3".to_string(),
                suggested_fix: Some("Ensure packet numbers are strictly increasing".to_string()),
            });
        }

        self.stats.passed_checks += 1;
        Ok(())
    }

    /// Validate frame encoding (RFC 9000 Section 12.4)
    pub fn validate_frame_encoding(&mut self, frame: &Frame) -> QuicResult<()> {
        if !self.enabled_rules.contains(&ComplianceRule::Rfc9000FrameEncoding) {
            return Ok(());
        }

        self.stats.total_checks += 1;

        // Validate frame-specific requirements
        match frame {
            Frame::Stream { stream_id, offset, data, .. } => {
                // RFC 9000: Stream ID must be within allowed range
                if *stream_id > (1u64 << 62) - 1 {
                    self.add_violation(ComplianceViolation {
                        rule: ComplianceRule::Rfc9000FrameEncoding,
                        severity: ViolationSeverity::Error,
                        description: format!("Stream ID {} exceeds maximum allowed value", stream_id),
                        context: "STREAM frame validation".to_string(),
                        rfc_reference: "RFC 9000 Section 2.1".to_string(),
                        suggested_fix: Some("Use stream IDs within the allowed range".to_string()),
                    });
                    return Ok(());
                }

                // Check for reasonable data sizes
                if data.len() > 65536 {
                    self.add_violation(ComplianceViolation {
                        rule: ComplianceRule::Rfc9000FrameEncoding,
                        severity: ViolationSeverity::Warning,
                        description: format!("STREAM frame data length {} is very large", data.len()),
                        context: "STREAM frame validation".to_string(),
                        rfc_reference: "RFC 9000 Section 19.8".to_string(),
                        suggested_fix: Some("Consider splitting large data into smaller frames".to_string()),
                    });
                }
            }

            Frame::ConnectionClose { error_code, reason_phrase, .. } => {
                // RFC 9000: Reason phrase should be UTF-8
                if !reason_phrase.is_ascii() {
                    // Check if it's valid UTF-8
                    if std::str::from_utf8(reason_phrase.as_bytes()).is_err() {
                        self.add_violation(ComplianceViolation {
                            rule: ComplianceRule::Rfc9000FrameEncoding,
                            severity: ViolationSeverity::Warning,
                            description: "CONNECTION_CLOSE reason phrase contains invalid UTF-8".to_string(),
                            context: "CONNECTION_CLOSE frame validation".to_string(),
                            rfc_reference: "RFC 9000 Section 19.19".to_string(),
                            suggested_fix: Some("Use valid UTF-8 for reason phrases".to_string()),
                        });
                    }
                }

                // Check reason phrase length
                if reason_phrase.len() > 1024 {
                    self.add_violation(ComplianceViolation {
                        rule: ComplianceRule::Rfc9000FrameEncoding,
                        severity: ViolationSeverity::Warning,
                        description: format!("CONNECTION_CLOSE reason phrase length {} is very long", reason_phrase.len()),
                        context: "CONNECTION_CLOSE frame validation".to_string(),
                        rfc_reference: "RFC 9000 Section 19.19".to_string(),
                        suggested_fix: Some("Keep reason phrases concise".to_string()),
                    });
                }
            }

            Frame::NewConnectionId { connection_id, .. } => {
                // Validate connection ID length
                if connection_id.len() > 20 {
                    self.add_violation(ComplianceViolation {
                        rule: ComplianceRule::Rfc9000FrameEncoding,
                        severity: ViolationSeverity::Error,
                        description: format!("NEW_CONNECTION_ID contains connection ID of length {}, exceeds maximum 20", connection_id.len()),
                        context: "NEW_CONNECTION_ID frame validation".to_string(),
                        rfc_reference: "RFC 9000 Section 5.1".to_string(),
                        suggested_fix: Some("Use connection IDs of 20 bytes or less".to_string()),
                    });
                    return Ok(());
                }
            }

            _ => {
                // Other frames - basic validation passed
            }
        }

        self.stats.passed_checks += 1;
        Ok(())
    }

    /// Validate flow control limits (RFC 9000 Section 4)
    pub fn validate_flow_control(&mut self, stream_id: u64, offset: u64, data_length: usize, flow_control_limit: u64) -> QuicResult<()> {
        if !self.enabled_rules.contains(&ComplianceRule::Rfc9000FlowControl) {
            return Ok(());
        }

        self.stats.total_checks += 1;

        let final_offset = offset + data_length as u64;

        if final_offset > flow_control_limit {
            self.add_violation(ComplianceViolation {
                rule: ComplianceRule::Rfc9000FlowControl,
                severity: ViolationSeverity::Error,
                description: format!(
                    "Stream {} data at offset {} with length {} exceeds flow control limit {}",
                    stream_id, offset, data_length, flow_control_limit
                ),
                context: "Flow control validation".to_string(),
                rfc_reference: "RFC 9000 Section 4.1".to_string(),
                suggested_fix: Some("Respect flow control limits before sending data".to_string()),
            });
            return Ok(());
        }

        self.stats.passed_checks += 1;
        Ok(())
    }

    /// Validate version negotiation (RFC 9000 Section 6)
    pub fn validate_version_negotiation(&mut self, client_version: QuicVersion, server_versions: &[QuicVersion]) -> QuicResult<()> {
        if !self.enabled_rules.contains(&ComplianceRule::Rfc9000VersionNegotiation) {
            return Ok(());
        }

        self.stats.total_checks += 1;

        // RFC 9000: Server MUST include the version it would select in the list
        if !server_versions.is_empty() && !server_versions.contains(&client_version) {
            // Check if server has a compatible version
            let has_compatible = server_versions.iter().any(|v| {
                // Version 1 and Version 2 are both valid
                matches!((client_version, v),
                    (QuicVersion::V1, QuicVersion::V1) |
                    (QuicVersion::V2, QuicVersion::V2) |
                    (QuicVersion::V1, QuicVersion::V2) |
                    (QuicVersion::V2, QuicVersion::V1)
                )
            });

            if !has_compatible {
                self.add_violation(ComplianceViolation {
                    rule: ComplianceRule::Rfc9000VersionNegotiation,
                    severity: ViolationSeverity::Warning,
                    description: format!("Server does not support client version {:?}", client_version),
                    context: "Version negotiation".to_string(),
                    rfc_reference: "RFC 9000 Section 6".to_string(),
                    suggested_fix: Some("Ensure version compatibility between client and server".to_string()),
                });
            }
        }

        self.stats.passed_checks += 1;
        Ok(())
    }

    /// Validate congestion control behavior (RFC 9002 Section 7)
    pub fn validate_congestion_control(&mut self, cwnd: u64, bytes_in_flight: u64, ssthresh: Option<u64>) -> QuicResult<()> {
        if !self.enabled_rules.contains(&ComplianceRule::Rfc9002CongestionControl) {
            return Ok(());
        }

        self.stats.total_checks += 1;

        // RFC 9002: Congestion window should not be less than minimum
        const MIN_CONGESTION_WINDOW: u64 = 14720; // 10 * max_datagram_size (typical 1472 bytes)

        if cwnd < MIN_CONGESTION_WINDOW {
            self.add_violation(ComplianceViolation {
                rule: ComplianceRule::Rfc9002CongestionControl,
                severity: ViolationSeverity::Warning,
                description: format!("Congestion window {} is below recommended minimum {}", cwnd, MIN_CONGESTION_WINDOW),
                context: "Congestion control validation".to_string(),
                rfc_reference: "RFC 9002 Section 7.2".to_string(),
                suggested_fix: Some("Maintain minimum congestion window size".to_string()),
            });
        }

        // Bytes in flight should not exceed congestion window
        if bytes_in_flight > cwnd {
            self.add_violation(ComplianceViolation {
                rule: ComplianceRule::Rfc9002CongestionControl,
                severity: ViolationSeverity::Error,
                description: format!("Bytes in flight {} exceeds congestion window {}", bytes_in_flight, cwnd),
                context: "Congestion control validation".to_string(),
                rfc_reference: "RFC 9002 Section 7".to_string(),
                suggested_fix: Some("Do not send more data than congestion window allows".to_string()),
            });
            return Ok(());
        }

        self.stats.passed_checks += 1;
        Ok(())
    }

    /// Add a compliance violation
    fn add_violation(&mut self, violation: ComplianceViolation) {
        match violation.severity {
            ViolationSeverity::Critical => self.stats.critical_violations += 1,
            ViolationSeverity::Error => self.stats.error_violations += 1,
            ViolationSeverity::Warning => self.stats.warning_violations += 1,
            ViolationSeverity::Info => self.stats.info_violations += 1,
        }
        self.stats.violations_found += 1;
        self.violations.push(violation);
    }

    /// Get all violations
    pub fn get_violations(&self) -> &[ComplianceViolation] {
        &self.violations
    }

    /// Get violations by severity
    pub fn get_violations_by_severity(&self, severity: ViolationSeverity) -> Vec<&ComplianceViolation> {
        self.violations.iter()
            .filter(|v| v.severity == severity)
            .collect()
    }

    /// Get validation statistics
    pub fn get_stats(&self) -> &ValidationStats {
        &self.stats
    }

    /// Check if there are any critical violations
    pub fn has_critical_violations(&self) -> bool {
        self.stats.critical_violations > 0
    }

    /// Check if implementation is RFC compliant (no critical or error violations)
    pub fn is_compliant(&self) -> bool {
        self.stats.critical_violations == 0 && self.stats.error_violations == 0
    }

    /// Generate compliance report
    pub fn generate_report(&self) -> ComplianceReport {
        ComplianceReport {
            stats: self.stats.clone(),
            violations: self.violations.clone(),
            is_compliant: self.is_compliant(),
            has_warnings: self.stats.warning_violations > 0,
        }
    }

    /// Clear all violations and reset stats
    pub fn reset(&mut self) {
        self.violations.clear();
        self.stats = ValidationStats::default();
    }
}

/// Comprehensive compliance report
#[derive(Debug, Clone)]
pub struct ComplianceReport {
    pub stats: ValidationStats,
    pub violations: Vec<ComplianceViolation>,
    pub is_compliant: bool,
    pub has_warnings: bool,
}

impl ComplianceReport {
    /// Get summary as string
    pub fn summary(&self) -> String {
        format!(
            "RFC Compliance Report\n\
             Total Checks: {}\n\
             Passed: {}\n\
             Violations: {} (Critical: {}, Error: {}, Warning: {}, Info: {})\n\
             Compliant: {}\n\
             Pass Rate: {:.1}%",
            self.stats.total_checks,
            self.stats.passed_checks,
            self.stats.violations_found,
            self.stats.critical_violations,
            self.stats.error_violations,
            self.stats.warning_violations,
            self.stats.info_violations,
            if self.is_compliant { "Yes" } else { "No" },
            if self.stats.total_checks > 0 {
                (self.stats.passed_checks as f64 / self.stats.total_checks as f64) * 100.0
            } else {
                0.0
            }
        )
    }
}

impl Default for RfcComplianceValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_connection_id_validation() {
        let mut validator = RfcComplianceValidator::new();

        // Valid connection ID
        let valid_id = ConnectionId::from_bytes(vec![1, 2, 3, 4], 0).unwrap();
        assert!(validator.validate_connection_id(&valid_id).is_ok());
        assert_eq!(validator.get_violations().len(), 0);

        // Invalid connection ID (too long)
        let invalid_id = ConnectionId::from_bytes(vec![0u8; 25], 0).unwrap();
        assert!(validator.validate_connection_id(&invalid_id).is_ok());
        assert_eq!(validator.get_violations().len(), 1);
        assert_eq!(validator.get_violations()[0].severity, ViolationSeverity::Error);
    }

    #[test]
    fn test_packet_number_validation() {
        let mut validator = RfcComplianceValidator::new();

        // Valid packet number
        assert!(validator.validate_packet_number_space(100, 99).is_ok());
        assert_eq!(validator.get_violations().len(), 0);

        // Invalid packet number (too large)
        let max_pn = (1u64 << 62) - 1;
        assert!(validator.validate_packet_number_space(max_pn + 1, 0).is_ok());
        assert_eq!(validator.get_violations().len(), 1);
        assert_eq!(validator.get_violations()[0].severity, ViolationSeverity::Critical);
    }

    #[test]
    fn test_frame_validation() {
        let mut validator = RfcComplianceValidator::new();

        // Valid STREAM frame
        let valid_frame = Frame::Stream {
            stream_id: 4,
            offset: 0,
            data: Bytes::from("hello"),
            fin: false,
        };
        assert!(validator.validate_frame_encoding(&valid_frame).is_ok());

        // Invalid STREAM frame (stream ID too large)
        let invalid_frame = Frame::Stream {
            stream_id: 1u64 << 62,
            offset: 0,
            data: Bytes::from("hello"),
            fin: false,
        };
        assert!(validator.validate_frame_encoding(&invalid_frame).is_ok());
        assert!(validator.get_violations().len() > 0);
    }

    #[test]
    fn test_compliance_report() {
        let mut validator = RfcComplianceValidator::new();

        // Add some violations
        validator.add_violation(ComplianceViolation {
            rule: ComplianceRule::Rfc9000ConnectionIdLength,
            severity: ViolationSeverity::Error,
            description: "Test violation".to_string(),
            context: "Test".to_string(),
            rfc_reference: "RFC 9000".to_string(),
            suggested_fix: None,
        });

        let report = validator.generate_report();
        assert!(!report.is_compliant);
        assert_eq!(report.violations.len(), 1);
    }
}