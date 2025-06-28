use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use super::error::{QuicError, Result};

/// Bandwidth estimation and network adaptation for optimal performance
#[derive(Debug)]
pub struct BandwidthEstimator {
    /// Recent bandwidth samples
    samples: VecDeque<BandwidthSample>,
    /// Current estimated bandwidth
    estimated_bandwidth: u64, // bytes per second
    /// Maximum observed bandwidth
    max_bandwidth: u64,
    /// Bandwidth estimation window
    window_duration: Duration,
    /// Minimum number of samples for estimation
    min_samples: usize,
    /// Network adaptation configuration
    config: AdaptationConfig,
    /// Recent delivery rate measurements
    delivery_rates: VecDeque<DeliveryRateInfo>,
    /// Current round-trip time estimate
    rtt_estimate: Option<Duration>,
}

#[derive(Debug, Clone)]
pub struct AdaptationConfig {
    /// Enable bandwidth adaptation
    pub enable_adaptation: bool,
    /// Bandwidth estimation window
    pub estimation_window: Duration,
    /// Minimum bandwidth (bytes/sec)
    pub min_bandwidth: u64,
    /// Maximum bandwidth (bytes/sec)
    pub max_bandwidth: u64,
    /// Adaptation sensitivity (0.0 - 1.0)
    pub adaptation_sensitivity: f64,
    /// Enable congestion-based adaptation
    pub enable_congestion_adaptation: bool,
}

impl Default for AdaptationConfig {
    fn default() -> Self {
        Self {
            enable_adaptation: true,
            estimation_window: Duration::from_secs(10),
            min_bandwidth: 64 * 1024, // 64 KB/s
            max_bandwidth: 1_000_000_000, // 1 GB/s
            adaptation_sensitivity: 0.8,
            enable_congestion_adaptation: true,
        }
    }
}

#[derive(Debug, Clone)]
struct BandwidthSample {
    timestamp: Instant,
    bytes_delivered: u64,
    delivery_time: Duration,
    rtt: Duration,
    is_app_limited: bool,
}

#[derive(Debug, Clone)]
struct DeliveryRateInfo {
    timestamp: Instant,
    delivered_bytes: u64,
    delivered_time: Duration,
    first_sent_time: Instant,
    prior_delivered: u64,
    prior_time: Instant,
    interval: Duration,
}

#[derive(Debug, Clone)]
pub struct NetworkConditions {
    pub estimated_bandwidth: u64,
    pub rtt: Option<Duration>,
    pub loss_rate: f64,
    pub congestion_level: CongestionLevel,
    pub adaptation_recommendation: AdaptationRecommendation,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CongestionLevel {
    Low,
    Moderate,
    High,
    Severe,
}

#[derive(Debug, Clone)]
pub enum AdaptationRecommendation {
    IncreaseRate { factor: f64 },
    DecreaseRate { factor: f64 },
    MaintainRate,
    BackOff,
}

impl BandwidthEstimator {
    pub fn new(config: AdaptationConfig) -> Self {
        Self {
            samples: VecDeque::new(),
            estimated_bandwidth: config.min_bandwidth,
            max_bandwidth: config.min_bandwidth,
            window_duration: config.estimation_window,
            min_samples: 5,
            config,
            delivery_rates: VecDeque::new(),
            rtt_estimate: None,
        }
    }

    /// Record a bandwidth sample from packet delivery
    pub fn record_sample(
        &mut self,
        bytes_delivered: u64,
        delivery_time: Duration,
        rtt: Duration,
        is_app_limited: bool,
    ) -> Result<()> {
        let now = Instant::now();
        
        let sample = BandwidthSample {
            timestamp: now,
            bytes_delivered,
            delivery_time,
            rtt,
            is_app_limited,
        };

        self.samples.push_back(sample);
        self.rtt_estimate = Some(rtt);

        // Remove old samples outside the window
        self.cleanup_old_samples(now);

        // Update bandwidth estimate
        self.update_bandwidth_estimate()?;

        debug!("Recorded bandwidth sample: {} bytes in {:?} (RTT: {:?})",
               bytes_delivered, delivery_time, rtt);

        Ok(())
    }

    /// Update the current bandwidth estimate
    fn update_bandwidth_estimate(&mut self) -> Result<()> {
        if self.samples.len() < self.min_samples {
            return Ok(());
        }

        // Use the maximum bandwidth observed in recent samples
        let mut max_bandwidth_in_window = 0u64;
        let mut total_bytes = 0u64;
        let mut total_time = Duration::from_nanos(0);

        for sample in &self.samples {
            if !sample.is_app_limited {
                let sample_bandwidth = if sample.delivery_time.as_nanos() > 0 {
                    (sample.bytes_delivered * 1_000_000_000) / sample.delivery_time.as_nanos() as u64
                } else {
                    0
                };
                
                max_bandwidth_in_window = max_bandwidth_in_window.max(sample_bandwidth);
                total_bytes += sample.bytes_delivered;
                total_time += sample.delivery_time;
            }
        }

        // Calculate average bandwidth
        let avg_bandwidth = if total_time.as_nanos() > 0 {
            (total_bytes * 1_000_000_000) / total_time.as_nanos() as u64
        } else {
            self.estimated_bandwidth
        };

        // Use weighted average of max and average
        let new_estimate = (max_bandwidth_in_window * 7 + avg_bandwidth * 3) / 10;
        
        // Apply smoothing
        self.estimated_bandwidth = (self.estimated_bandwidth * 3 + new_estimate) / 4;
        self.max_bandwidth = self.max_bandwidth.max(max_bandwidth_in_window);

        // Clamp to configured limits
        self.estimated_bandwidth = self.estimated_bandwidth
            .max(self.config.min_bandwidth)
            .min(self.config.max_bandwidth);

        debug!("Updated bandwidth estimate: {} bytes/sec (max: {} bytes/sec)",
               self.estimated_bandwidth, self.max_bandwidth);

        Ok(())
    }

    /// Clean up old samples outside the estimation window
    fn cleanup_old_samples(&mut self, now: Instant) {
        while let Some(sample) = self.samples.front() {
            if now.duration_since(sample.timestamp) > self.window_duration {
                self.samples.pop_front();
            } else {
                break;
            }
        }

        // Also cleanup delivery rates
        while let Some(rate) = self.delivery_rates.front() {
            if now.duration_since(rate.timestamp) > self.window_duration {
                self.delivery_rates.pop_front();
            } else {
                break;
            }
        }
    }

    /// Get current network conditions assessment
    pub fn get_network_conditions(&self, loss_rate: f64) -> NetworkConditions {
        let congestion_level = self.assess_congestion_level(loss_rate);
        let recommendation = self.get_adaptation_recommendation(&congestion_level, loss_rate);

        NetworkConditions {
            estimated_bandwidth: self.estimated_bandwidth,
            rtt: self.rtt_estimate,
            loss_rate,
            congestion_level,
            adaptation_recommendation: recommendation,
        }
    }

    /// Assess current congestion level
    fn assess_congestion_level(&self, loss_rate: f64) -> CongestionLevel {
        // Simple congestion assessment based on loss rate and RTT trends
        if loss_rate > 0.05 { // > 5% loss
            CongestionLevel::Severe
        } else if loss_rate > 0.02 { // > 2% loss
            CongestionLevel::High
        } else if loss_rate > 0.005 { // > 0.5% loss
            CongestionLevel::Moderate
        } else {
            CongestionLevel::Low
        }
    }

    /// Get adaptation recommendation based on network conditions
    fn get_adaptation_recommendation(
        &self,
        congestion_level: &CongestionLevel,
        loss_rate: f64,
    ) -> AdaptationRecommendation {
        if !self.config.enable_adaptation {
            return AdaptationRecommendation::MaintainRate;
        }

        match congestion_level {
            CongestionLevel::Severe => AdaptationRecommendation::BackOff,
            CongestionLevel::High => AdaptationRecommendation::DecreaseRate { 
                factor: 0.5 * self.config.adaptation_sensitivity 
            },
            CongestionLevel::Moderate => AdaptationRecommendation::DecreaseRate { 
                factor: 0.8 * self.config.adaptation_sensitivity 
            },
            CongestionLevel::Low => {
                // Only increase if we have sufficient bandwidth headroom
                if self.estimated_bandwidth < self.max_bandwidth * 9 / 10 {
                    AdaptationRecommendation::IncreaseRate { 
                        factor: 1.1 + (0.2 * self.config.adaptation_sensitivity) 
                    }
                } else {
                    AdaptationRecommendation::MaintainRate
                }
            }
        }
    }

    /// Update with delivery rate information (BBR-style)
    pub fn update_delivery_rate(
        &mut self,
        delivered_bytes: u64,
        delivered_time: Duration,
        first_sent_time: Instant,
        prior_delivered: u64,
        prior_time: Instant,
    ) {
        let now = Instant::now();
        let interval = delivered_time;

        let delivery_rate = DeliveryRateInfo {
            timestamp: now,
            delivered_bytes,
            delivered_time,
            first_sent_time,
            prior_delivered,
            prior_time,
            interval,
        };

        self.delivery_rates.push_back(delivery_rate);

        // Keep only recent delivery rates
        while self.delivery_rates.len() > 20 {
            self.delivery_rates.pop_front();
        }
    }

    /// Get estimated bandwidth in bytes per second
    pub fn get_estimated_bandwidth(&self) -> u64 {
        self.estimated_bandwidth
    }

    /// Get maximum observed bandwidth
    pub fn get_max_bandwidth(&self) -> u64 {
        self.max_bandwidth
    }

    /// Predict bandwidth for the next window
    pub fn predict_bandwidth(&self, prediction_window: Duration) -> u64 {
        // Simple prediction based on recent trend
        if self.samples.len() < 3 {
            return self.estimated_bandwidth;
        }

        let recent_samples: Vec<_> = self.samples.iter().rev().take(5).collect();
        if recent_samples.len() < 2 {
            return self.estimated_bandwidth;
        }

        // Calculate trend from recent samples
        let mut bandwidths = Vec::new();
        for sample in &recent_samples {
            if !sample.is_app_limited && sample.delivery_time.as_nanos() > 0 {
                let bandwidth = (sample.bytes_delivered * 1_000_000_000) / sample.delivery_time.as_nanos() as u64;
                bandwidths.push(bandwidth);
            }
        }

        if bandwidths.len() < 2 {
            return self.estimated_bandwidth;
        }

        // Simple linear trend
        let first_bw = bandwidths[bandwidths.len() - 1] as f64;
        let last_bw = bandwidths[0] as f64;
        let trend = (last_bw - first_bw) / bandwidths.len() as f64;

        let predicted = self.estimated_bandwidth as f64 + trend;
        
        (predicted as u64)
            .max(self.config.min_bandwidth)
            .min(self.config.max_bandwidth)
    }

    /// Apply adaptation recommendation to congestion control
    pub fn apply_adaptation(&self, current_cwnd: u64, recommendation: &AdaptationRecommendation) -> u64 {
        match recommendation {
            AdaptationRecommendation::IncreaseRate { factor } => {
                let new_cwnd = (current_cwnd as f64 * factor) as u64;
                new_cwnd.min(self.max_bandwidth / 8) // Conservative upper bound
            }
            AdaptationRecommendation::DecreaseRate { factor } => {
                let new_cwnd = (current_cwnd as f64 * factor) as u64;
                new_cwnd.max(self.config.min_bandwidth / 8) // Conservative lower bound
            }
            AdaptationRecommendation::BackOff => {
                current_cwnd / 2 // Halve the congestion window
            }
            AdaptationRecommendation::MaintainRate => current_cwnd,
        }
    }

    /// Get bandwidth estimation statistics
    pub fn get_stats(&self) -> BandwidthStats {
        BandwidthStats {
            estimated_bandwidth: self.estimated_bandwidth,
            max_bandwidth: self.max_bandwidth,
            sample_count: self.samples.len(),
            delivery_rate_count: self.delivery_rates.len(),
            window_duration: self.window_duration,
            current_rtt: self.rtt_estimate,
        }
    }

    /// Reset bandwidth estimation (for connection migration)
    pub fn reset(&mut self) {
        self.samples.clear();
        self.delivery_rates.clear();
        self.estimated_bandwidth = self.config.min_bandwidth;
        self.max_bandwidth = self.config.min_bandwidth;
        self.rtt_estimate = None;
        info!("Bandwidth estimator reset");
    }

    /// Check if we have sufficient data for reliable estimation
    pub fn has_reliable_estimate(&self) -> bool {
        self.samples.len() >= self.min_samples && 
        self.samples.iter().any(|s| !s.is_app_limited)
    }
}

#[derive(Debug, Clone)]
pub struct BandwidthStats {
    pub estimated_bandwidth: u64,
    pub max_bandwidth: u64,
    pub sample_count: usize,
    pub delivery_rate_count: usize,
    pub window_duration: Duration,
    pub current_rtt: Option<Duration>,
}

/// Network adaptation engine that coordinates with congestion control
#[derive(Debug)]
pub struct NetworkAdapter {
    bandwidth_estimator: BandwidthEstimator,
    adaptation_history: VecDeque<AdaptationEvent>,
    config: AdaptationConfig,
}

#[derive(Debug, Clone)]
struct AdaptationEvent {
    timestamp: Instant,
    recommendation: AdaptationRecommendation,
    bandwidth_before: u64,
    bandwidth_after: u64,
    effective: bool,
}

impl NetworkAdapter {
    pub fn new(config: AdaptationConfig) -> Self {
        Self {
            bandwidth_estimator: BandwidthEstimator::new(config.clone()),
            adaptation_history: VecDeque::new(),
            config,
        }
    }

    /// Process network feedback and adapt
    pub fn process_feedback(
        &mut self,
        bytes_delivered: u64,
        delivery_time: Duration,
        rtt: Duration,
        loss_rate: f64,
        is_app_limited: bool,
    ) -> Result<NetworkConditions> {
        // Record bandwidth sample
        self.bandwidth_estimator.record_sample(
            bytes_delivered,
            delivery_time,
            rtt,
            is_app_limited,
        )?;

        // Get current conditions and recommendations
        let conditions = self.bandwidth_estimator.get_network_conditions(loss_rate);

        // Record adaptation event
        let adaptation_event = AdaptationEvent {
            timestamp: Instant::now(),
            recommendation: conditions.adaptation_recommendation.clone(),
            bandwidth_before: self.bandwidth_estimator.get_estimated_bandwidth(),
            bandwidth_after: self.bandwidth_estimator.get_estimated_bandwidth(), // Will be updated
            effective: true, // Will be determined later
        };

        self.adaptation_history.push_back(adaptation_event);

        // Keep limited history
        while self.adaptation_history.len() > 100 {
            self.adaptation_history.pop_front();
        }

        Ok(conditions)
    }

    /// Get bandwidth estimator reference
    pub fn bandwidth_estimator(&self) -> &BandwidthEstimator {
        &self.bandwidth_estimator
    }

    /// Get mutable bandwidth estimator reference
    pub fn bandwidth_estimator_mut(&mut self) -> &mut BandwidthEstimator {
        &mut self.bandwidth_estimator
    }

    /// Evaluate effectiveness of recent adaptations
    pub fn evaluate_adaptation_effectiveness(&self) -> f64 {
        if self.adaptation_history.len() < 5 {
            return 0.5; // Neutral score
        }

        let recent_events: Vec<_> = self.adaptation_history.iter().rev().take(5).collect();
        let mut effectiveness_score = 0.0;

        for event in &recent_events {
            match event.recommendation {
                AdaptationRecommendation::IncreaseRate { .. } => {
                    if event.bandwidth_after > event.bandwidth_before {
                        effectiveness_score += 1.0;
                    } else {
                        effectiveness_score -= 0.5;
                    }
                }
                AdaptationRecommendation::DecreaseRate { .. } => {
                    // For decrease rate, effectiveness is harder to measure
                    // We assume it's effective if it was followed
                    effectiveness_score += 0.5;
                }
                _ => effectiveness_score += 0.3,
            }
        }

        effectiveness_score / recent_events.len() as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bandwidth_estimation() {
        let mut estimator = BandwidthEstimator::new(AdaptationConfig::default());
        
        // Record some samples
        estimator.record_sample(
            10000, // 10KB
            Duration::from_millis(100),
            Duration::from_millis(50),
            false,
        ).unwrap();

        estimator.record_sample(
            20000, // 20KB
            Duration::from_millis(150),
            Duration::from_millis(45),
            false,
        ).unwrap();

        assert!(estimator.get_estimated_bandwidth() > 0);
    }

    #[test]
    fn test_congestion_assessment() {
        let estimator = BandwidthEstimator::new(AdaptationConfig::default());
        
        // Test different congestion levels
        assert_eq!(estimator.assess_congestion_level(0.001), CongestionLevel::Low);
        assert_eq!(estimator.assess_congestion_level(0.01), CongestionLevel::Moderate);
        assert_eq!(estimator.assess_congestion_level(0.03), CongestionLevel::High);
        assert_eq!(estimator.assess_congestion_level(0.1), CongestionLevel::Severe);
    }

    #[test]
    fn test_adaptation_recommendations() {
        let estimator = BandwidthEstimator::new(AdaptationConfig::default());
        
        let conditions = estimator.get_network_conditions(0.001); // Low loss
        match conditions.adaptation_recommendation {
            AdaptationRecommendation::IncreaseRate { .. } |
            AdaptationRecommendation::MaintainRate => {
                // Expected for low congestion
            }
            _ => panic!("Unexpected recommendation for low congestion"),
        }

        let conditions = estimator.get_network_conditions(0.1); // High loss
        match conditions.adaptation_recommendation {
            AdaptationRecommendation::BackOff => {
                // Expected for high congestion
            }
            _ => panic!("Unexpected recommendation for high congestion"),
        }
    }
}