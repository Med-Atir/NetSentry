//
// Created by mohammed on 13/11/2026.
//
#include "FeatureExtractor.h"
#include <fstream>
#include <cmath>
#include <algorithm>

FeatureExtractor::FeatureExtractor() {
    means_.fill(0.0f);
    stds_.fill(1.0f);
}

bool FeatureExtractor::load_scaler(const std::string& scaler_path) {
    std::ifstream file(scaler_path);
    if (!file.is_open()) {
        return false;
    }

    std::array<float, NUM_FEATURES> loaded_means{};
    std::array<float, NUM_FEATURES> loaded_stds{};

    // Expects 30 mean values followed by 30 std values (whitespace/newline separated)
    for (size_t i = 0; i < NUM_FEATURES; ++i) {
        if (!(file >> loaded_means[i])) {
            return false;
        }
    }
    for (size_t i = 0; i < NUM_FEATURES; ++i) {
        if (!(file >> loaded_stds[i])) {
            return false;
        }
        // Guard against constant features where std == 0
        if (std::abs(loaded_stds[i]) < 1e-12f) {
            loaded_stds[i] = 1.0f;
        }
    }

    means_ = loaded_means;
    stds_ = loaded_stds;
    has_scaler_ = true;
    return true;
}

FeatureVector FeatureExtractor::extract(
    const FlowKey& key,
    const FlowStats& stats,
    bool apply_scaling) const {

    std::array<float, NUM_FEATURES> f{};

    const uint64_t dur_us       = stats.duration_us();
    const double   dur_sec      = static_cast<double>(dur_us) / 1e6;
    const uint32_t fwd_pkts     = stats.get_fwd_packets();
    const uint32_t bwd_pkts     = stats.get_bwd_packets();
    const uint32_t tot_pkts     = stats.total_packets();
    const uint64_t fwd_bytes    = stats.get_fwd_bytes();
    const uint64_t bwd_bytes    = stats.get_bwd_bytes();
    const uint64_t tot_bytes    = stats.total_bytes();

    // 0: Flow Duration (microseconds)
    f[0] = static_cast<float>(dur_us);

    // 1-2: Directional Packet Counts
    f[1] = static_cast<float>(fwd_pkts);
    f[2] = static_cast<float>(bwd_pkts);

    // 3-4: Directional Byte Totals
    f[3] = static_cast<float>(fwd_bytes);
    f[4] = static_cast<float>(bwd_bytes);

    // 5-6: Forward Packet Length Max & Mean
    f[5] = static_cast<float>(stats.get_fwd_pkt_len_max());
    f[6] = (fwd_pkts > 0)
               ? static_cast<float>(static_cast<double>(fwd_bytes) / fwd_pkts)
               : 0.0f;

    // 7-8: Backward Packet Length Max & Mean
    f[7] = static_cast<float>(stats.get_bwd_pkt_len_max());
    f[8] = (bwd_pkts > 0)
               ? static_cast<float>(static_cast<double>(bwd_bytes) / bwd_pkts)
               : 0.0f;

    // 9: Flow Bytes/s
    f[9] = (dur_us > 0)
               ? static_cast<float>(static_cast<double>(tot_bytes) / dur_sec)
               : 0.0f;

    // 10-11: Bidirectional Flow IAT Mean & Std
    f[10] = static_cast<float>(stats.iat_mean());
    f[11] = static_cast<float>(stats.iat_std());

    // 12-13: Forward IAT Total & Std
    f[12] = static_cast<float>(stats.get_sum_fwd_iat_us());
    f[13] = static_cast<float>(stats.fwd_iat_std());

    // 14: Fwd Header Length
    f[14] = static_cast<float>(stats.get_fwd_header_bytes());

    // 15-16: Forward & Backward Packets/s
    f[15] = (dur_us > 0)
                ? static_cast<float>(static_cast<double>(fwd_pkts) / dur_sec)
                : 0.0f;
    f[16] = (dur_us > 0)
                ? static_cast<float>(static_cast<double>(bwd_pkts) / dur_sec)
                : 0.0f;

    // 17: Packet Length Std
    f[17] = static_cast<float>(stats.pkt_len_std());

    // 18-22: TCP Flag Counts (FIN, SYN, RST, PSH, ACK)
    f[18] = static_cast<float>(stats.get_fin_count());
    f[19] = static_cast<float>(stats.get_syn_count());
    f[20] = static_cast<float>(stats.get_rst_count());
    f[21] = static_cast<float>(stats.get_psh_count());
    f[22] = static_cast<float>(stats.get_ack_count());

    // 23: Down/Up Ratio (CICFlowMeter truncates to integer ratio)
    f[23] = (fwd_pkts > 0)
                ? static_cast<float>(bwd_pkts / fwd_pkts)
                : 0.0f;

    // 24: Avg Packet Size
    f[24] = (tot_pkts > 0)
                ? static_cast<float>(static_cast<double>(tot_bytes) / tot_pkts)
                : 0.0f;

    // 25-26: Initial TCP Window Sizes (-1 if non-TCP or unseen in that direction)
    f[25] = static_cast<float>(stats.get_init_fwd_win_bytes());
    f[26] = static_cast<float>(stats.get_init_bwd_win_bytes());

    // 27: Fwd Seg Size Min
    f[27] = static_cast<float>(stats.get_fwd_seg_size_min());

    // 28-29: Active Mean & Idle Mean
    f[28] = static_cast<float>(stats.active_mean());
    f[29] = static_cast<float>(stats.idle_mean());

    FeatureVector vec;
    vec.set_flow_key(key);
    vec.set_timestamp_us(stats.get_last_seen_us());
    vec.set_features(f);

    if (apply_scaling && has_scaler_) {
        normalize_in_place(vec);
    }

    return vec;
}

std::vector<FeatureVector> FeatureExtractor::extract_batch(
    const std::vector<std::pair<FlowKey, FlowStats>>& flows,
    bool apply_scaling) const {

    std::vector<FeatureVector> batch;
    batch.reserve(flows.size());

    for (const auto& [key, stats] : flows) {
        batch.emplace_back(extract(key, stats, apply_scaling));
    }

    return batch;
}

void FeatureExtractor::normalize_in_place(FeatureVector& vec) const {
    if (!has_scaler_) {
        return;
    }

    auto& feats = vec.mutable_features();
    for (size_t i = 0; i < NUM_FEATURES; ++i) {
        feats[i] = (feats[i] - means_[i]) / stds_[i];
    }
}