//
// Created by mohammed on 13/11/2026.
//
#include "../Headers/FeatureExtractor.h"
#include <fstream>
#include <cmath>
#include <algorithm>

FeatureExtractor::FeatureExtractor() {
    means_.fill(0.0f);
    stds_.fill(1.0f);
}

bool FeatureExtractor::load_scaler(const std::string& scaler_path) {//this method open and load the scaler; its the model we trained using pytorch and DL
    std::ifstream file(scaler_path);                                // we load the file then load the means and stds of the 30 features we have selected
    if (!file.is_open()) {
        return false;
    }

    std::array<float, NUM_FEATURES> loaded_means{};
    std::array<float, NUM_FEATURES> loaded_stds{};

    // expects 30 mean values followed by 30 std values
    for (size_t i = 0; i < NUM_FEATURES; ++i) {
        if (!(file >> loaded_means[i])) {
            return false;
        }
    }
    for (size_t i = 0; i < NUM_FEATURES; ++i) {
        if (!(file >> loaded_stds[i])) {
            return false;
        }
        // yk because of constants feature, std = 0
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

    std::vector<float> f(NUM_FEATURES, 0.0f);

    const uint64_t dur_us       = stats.duration_us();
    const double   dur_sec      = static_cast<double>(dur_us) / 1e6;
    const uint32_t fwd_pkts     = stats.get_fwd_packets();
    const uint32_t bwd_pkts     = stats.get_bwd_packets();
    const uint32_t tot_pkts     = stats.total_packets();
    const uint64_t fwd_bytes    = stats.get_fwd_bytes();
    const uint64_t bwd_bytes    = stats.get_bwd_bytes();
    const uint64_t tot_bytes    = stats.total_bytes();

    // flow duration by microsecond
    f[0] = static_cast<float>(dur_us);

    // directional paquet counts
    f[1] = static_cast<float>(fwd_pkts);
    f[2] = static_cast<float>(bwd_pkts);

    // directional byte totals
    f[3] = static_cast<float>(fwd_bytes);
    f[4] = static_cast<float>(bwd_bytes);

    // forward packet lenght max & mean
    f[5] = static_cast<float>(stats.get_fwd_pkt_len_max());
    f[6] = (fwd_pkts > 0)
               ? static_cast<float>(static_cast<double>(fwd_bytes) / fwd_pkts)
               : 0.0f;

    // backward packet lenght max & mean
    f[7] = static_cast<float>(stats.get_bwd_pkt_len_max());
    f[8] = (bwd_pkts > 0)
               ? static_cast<float>(static_cast<double>(bwd_bytes) / bwd_pkts)
               : 0.0f;

    // flow bytes
    f[9] = (dur_us > 0)
               ? static_cast<float>(static_cast<double>(tot_bytes) / dur_sec)
               : 0.0f;

    // bidirect flow iat mean & std
    f[10] = static_cast<float>(stats.iat_mean());
    f[11] = static_cast<float>(stats.iat_std());

    // forward iat total & std
    f[12] = static_cast<float>(stats.get_sum_fwd_iat_us());
    f[13] = static_cast<float>(stats.fwd_iat_std());

    // fwd header lenght
    f[14] = static_cast<float>(stats.get_fwd_header_bytes());

    // fwd bwd header packets
    f[15] = (dur_us > 0)
                ? static_cast<float>(static_cast<double>(fwd_pkts) / dur_sec)
                : 0.0f;
    f[16] = (dur_us > 0)
                ? static_cast<float>(static_cast<double>(bwd_pkts) / dur_sec)
                : 0.0f;

    // packet lenght std
    f[17] = static_cast<float>(stats.pkt_len_std());

    //tcp flags counts
    f[18] = static_cast<float>(stats.get_fin_count());
    f[19] = static_cast<float>(stats.get_syn_count());
    f[20] = static_cast<float>(stats.get_rst_count());
    f[21] = static_cast<float>(stats.get_psh_count());
    f[22] = static_cast<float>(stats.get_ack_count());

    // down and up ration
    f[23] = (fwd_pkts > 0)
                ? static_cast<float>(bwd_pkts) / fwd_pkts
                : 0.0f;

    // avg pacjet size
    f[24] = (tot_pkts > 0)
                ? static_cast<float>(static_cast<double>(tot_bytes) / tot_pkts)
                : 0.0f;

    // init tcp winodw size
    f[25] = static_cast<float>(stats.get_init_fwd_win_bytes());
    f[26] = static_cast<float>(stats.get_init_bwd_win_bytes());

    // fwd segmt size (min)
    f[27] = static_cast<float>(stats.get_fwd_seg_size_min());

    // active and idle mean
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