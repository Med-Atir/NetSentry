//
// Created by mohammed on 13/11/2026.
//

#ifndef NETSENTRY_FEATUREEXTRACTOR_H
#define NETSENTRY_FEATUREEXTRACTOR_H
#include "Types.h"
#include <array>
#include <vector>
#include <utility>
#include <string>
#include <cstdint>

class FeatureExtractor {
private:
    std::array<float, NUM_FEATURES> means_{};
    std::array<float, NUM_FEATURES> stds_{};
    bool has_scaler_ = false;

public:
    FeatureExtractor();

    bool load_scaler(const std::string& scaler_path);
    bool is_scaler_loaded() const { return has_scaler_; }

    FeatureVector extract(const FlowKey& key, const FlowStats& stats, bool apply_scaling = false) const;

    std::vector<FeatureVector> extract_batch(
        const std::vector<std::pair<FlowKey, FlowStats>>& flows,
        bool apply_scaling = false) const;

    void normalize_in_place(FeatureVector& vec) const;
};

#endif // NETSENTRY_FEATUREEXTRACTOR_H