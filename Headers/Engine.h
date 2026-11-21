//
// Created by mohammed on 14/11/2026.
//

#ifndef NETSENTRY_ENGINE_H
#define NETSENTRY_ENGINE_H
#include <string>
#include <vector>
#include <memory>
#include <nlohmann/json.hpp>
#include <onnxruntime_cxx_api.h>
#include <cmath>
#include <algorithm>
#include <array>
#include <fstream>
struct PredictionResult {
    bool is_malicious;
    std::string label;
    float score;
    std::string engine_stage;
};

class Engine {
private:
    Ort::Env env_;
    Ort::SessionOptions session_options_;
    std::unique_ptr<Ort::Session> lgbm_session_;
    std::unique_ptr<Ort::Session> iforest_session_;
    Ort::MemoryInfo memory_info_ ;
    std::vector<std::string> class_labels_;
    std::vector<float> class_thresholds_ ;
    float anomaly_threshold_ ;
    size_t expected_features_ = 30;
    void load_lgbm_metadata(const std::string& json_path);
    void load_unsup_metadata(const std::string& json_path);
    std::vector<float> run_lightgbm(const std::vector<float>& features);
    float run_isolation_forest(const std::vector<float>& log_features);
public:
    Engine(const std::string &lgbm_model_path, const std::string &lgbm_meta_path, const std::string &iforest_model_path, const std::string &iforest_meta_path);
    PredictionResult predict(const std::vector<float>& features);
};
#endif //NETSENTRY_ENGINE_H