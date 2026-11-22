//
// Created by mohammed on 14/11/2026.
//
#include "../Headers/Engine.h"

Engine::Engine(const std::string& lgbm_model_path,const std::string& lgbm_meta_path,const std::string& iforest_model_path,const std::string& iforest_meta_path)
      : env_(ORT_LOGGING_LEVEL_WARNING, "NetSentry"),
      memory_info_(Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault)){
     load_lgbm_metadata(lgbm_meta_path);
     load_unsup_metadata(iforest_meta_path);
    lgbm_session_ = std::make_unique<Ort::Session>(env_, lgbm_model_path.c_str(), session_options_);
    iforest_session_ = std::make_unique<Ort::Session>(env_, iforest_model_path.c_str(), session_options_);
}

void Engine::load_lgbm_metadata(const std::string &json_path) {
    std::ifstream file(json_path);
    if (!file.is_open()) {
        return;
    }
    nlohmann::json data = nlohmann::json::parse(file);
    for (const std::string& value : data["classes"]) {
        class_labels_.push_back(value);
    }
    for (const float& value : data["thresholds"]) {
        class_thresholds_.push_back(value);
    }
}

void Engine::load_unsup_metadata(const std::string &json_path) {
    std::ifstream file(json_path);
    if (!file.is_open()) {
        return;
    }
    nlohmann::json data = nlohmann::json::parse(file);
    anomaly_threshold_ = data["threshold"];
}

std::vector<float> Engine::run_lightgbm(const std::vector<float> &features) {
    std::array<int64_t, 2> tab = {1, 30};
    auto tensor = Ort::Value::CreateTensor<float>(memory_info_,const_cast<float*>(features.data()),features.size(),tab.data(),tab.size());
    Ort::AllocatorWithDefaultOptions allocator;
    auto index = lgbm_session_->GetInputNameAllocated(0,allocator);
    auto proba = lgbm_session_->GetOutputNameAllocated(1,allocator);
    std::array<const char*, 1> input_names = {index.get()};
    std::array<const char*, 1> output_names = {proba.get()};
    auto tensorTabs = lgbm_session_->Run(Ort::RunOptions{nullptr},input_names.data(),&tensor,1,output_names.data(),1);
    auto probabilites = tensorTabs[0].GetTensorMutableData<float>();
    auto taille = class_labels_.size();
    return std::vector<float>(probabilites, probabilites + taille);
}

float Engine::run_isolation_forest(const std::vector<float> &log_features) {
    std::array<int64_t, 2> tab = {1, 30};
    auto tensor = Ort::Value::CreateTensor<float>(memory_info_,const_cast<float*>(log_features.data()),log_features.size(),tab.data(),tab.size());
    Ort::AllocatorWithDefaultOptions allocator;
    auto index = iforest_session_->GetInputNameAllocated(0,allocator);
    auto proba = iforest_session_->GetOutputNameAllocated(1,allocator);
    std::array<const char*, 1> input_names = {index.get()};
    std::array<const char*, 1> output_names = {proba.get()};
    auto tensorTabs = iforest_session_->Run(Ort::RunOptions{nullptr},input_names.data(),&tensor,1,output_names.data(),1);
    auto probabilites = tensorTabs[0].GetTensorMutableData<float>();
    return probabilites[0];
}

PredictionResult Engine::predict(const std::vector<float> &features) {
    std::vector<float> lgbm = run_lightgbm(features);

    for (size_t i = 1; i < class_labels_.size(); i++) {
        if (lgbm[i] >= class_thresholds_[i]) {
            PredictionResult p;
            p.score = lgbm[i];
            p.engine_stage = "LGBM";
            p.is_malicious = true;
            p.label = class_labels_[i];
            return p;
        }
    }

    if (lgbm[0] >= benign_gate_) {
        PredictionResult p;
        p.score = lgbm[0];
        p.engine_stage = "LGBM";
        p.is_malicious = false;
        p.label = "Benign";
        return p;
    }

    std::vector<float> log_features;
    log_features.reserve(features.size());
    for (auto feat : features) {
        log_features.push_back(std::log1p(std::max(feat, 0.0f)));
    }
    float iforest = run_isolation_forest(log_features);
    if (iforest < anomaly_threshold_) {
        PredictionResult p;
        p.score = iforest;
        p.engine_stage = "IsolationForest";
        p.is_malicious = true;
        p.label = "ZERO-Day";
        return p;
    }

    PredictionResult p;
    p.score = lgbm[0];
    p.engine_stage = "Cascade";
    p.is_malicious = false;
    p.label = "Benign";
    return p;
}
