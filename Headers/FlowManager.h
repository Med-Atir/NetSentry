//
// Created by mohammed on 13/11/2026.
//

#ifndef NETSENTRY_FLOWMANAGER_H
#define NETSENTRY_FLOWMANAGER_H
#include "Types.h"
#include <unordered_map>
#include <vector>
#include <utility>
#include <cstdint>
#include <mutex>
#include <tuple>

class FlowManager {
private:
    mutable std::mutex mutex_;
    std::unordered_map<FlowKey, FlowStats> active_flows_;
    uint64_t idle_timeout_us_ = 60'000'000;
    uint64_t active_timeout_us_ = 120'000'000;
    static FlowKey make_flow_key(const PacketMetaData& pkt);
public:
    void process_packet(const PacketMetaData& pkt);
    std::vector<std::pair<FlowKey, FlowStats>> evict_flows(uint64_t current_time_us);
    std::vector<std::pair<FlowKey, FlowStats>> flush_all();
    size_t active_flow_count() const;
};

#endif //NETSENTRY_FLOWMANAGER_H
