//
// Created by mohammed on 13/11/2026.
//

#include "FlowManager.h"

FlowKey FlowManager::make_flow_key(const PacketMetaData &pkt) {
    FlowKey key;
    uint32_t src_ip = pkt.get_src_ip(),dst_ip = pkt.get_dst_ip();
    uint16_t src_port = pkt.get_src_port(),dst_port = pkt.get_dst_port();
    if (std::tie(src_ip,src_port) < std::tie(dst_ip,dst_port)) {
        key.set_ip_a(src_ip);
        key.set_port_a(src_port);
        key.set_ip_b(dst_ip);
        key.set_port_b(dst_port);
        key.set_protocol(pkt.get_protocol());
    }
    else {
        key.set_ip_b(src_ip);
        key.set_port_b(src_port);
        key.set_ip_a(dst_ip);
        key.set_port_a(dst_port);
        key.set_protocol(pkt.get_protocol());
    }
    return key;
}

size_t FlowManager::active_flow_count() const {
    return this->active_flows_.size();
}

void FlowManager::process_packet(const PacketMetaData &pkt) {
    FlowKey key = make_flow_key(pkt);
    active_flows_[key].update(pkt);
}

std::vector<std::pair<FlowKey, FlowStats> > FlowManager::evict_flows(uint64_t current_time_us) {
    std::vector<std::pair<FlowKey, FlowStats>> evicted;
    auto it = active_flows_.begin();
    while(it != active_flows_.end()) {
        const FlowStats& stats = it->second;
        if (stats.get_is_closed() || (current_time_us >= stats.get_last_seen_us() && (current_time_us - stats.get_last_seen_us()) >= idle_timeout_us_) || stats.duration_us() >= active_timeout_us_) {
            evicted.emplace_back(it->first, std::move(it->second));
            it = active_flows_.erase(it);
        }
        else {
            ++it;
        }
    }
    return evicted;
}

std::vector<std::pair<FlowKey, FlowStats> > FlowManager::flush_all() {
    std::vector<std::pair<FlowKey, FlowStats>> remaining;
    remaining.reserve(active_flows_.size());
    for (auto it = active_flows_.begin();it != active_flows_.end();++it) {
        remaining.emplace_back(it->first, std::move(it->second));
        }
    active_flows_.clear();
    return remaining;
}
