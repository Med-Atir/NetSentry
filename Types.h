//
// Created by mohammed on 12/11/2026.
//

#ifndef NETSENTRY_TYPES_H
#define NETSENTRY_TYPES_H
#include <functional>
#include <cstdint>
#include <cmath>
#include <algorithm>
#include <array>
#include <string>
constexpr size_t NUM_FEATURES = 30;
class PacketMetaData {
private:
    uint64_t time_stamp_us = 0;
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;
    uint16_t packet_len = 0;
    uint16_t payload_len = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t protocol = 0;
    uint8_t tcp_flag = 0;
    uint16_t tcp_window = 0;
    uint16_t header_len = 0;
public:
    uint16_t get_tcp_window ()const{return tcp_window;};
    uint16_t get_header_len()const{return header_len;}
    uint32_t get_src_ip() const {
        return src_ip;
    }
    uint32_t get_dst_ip() const {
        return dst_ip;
    }
    uint16_t get_src_port() const {
        return src_port;
    }
    uint16_t get_dst_port() const{
        return dst_port;
    }
    uint8_t get_protocol() const{
        return protocol;
    }
    uint8_t get_tcp_flags()const {
        return tcp_flag;
    }
    uint16_t get_packet_len() const{
        return packet_len;
    }
    uint16_t get_payload_len()const {
        return payload_len;
    }
    uint64_t get_timestamp_us() const{
        return time_stamp_us;
    }
    void set_src_ip(uint32_t n) {
        src_ip = n;
    }
    void set_dst_ip(uint32_t n) {
        dst_ip = n;
    }
    void set_src_port(uint16_t n) {
        src_port = n;
    }
    void set_dst_port(uint16_t n) {
        dst_port = n;
    }
    void set_protocol(uint8_t n) {
        protocol = n;
    }
    void set_tcp_flags(uint8_t n) {
        tcp_flag = n;
    }
    void set_packet_len(uint16_t n) {
        packet_len = n;
    }
    void set_payload_len(uint16_t n) {
        payload_len = n;
    }
    void set_timestamp_us(uint64_t n) {
        time_stamp_us = n;
    }
    void set_tcp_window (uint16_t s) {
        tcp_window = s;
    }
    void set_header_len(uint16_t s) {
        header_len = s;
    }

};
class FlowKey {
private:
    uint32_t ip_a = 0;
    uint32_t ip_b =0;
    uint16_t port_a = 0;
    uint16_t port_b = 0;
    uint8_t protocol = 0;
public:
    uint32_t get_ip_a()const {
        return ip_a;
    }
    uint32_t get_ip_b()const {
        return ip_b;
    }
    uint16_t get_port_a()const {
        return port_a;
    }
    uint16_t get_port_b()const {
        return port_b;
    }
    uint16_t get_protocol()const {
        return protocol;
    }
    void set_ip_a(uint32_t n) {
        ip_a = n;
    }
    void set_ip_b(uint32_t n){
        ip_b = n;
    }
    void set_port_a(uint16_t n){
        port_a = n;
    }
    void set_port_b(uint16_t n){
        port_b = n;
    }
    void set_protocol(uint8_t n){
        protocol = n;
    }
    bool operator==(const FlowKey&)const;
};
namespace std {
    template <>
    struct hash<FlowKey> {
        size_t operator()(const FlowKey& k) const noexcept {
            size_t seed = 0;
            auto hash_combine = [&seed](auto val) {
                seed ^= std::hash<decltype(val)>{}(val) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
            };

            hash_combine(k.get_ip_a());
            hash_combine(k.get_ip_b());
            hash_combine(k.get_port_a());
            hash_combine(k.get_port_b());
            hash_combine(k.get_protocol());

            return seed;
        }
    };
}
class FlowStats {
private:
    uint32_t initiator_ip = 0;
    uint16_t initiator_port = 0;
    uint64_t first_seen_us = 0;
    uint64_t last_seen_us = 0;
    uint64_t last_fwd_us = 0;
    uint64_t last_bwd_us = 0;
    bool is_closed = false;

    uint32_t fwd_packets = 0;
    uint32_t bwd_packets = 0;
    uint32_t fwd_pkt_len_max = 0;
    uint32_t bwd_pkt_len_max = 0;
    uint64_t fwd_bytes = 0;
    uint64_t bwd_bytes = 0;
    uint64_t fwd_header_bytes = 0;
    uint64_t bwd_header_bytes = 0;
    uint32_t fwd_seg_size_min = 0;

    int32_t init_fwd_win_bytes = -1;
    int32_t init_bwd_win_bytes = -1;

    uint16_t min_pkt_len = UINT16_MAX;
    uint16_t max_pkt_len = 0;
    uint64_t sum_pkt_len = 0;
    double sum_sq_pkt_len = 0.0;

    uint64_t min_iat_us = UINT64_MAX;
    uint64_t max_iat_us = 0;
    double sum_iat_us = 0.0;
    double sum_sq_iat_us = 0.0;

    double sum_fwd_iat_us = 0.0;
    double sum_sq_fwd_iat_us = 0.0;

    uint64_t start_active_us = 0;
    double sum_active_us = 0.0;
    uint32_t active_count = 0;
    double sum_idle_us = 0.0;
    uint32_t idle_count = 0;

    uint16_t syn_count = 0;
    uint16_t ack_count = 0;
    uint16_t fin_count = 0;
    uint16_t rst_count = 0;
    uint16_t psh_count = 0;
    uint16_t urg_count = 0;

public:
    uint32_t get_initiator_ip() const { return initiator_ip; }
    uint16_t get_initiator_port() const { return initiator_port; }
    uint64_t get_first_seen_us() const { return first_seen_us; }
    uint64_t get_last_seen_us() const { return last_seen_us; }
    uint64_t get_last_fwd_us() const { return last_fwd_us; }
    uint64_t get_last_bwd_us() const { return last_bwd_us; }
    bool get_is_closed() const { return is_closed; }

    uint32_t get_fwd_packets() const { return fwd_packets; }
    uint32_t get_bwd_packets() const { return bwd_packets; }
    uint32_t get_fwd_pkt_len_max() const { return fwd_pkt_len_max; }
    uint32_t get_bwd_pkt_len_max() const { return bwd_pkt_len_max; }
    uint64_t get_fwd_bytes() const { return fwd_bytes; }
    uint64_t get_bwd_bytes() const { return bwd_bytes; }
    uint64_t get_fwd_header_bytes() const { return fwd_header_bytes; }
    uint64_t get_bwd_header_bytes() const { return bwd_header_bytes; }
    uint32_t get_fwd_seg_size_min() const { return fwd_seg_size_min; }

    int32_t get_init_fwd_win_bytes() const { return init_fwd_win_bytes; }
    int32_t get_init_bwd_win_bytes() const { return init_bwd_win_bytes; }

    uint16_t get_min_pkt_len() const { return min_pkt_len; }
    uint16_t get_max_pkt_len() const { return max_pkt_len; }
    uint64_t get_sum_pkt_len() const { return sum_pkt_len; }
    double get_sum_sq_pkt_len() const { return sum_sq_pkt_len; }

    uint64_t get_min_iat_us() const { return min_iat_us; }
    uint64_t get_max_iat_us() const { return max_iat_us; }
    double get_sum_iat_us() const { return sum_iat_us; }
    double get_sum_sq_iat_us() const { return sum_sq_iat_us; }

    double get_sum_fwd_iat_us() const { return sum_fwd_iat_us; }
    double get_sum_sq_fwd_iat_us() const { return sum_sq_fwd_iat_us; }

    double get_sum_active_us() const { return sum_active_us; }
    uint32_t get_active_count() const { return active_count; }
    double get_sum_idle_us() const { return sum_idle_us; }
    uint32_t get_idle_count() const { return idle_count; }

    uint16_t get_syn_count() const { return syn_count; }
    uint16_t get_ack_count() const { return ack_count; }
    uint16_t get_fin_count() const { return fin_count; }
    uint16_t get_rst_count() const { return rst_count; }
    uint16_t get_psh_count() const { return psh_count; }
    uint16_t get_urg_count() const { return urg_count; }

    FlowStats() = default;
    void update(const PacketMetaData& pkt);

    uint64_t duration_us() const;
    uint32_t total_packets() const;
    uint64_t total_bytes() const;
    double pkt_len_mean() const;
    double pkt_len_std() const;
    double iat_mean() const;
    double iat_std() const;
    double fwd_iat_std() const;
    double active_mean() const;
    double idle_mean() const;
};
class FeatureVector {
private:
    FlowKey flow_key_;
    uint64_t timestamp_us_ = 0;
    std::array<float, NUM_FEATURES> features_{};

public:
    const FlowKey& get_flow_key() const { return flow_key_; }
    void set_flow_key(const FlowKey& key) { flow_key_ = key; }

    uint64_t get_timestamp_us() const { return timestamp_us_; }
    void set_timestamp_us(uint64_t ts) { timestamp_us_ = ts; }

    const std::array<float, NUM_FEATURES>& get_features() const { return features_; }
    std::array<float, NUM_FEATURES>& mutable_features() { return features_; }
    void set_features(const std::array<float, NUM_FEATURES>& feats) { features_ = feats; }
};
enum class Severity : uint8_t {
        Low = 0,
        Medium = 1,
        High = 2,
        Critical = 3
    };

inline std::string severity_to_string(Severity severity) {
        switch (severity) {
                case Severity::Low:      return "LOW";
                case Severity::Medium:   return "MEDIUM";
                case Severity::High:     return "HIGH";
                case Severity::Critical: return "CRITICAL";
                default:                 return "UNKNOWN";
        }
}
class AlertEvent {
private:
        std::string src_ip;
        std::string dst_ip;
        uint16_t src_port = 0;
        uint16_t dst_port = 0;
        uint8_t protocol = 0;
        std::string attack_type;
        float confidence = 0.0f;
        std::string action_taken;
        Severity severity = Severity::Low;
        uint64_t time_stamp_us = 0;
        float anomaly_score = 0.0f;
public:
        std::string get_src_ip()const{return src_ip;}
        std::string get_dst_ip()const{return dst_ip;}
        uint16_t get_src_port()const{return src_port;}
        uint16_t get_dst_port()const{return dst_port;}
        uint8_t get_protocol()const{return protocol;}
        std::string get_attack_type()const{return attack_type;}
        std::string get_action()const{return action_taken;}
        float get_confidence()const{return confidence;}
        Severity get_severity()const{return severity;}
        uint64_t get_timestamp_us()const{return time_stamp_us;}
        float get_anomaly_score()const{return anomaly_score;}

        void set_timestamp(const uint64_t& s){time_stamp_us = s;}
        void set_anomaly_score(float s){anomaly_score = s;}
        void set_protocol(uint8_t n) { protocol = n; }
        void set_src_ip(const std::string& s){src_ip = s;}
        void set_dst_ip(const std::string& s){dst_ip = s;}
        void set_action(const std::string& s){action_taken = s;}
        void set_attack_type(const std::string& s){attack_type = s;}
        void set_confidence(const float& s){confidence = s;}
        void set_src_port(const uint16_t& s){src_port = s;}
        void set_dst_port(const uint16_t& s){dst_port = s;}
        void set_severity(const Severity& s){severity = s;}

};
#endif //NETSENTRY_TYPES_H
