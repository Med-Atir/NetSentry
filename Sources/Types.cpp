//
// Created by mohammed on 12/11/2026.
//

#include "../Headers/Types.h"

bool FlowKey::operator==(const FlowKey &t)const{
        return this->ip_a == t.ip_a && this->ip_b == t.ip_b && this->port_a == t.port_a && this->port_b == t.port_b && this->protocol == t.protocol;
}
void FlowStats::update(const PacketMetaData& pkt) {
    const uint64_t pkt_time   = pkt.get_timestamp_us();
    const uint32_t pkt_len    = pkt.get_packet_len();
    const uint32_t header_len = pkt.get_header_len();
    const uint8_t  proto      = pkt.get_protocol();

    constexpr uint64_t IDLE_THRESHOLD_US = 5'000'000;

    if (total_packets() == 0) {
        first_seen_us   = pkt_time;
        last_seen_us    = pkt_time;
        start_active_us = pkt_time;

        initiator_ip    = pkt.get_src_ip();
        initiator_port  = pkt.get_src_port();

        min_pkt_len     = static_cast<uint16_t>(pkt_len);
        max_pkt_len     = static_cast<uint16_t>(pkt_len);
    } else {
        const uint64_t iat = (pkt_time >= last_seen_us) ? (pkt_time - last_seen_us) : 0;

        min_iat_us     = std::min(min_iat_us, iat);
        max_iat_us     = std::max(max_iat_us, iat);
        sum_iat_us    += static_cast<double>(iat);
        sum_sq_iat_us += static_cast<double>(iat) * static_cast<double>(iat);

        if (iat > IDLE_THRESHOLD_US) {
            const uint64_t active_dur = (last_seen_us >= start_active_us)
                                            ? (last_seen_us - start_active_us)
                                            : 0;
            if (active_dur > 0) {
                sum_active_us += static_cast<double>(active_dur);
                ++active_count;
            }
            sum_idle_us += static_cast<double>(iat);
            ++idle_count;
            start_active_us = pkt_time;
        }

        if (pkt_time > last_seen_us) {
            last_seen_us = pkt_time;
        }
        min_pkt_len = std::min(min_pkt_len, static_cast<uint16_t>(pkt_len));
        max_pkt_len = std::max(max_pkt_len, static_cast<uint16_t>(pkt_len));
    }

    sum_pkt_len    += pkt_len;
    sum_sq_pkt_len += static_cast<double>(pkt_len) * static_cast<double>(pkt_len);

    const bool is_fwd = (pkt.get_src_ip() == initiator_ip && pkt.get_src_port() == initiator_port);

    if (is_fwd) {
        if (fwd_packets > 0 && pkt_time >= last_fwd_us) {
            const uint64_t fwd_iat = pkt_time - last_fwd_us;
            sum_fwd_iat_us    += static_cast<double>(fwd_iat);
            sum_sq_fwd_iat_us += static_cast<double>(fwd_iat) * static_cast<double>(fwd_iat);
        }
        last_fwd_us = pkt_time;

        ++fwd_packets;
        fwd_bytes        += pkt_len;
        fwd_header_bytes += header_len;
        fwd_pkt_len_max   = std::max(fwd_pkt_len_max, pkt_len);

        if (fwd_packets == 1) {
            fwd_seg_size_min = header_len;
        } else {
            fwd_seg_size_min = std::min(fwd_seg_size_min, header_len);
        }

        if (proto == 6 && init_fwd_win_bytes == -1) {
            init_fwd_win_bytes = static_cast<int32_t>(pkt.get_tcp_window());
        }
    } else {
        last_bwd_us = pkt_time;

        ++bwd_packets;
        bwd_bytes        += pkt_len;
        bwd_header_bytes += header_len;
        bwd_pkt_len_max   = std::max(bwd_pkt_len_max, pkt_len);

        if (proto == 6 && init_bwd_win_bytes == -1) {
            init_bwd_win_bytes = static_cast<int32_t>(pkt.get_tcp_window());
        }
    }
    if (proto == 6) {
        const uint8_t flags = pkt.get_tcp_flags();
        if (flags & 0x01) { ++fin_count; is_closed = true; } // FIN
        if (flags & 0x02) { ++syn_count; }                   // SYN
        if (flags & 0x04) { ++rst_count; is_closed = true; } // RST
        if (flags & 0x08) { ++psh_count; }                   // PSH
        if (flags & 0x10) { ++ack_count; }                   // ACK
        if (flags & 0x20) { ++urg_count; }                   // URG
    }
}
uint64_t FlowStats::duration_us()const{
        return last_seen_us - first_seen_us;
}
uint32_t FlowStats::total_packets() const{
        return fwd_packets + bwd_packets;
}
uint64_t FlowStats::total_bytes() const{
        return fwd_bytes + bwd_bytes;
}
double FlowStats::pkt_len_mean() const {
        if (total_packets() != 0) {
                return static_cast<double>(sum_pkt_len)/total_packets();
        }
        return 0.0;
}
double FlowStats::pkt_len_std() const {
        const double mean = pkt_len_mean();
        if (total_packets() != 0)
                return std::sqrt(std::max(0.0,(sum_sq_pkt_len/total_packets())-(mean*mean)));
        return 0.0;
}
double FlowStats::iat_mean() const {
        if (total_packets() > 1) {
                return static_cast<double>(sum_iat_us)/(total_packets() -1) ;
        }
        return 0.0;
}
double FlowStats::iat_std() const {
        const double mean = iat_mean();
        if (total_packets() >1)
                return std::sqrt(std::max(0.0,(sum_sq_iat_us/(total_packets()-1))-(mean*mean)));
        return 0.0;
}
double FlowStats::fwd_iat_std() const {
    if (fwd_packets > 1) {
        const double mean = sum_fwd_iat_us / (fwd_packets - 1);
        return std::sqrt(std::max(0.0, (sum_sq_fwd_iat_us / (fwd_packets - 1)) - (mean * mean)));
    }
    return 0.0;
}
double FlowStats::active_mean() const {
    return (active_count > 0) ? (sum_active_us / active_count) : 0.0;
}
double FlowStats::idle_mean() const {
    return (idle_count > 0) ? (sum_idle_us / idle_count) : 0.0;
}