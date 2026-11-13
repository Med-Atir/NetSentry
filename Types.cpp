//
// Created by mohammed on 12/11/2026.
//

#include "Types.h"

bool FlowKey::operator==(const FlowKey &t)const{
        return this->ip_a == t.ip_a && this->ip_b == t.ip_b && this->port_a == t.port_a && this->port_b == t.port_b && this->protocol == t.protocol;
}
void FlowStats::update(const PacketMetaData& pkt) {
    const uint64_t ts = pkt.get_time_stamp_us();
    const uint16_t len = pkt.get_packet_len();
    const uint16_t payload_len = pkt.get_payload_len();
    const uint16_t header_len = (len >= payload_len) ? (len - payload_len) : 0;

    if (total_packets() == 0) {
        initiator_ip = pkt.get_src_ip();
        initiator_port = pkt.get_src_port();
        first_seen_us = ts;
        last_seen_us = ts;
    } else {
        const uint64_t iat = (ts >= last_seen_us) ? (ts - last_seen_us) : 0;
        min_iat_us = std::min(min_iat_us, iat);
        max_iat_us = std::max(max_iat_us, iat);
        sum_iat_us += static_cast<double>(iat);
        sum_sq_iat_us += static_cast<double>(iat) * static_cast<double>(iat);
    }

    min_pkt_len = std::min(min_pkt_len, len);
    max_pkt_len = std::max(max_pkt_len, len);
    sum_pkt_len += len;
    sum_sq_pkt_len += static_cast<double>(len) * static_cast<double>(len);

    if (pkt.get_src_ip() == initiator_ip && pkt.get_src_port() == initiator_port) {
        fwd_packets++;
        fwd_bytes += len;
        fwd_header_bytes += header_len;
        last_fwd_us = ts;
        if (payload_len > 0) {
            act_data_pkt_fwd++;
        }
    } else {
        bwd_packets++;
        bwd_bytes += len;
        bwd_header_bytes += header_len;
        last_bwd_us = ts;
    }

    if (pkt.get_protocol() == 6) {
        const uint8_t flags = pkt.get_tcp_flag();
        if (flags & 0x01) fin_count++;
        if (flags & 0x02) syn_count++;
        if (flags & 0x04) rst_count++;
        if (flags & 0x08) psh_count++;
        if (flags & 0x10) ack_count++;
        if (flags & 0x20) urg_count++;

        if ((flags & 0x01) || (flags & 0x04)) {
            is_closed = true;
        }
    }

    last_seen_us = ts;
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