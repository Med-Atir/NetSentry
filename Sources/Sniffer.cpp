//
// Created by mohammed on 31/10/2026.
//

#include "../Headers/Sniffer.h"

std::vector<InterfaceInfo> PacketSniffer::liste_interfaces() {
    std::vector<InterfaceInfo> vect;
    const std::vector<pcpp::PcapLiveDevice*>& tab = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
    vect.reserve(tab.size());
    for (auto inter: tab) {
        InterfaceInfo element;
        element.name = inter->getName();
        element.description = inter->getDesc();
        if (inter->getIPv4Address() != pcpp::IPv4Address::Zero)
        element.ipv4 = inter->getIPv4Address().toString();
        vect.push_back(element);
    }
    return vect;
}

bool PacketSniffer::start_live(const std::string &iface, const std::string &bpf) {
    stop();
    live_device_ = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(iface);
    if (!live_device_)
        return false;
    if (!live_device_->open()) {
        live_device_ = nullptr;
        return false;
    }
    if (!bpf.empty()) {
        if (!live_device_->setFilter(bpf)){
            live_device_->close();
            live_device_ = nullptr;
            return false;
        }
    }
    packets_captured_ = 0;
    packets_parsed_= 0;
    packets_ignored_ = 0;
    running_ = true;
    if (!live_device_->startCapture(on_packet_arrived, this)) {
        live_device_->close();
        live_device_ = nullptr;
        running_ = false;
        return false;
    }
    return true;
}

bool PacketSniffer::start_pcap(const std::string &path, const std::string &bpf) {
    stop();
    file_reader_.reset(pcpp::IFileReaderDevice::getReader(path));
    if (!file_reader_)
        return false;
    if (!file_reader_->open()) {
        file_reader_ = nullptr;
        return false;
    }
    if (!bpf.empty()) {
        if (!file_reader_->setFilter(bpf)){
            file_reader_->close();
            file_reader_ = nullptr;
            return false;
        }
    }
    packets_captured_ = 0;
    packets_parsed_= 0;
    packets_ignored_ = 0;
    running_ = true;
    try {
        reader_thread_ = std::thread(&PacketSniffer::pcap_reader_loop, this);
    } catch (const std::system_error&){
        file_reader_->close();
        file_reader_ = nullptr;
        running_ = false;
        return false;
    }
    return true;
}

void PacketSniffer::pcap_reader_loop() {
    pcpp::RawPacket raw_packet;
    while (running_.load() && file_reader_->getNextPacket(raw_packet)) {
        handle_raw_packet(&raw_packet);
    }
    running_ = false;
    file_reader_->close();
}

void PacketSniffer::stop() {
    running_ = false;
    if (reader_thread_.joinable())
        reader_thread_.join();
    if (live_device_) {
        live_device_->stopCapture();
        live_device_->close();
        live_device_ = nullptr;
    }
    if (file_reader_) {
        file_reader_->close();
        file_reader_.reset();
    }
}

void PacketSniffer::handle_raw_packet(pcpp::RawPacket* raw) {
    if (!raw) {
        return;
    }
    packets_captured_++;
    pcpp::Packet parsed(raw);
    auto* ipv4 = parsed.getLayerOfType<pcpp::IPv4Layer>();
    if (!ipv4) {
        packets_ignored_++;
        return;
    }
    auto* tcp = parsed.getLayerOfType<pcpp::TcpLayer>();
    auto* udp = parsed.getLayerOfType<pcpp::UdpLayer>();
    if (!tcp && !udp) {
        packets_ignored_++;
        return;
    }
    PacketMetaData pack;
    timespec ts = raw->getPacketTimeStamp();
    uint64_t timestamp_us = static_cast<uint64_t>(ts.tv_sec) * 1'000'000ULL +
                            static_cast<uint64_t>(ts.tv_nsec) / 1'000ULL;
    pack.set_timestamp_us(timestamp_us);
    pack.set_src_ip(ipv4->getSrcIPAddress().getIPv4().toInt());
    pack.set_dst_ip(ipv4->getDstIPAddress().getIPv4().toInt());
    pack.set_packet_len(static_cast<uint16_t>(ipv4->getDataLen()));

    if (tcp) {
        const pcpp::tcphdr* tcp_hdr = tcp->getTcpHeader();
        pack.set_protocol(6);
        pack.set_src_port(tcp->getSrcPort());
        pack.set_dst_port(tcp->getDstPort());
        pack.set_header_len(static_cast<uint32_t>(tcp->getHeaderLen()));
        pack.set_payload_len(static_cast<uint32_t>(tcp->getLayerPayloadSize()));

        uint8_t flags = 0;
        if (tcp_hdr->finFlag) flags |= 0x01;
        if (tcp_hdr->synFlag) flags |= 0x02;
        if (tcp_hdr->rstFlag) flags |= 0x04;
        if (tcp_hdr->pshFlag) flags |= 0x08;
        if (tcp_hdr->ackFlag) flags |= 0x10;
        if (tcp_hdr->urgFlag) flags |= 0x20;
        pack.set_tcp_flags(flags);

        pack.set_tcp_window(static_cast<int16_t>(ntohs(tcp_hdr->windowSize)));
    } else {
        pack.set_protocol(17);
        pack.set_src_port(udp->getSrcPort());
        pack.set_dst_port(udp->getDstPort());
        pack.set_header_len(static_cast<uint32_t>(udp->getHeaderLen()));
        pack.set_payload_len(static_cast<uint32_t>(udp->getLayerPayloadSize()));

        pack.set_tcp_flags(0);
        pack.set_tcp_window(-1);
    }
    packets_parsed_++;
    if (flow_manager_) {
        flow_manager_->process_packet(pack);
    }
}
void PacketSniffer::on_packet_arrived(pcpp::RawPacket *raw, pcpp::PcapLiveDevice *dev, void *cookie) {
    (void)dev;
    auto* self = static_cast<PacketSniffer*>(cookie);
    if (self && self->running_.load() && raw)
        self->handle_raw_packet(raw);
}

void PacketSniffer::set_flow_manager(FlowManager *fm) {
    flow_manager_ = fm;
}

bool PacketSniffer::is_running() const noexcept {
    return running_;
}

uint64_t PacketSniffer::packets_captured() const noexcept {
    return packets_captured_;
}

uint64_t PacketSniffer::packets_ignored() const noexcept {
    return packets_ignored_;
}

uint64_t PacketSniffer::packets_parsed() const noexcept {
    return packets_parsed_;
}
