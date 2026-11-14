//
// Created by mohammed on 31/10/2026.
//

#ifndef NETSENTRY_SNIFFER_H
#define NETSENTRY_SNIFFER_H
#include "Types.h"
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/IpAddress.h>
#include <arpa/inet.h>
#include "FlowManager.h"

class PacketSniffer {
private:
    FlowManager* flow_manager_;
    std::function<void(const PacketMetaData&)> callback_;
    pcpp::PcapLiveDevice* live_device_;
    std::unique_ptr<pcpp::IFileReaderDevice> file_reader_;
    std::atomic<bool> running_;
    std::thread reader_thread_;
    std::atomic<uint64_t> packets_captured_;
    std::atomic<uint64_t> packets_parsed_;
    std::atomic<uint64_t> packets_ignored_;
    void static on_packet_arrived(pcpp::RawPacket* raw, pcpp::PcapLiveDevice* dev, void* cookie);
    void handle_raw_packet(pcpp::RawPacket* raw);
    void pcap_reader_loop();
public:
    using PacketCallback = std::function<void(const PacketMetaData&)>;
    std::string name;
    std::string description;
    std::string ipv4;
    ~PacketSniffer() {
        PacketSniffer::stop();
        delete live_device_;
    }
    PacketSniffer() {
        running_ = false;
        live_device_ = nullptr;
        file_reader_ = nullptr;
        packets_captured_ = 0;
        packets_parsed_ = 0;
        packets_ignored_ = 0;
    }
    static std::vector<InterfaceInfo> liste_interfaces();
    void set_packet_callback(PacketCallback cb){callback_ = cb;}
    bool start_live(const std::string& iface, const std::string& bpf = "");
    bool start_pcap(const std::string& path, const std::string& bpf);
    void stop();
    bool is_running() const noexcept;
    uint64_t packets_captured() const noexcept;
    uint64_t packets_parsed() const noexcept;
    uint64_t packets_ignored() const noexcept;
};
#endif //NETSENTRY_SNIFFER_H
