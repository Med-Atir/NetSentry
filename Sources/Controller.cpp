//
// Created by mohammed on 16/11/2026.
//

#include "Headers/Controller.h"
#include "Headers/Types.h"

Controller::Controller(const std::string &dbName, const std::string &idsSupPath, const std::string &unsupPath,
    const std::string &idsSup_meta_path, const std::string &unSup_meta_path, QObject *parent)
:QObject(parent),Eng(idsSupPath,idsSup_meta_path,unsupPath,unSup_meta_path){
    db.connect(QString::fromStdString(dbName));
    connect(this, &Controller::alertDetected,
            this, &Controller::addAlertDB,
            Qt::QueuedConnection);
    Sniffer.set_flow_manager(&flowManager);
    Sniffer.set_packet_callback([this](const PacketMetaData& meta) {
        const uint64_t now_us = meta.get_timestamp_us();
        if (Last_evict_us_ == 0) {
            Last_evict_us_ = now_us;
        } else if (now_us > Last_evict_us_ && (now_us - Last_evict_us_) >= 1'000'000ULL) {
            Last_evict_us_ = now_us;
            auto expired = flowManager.evict_flows(now_us);
            if (!expired.empty()) {
                evaluate_flows(expired);
            }
        }

        const uint64_t pkts = Sniffer.packets_captured();
        if (pkts % 100 == 0) {
            emit statsUpdated(pkts, flowManager.active_flow_count(), Session_alerts.load());
        }
    });

    Sniffer.set_finished_callback([this]() {
        auto remaining = flowManager.flush_all();
        if (!remaining.empty()) {
            evaluate_flows(remaining);
        }
        emit statsUpdated(Sniffer.packets_captured(), 0, Session_alerts.load());
        emit captureFinished();
    });
}

Controller::~Controller() {
    Sniffer.stop();
   db.disconnect();
}

void Controller::evaluate_flows(const std::vector<std::pair<FlowKey, FlowStats>>& flows) {
    for (const auto& [key, stats] : flows) {
        FeatureVector fv = extractor.extract(key, stats, false);
        PredictionResult pred = Eng.predict(fv.get_features());
        if (pred.is_malicious) {
            Session_alerts++;
            AlertEvent alert = build_alert(key, stats, pred);
            emit alertDetected(alert);
            emit statsUpdated(Sniffer.packets_captured(), flowManager.active_flow_count(), Session_alerts.load());
        }
    }
}

AlertEvent Controller::build_alert(const FlowKey& key, const FlowStats& stats, const PredictionResult& pred) {
    AlertEvent alert;

    char src_buf[INET_ADDRSTRLEN]{};
    char dst_buf[INET_ADDRSTRLEN]{};
    uint32_t ip_a = key.get_ip_a();
    uint32_t ip_b = key.get_ip_b();
    inet_ntop(AF_INET, &ip_a, src_buf, sizeof(src_buf));
    inet_ntop(AF_INET, &ip_b, dst_buf, sizeof(dst_buf));

    alert.set_src_ip(src_buf);
    alert.set_dst_ip(dst_buf);
    alert.set_src_port(key.get_port_a());
    alert.set_dst_port(key.get_port_b());
    alert.set_protocol(key.get_protocol());
    alert.set_timestamp(stats.get_last_seen_us());
    alert.set_attack_type(pred.label);

    if (pred.engine_stage == "LGBM") {
        alert.set_confidence(pred.score);
        alert.set_anomaly_score(0.0f);
        alert.set_severity(pred.score >= 0.85f ? Severity::Critical : Severity::High);
    } else {
        alert.set_confidence(0.0f);
        alert.set_anomaly_score(pred.score);
        alert.set_severity(Severity::Medium);
    }
    alert.set_action("Logged");
    return alert;
}
std::vector<std::string> Controller::getInterfaces() {
    std::vector<std::string> vect;
    std::vector<InterfaceInfo> inter = this->Sniffer.liste_interfaces();
    for (auto const& i: inter) {
        vect.push_back(i.name);
    }
    return vect;
}

bool Controller::addAlertDB(const AlertEvent &e) {
    return db.addAlert(e);
}

bool Controller::clearAlertsDB() {
    return db.clearAlerts();
}

bool Controller::connectToDB(const QString &dbName) {
    return db.connect(dbName);
}

void Controller::disconnectFromDB() {
    return db.disconnect();
}

std::vector<AlertEvent> Controller::getAlerts(int limit) {
    return db.getAlerts(limit);
}

bool Controller::start_live(const std::string &iface, const std::string &bpf) {
    Session_alerts = 0;
    Last_evict_us_ = 0;
    flowManager.flush_all();
    return Sniffer.start_live(iface, bpf);
}

bool Controller::start_file(const std::string &path, const std::string &bpf) {
    Session_alerts = 0;
    Last_evict_us_ = 0;
    flowManager.flush_all();
    return Sniffer.start_pcap(path, bpf);
}
void Controller::stop() {
    Sniffer.stop();
    auto remaining = flowManager.flush_all();
    if (!remaining.empty()) {
        evaluate_flows(remaining);
    }
}