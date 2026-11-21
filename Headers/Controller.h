//
// Created by mohammed on 16/11/2026.
//

#ifndef NETSENTRY_CONTROLLER_H
#define NETSENTRY_CONTROLLER_H
#include "DB.h"
#include "Engine.h"
#include "FeatureExtractor.h"
#include "FlowManager.h"
#include "Sniffer.h"
#include <QObject>
#include <atomic>
#include <cstdint>
#include <string>
#include <vector>
#include <utility>

class Controller : public QObject{
    Q_OBJECT
private:
    DB db;
    Engine Eng;
    FeatureExtractor extractor;
    FlowManager flowManager;
    PacketSniffer Sniffer;
    std::atomic<uint64_t> Session_alerts{0};
    uint64_t Last_evict_us_ = 0;
    void evaluate_flows(const std::vector<std::pair<FlowKey, FlowStats>>& flows);
    AlertEvent build_alert(const FlowKey& key, const FlowStats& stats, const PredictionResult& pred);
public:
    Controller(const std::string& dbName,const std::string& idsSupPath,const std::string& unsupPath, const std::string &idsSup_meta_path, const std::string &unSup_meta_path,QObject* parent = nullptr);
    ~Controller() override;
    std::vector<std::string> getInterfaces();
    bool connectToDB(const QString& dbName);
    void disconnectFromDB();
    std::vector<AlertEvent> getAlerts(int limit = 500);
    bool addAlertDB(const AlertEvent&);
    bool clearAlertsDB();
    bool start_live(const std::string& iface, const std::string& bpf = "");
    bool start_file(const std::string& path, const std::string& bpf = "");
    void stop();
    signals:
    void alertDetected(const AlertEvent &alert);
    void captureFinished();
    void statsUpdated(uint64_t packets, uint64_t activeFlows, uint64_t sessionAlerts);
};

#endif //NETSENTRY_CONTROLLER_H
