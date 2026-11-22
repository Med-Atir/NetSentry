//
// Created by mohammed on 15/11/2026.
//


#include "Headers/DB.h"

DB::DB() {
    if (QSqlDatabase::contains(QSqlDatabase::defaultConnection)) {
        db = QSqlDatabase::database(QSqlDatabase::defaultConnection);
    } else {
        db = QSqlDatabase::addDatabase("QSQLITE");
    }
}

DB::~DB() {
    disconnect();
}

bool DB::connect(const QString& dbName) {
    db.setDatabaseName(dbName);

    if (!db.open()) {
        qWarning() << "DB open error:" << db.lastError().text();
        return false;
    }
    qWarning() << "Succes : Connecte a la base de donnees";
    return true;
}

void DB::disconnect() {
    if (db.isOpen()) {
        db.close();
        qDebug() << "Base de donnees deconnectee.";
    }
}

bool DB::addAlert(const AlertEvent &alert) {
    if (!db.isOpen()) {
        qWarning() << "DB is not open in addAlert";
        return false;
    }
    QSqlQuery requete;
    requete.prepare("INSERT INTO alerts(timestamp_us,src_ip,dst_ip,src_port,dst_port,protocol,attack_type,confidence,anomaly_score,severity,action_taken)"
                    "VALUES (:time,:sip,:dip,:sport,:dport,:protocol,:type,:conf,:score,:sev,:action)");
    requete.bindValue(":time",static_cast<qint64>(alert.get_timestamp_us()));
    requete.bindValue(":sip",QString::fromStdString(alert.get_src_ip()));
    requete.bindValue(":dip",QString::fromStdString(alert.get_dst_ip()));
    requete.bindValue(":sport",static_cast<int>(alert.get_src_port()));
    requete.bindValue(":dport",static_cast<int>(alert.get_dst_port()));
    requete.bindValue(":protocol",static_cast<int>(alert.get_protocol()));
    requete.bindValue(":type",QString::fromStdString(alert.get_attack_type()));
    requete.bindValue(":conf",alert.get_confidence());
    requete.bindValue(":score",alert.get_anomaly_score());
    requete.bindValue(":sev",QString::fromStdString(severity_to_string(alert.get_severity())));
    requete.bindValue(":action",QString::fromStdString(alert.get_action()));
    if (requete.exec()) {
        return true;
    }
    qWarning() << "DB insert error:" << requete.lastError().text();
    return false;
}

bool DB::clearAlerts() {
    QSqlQuery query;
    query.prepare("DELETE FROM alerts");
    if (query.exec())
        return true;
    qDebug() << "Erreur: " << query.lastError().text();
    return false;
}

std::vector<AlertEvent> DB::getAlerts(int limit) {
    std::vector<AlertEvent> alerts;
    QSqlQuery query(db);
    query.prepare("SELECT * FROM alerts "
                  "ORDER BY timestamp_us DESC LIMIT :limit");
    query.bindValue(":limit",limit);
    if (query.exec()) {
        while (query.next()){
           AlertEvent event;
            event.set_timestamp(query.value("timestamp_us").toULongLong());
            event.set_src_ip(query.value("src_ip").toString().toStdString());
            event.set_dst_ip(query.value("dst_ip").toString().toStdString());
            event.set_src_port(query.value("src_port").toInt());
            event.set_dst_port(query.value("dst_port").toInt());
            event.set_protocol(query.value("protocol").toInt());
            event.set_action(query.value("action_taken").toString().toStdString());
            event.set_confidence(query.value("confidence").toFloat());
            event.set_anomaly_score(query.value("anomaly_score").toFloat());
            event.set_attack_type(query.value("attack_type").toString().toStdString());
            event.set_severity(string_to_severity(query.value("severity").toString().toStdString()));
            alerts.push_back(event);
        }
    }
    else {
        qWarning() << "DB select error:" << query.lastError().text();
    }
    query.finish();
    return alerts;
}
