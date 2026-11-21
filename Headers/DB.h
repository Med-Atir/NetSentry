//
// Created by mohammed on 15/11/2026.
//

#ifndef NETSENTRY_DB_H
#define NETSENTRY_DB_H
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QString>
#include <QVariant>
#include "Types.h"
#include <vector>

class DB {
private:
    QSqlDatabase db;
public:
    DB();
    ~DB();
    bool connect(const QString& dbName);
    void disconnect();
    std::vector<AlertEvent> getAlerts(int limit = 500);
   bool addAlert(const AlertEvent&);
    bool clearAlerts();
};
#endif //NETSENTRY_DB_H
