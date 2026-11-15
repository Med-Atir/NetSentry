//
// Created by mohammed on 15/11/2026.
//

#ifndef ALERTSPAGE_H
#define ALERTSPAGE_H

#include <QWidget>
#include <vector>
#include "Headers/Types.h"

namespace Ui {
    class AlertForm;
}

class AlertsPage : public QWidget {
    Q_OBJECT

public:
    explicit AlertsPage(QWidget *parent = nullptr);
    ~AlertsPage() override;

    void loadAlerts(const std::vector<AlertEvent> &alerts);

    signals:
        void clearAlertsRequested();

private slots:
    void onClearClicked();

private:
    Ui::AlertForm *ui;
};

#endif // ALERTSPAGE_H