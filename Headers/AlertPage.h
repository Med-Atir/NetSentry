//
// Created by mohammed on 15/11/2026.
//

#ifndef ALERTSPAGE_H
#define ALERTSPAGE_H

#include <QWidget>
#include <vector>
#include "Headers/Controller.h"
#include "Headers/Types.h"

namespace Ui {
    class AlertForm;
}

class AlertsPage : public QWidget {
    Q_OBJECT

public:
    explicit AlertsPage(QWidget *parent = nullptr);
    ~AlertsPage() override;
    void setController(Controller* controller);


    void loadAlerts();

    signals:
        void clearAlertsRequested();

private slots:
    void onClearClicked();
    void onrefreshClicked();

private:
    Ui::AlertForm *ui;
    Controller *controller = nullptr;
};

#endif // ALERTSPAGE_H