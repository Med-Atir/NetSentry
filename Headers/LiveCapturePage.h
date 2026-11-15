//
// Created by mohammed on 15/11/2026.
//

#ifndef LIVECAPTUREPAGE_H
#define LIVECAPTUREPAGE_H

#include <QWidget>
#include <QStringList>
#include <cstdint>
#include "Headers/Types.h"

namespace Ui {
    class LiveForm;
}

class LiveCapturePage : public QWidget {
    Q_OBJECT

public:
    explicit LiveCapturePage(QWidget *parent = nullptr);
    ~LiveCapturePage() override;

    void setInterfaces(const QStringList &interfaces);
    void updateCounters(uint64_t packets, uint64_t activeFlows, uint64_t sessionAlerts);
    void appendAlert(const AlertEvent &alert);
    void setCapturingState(bool running);

    signals:
        void startRequested(const QString &interfaceName);
    void stopRequested();

private slots:
    void onStartClicked();
    void onStopClicked();

private:
    Ui::LiveForm *ui;
};

#endif // LIVECAPTUREPAGE_H
