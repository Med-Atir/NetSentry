//
// Created by mohammed on 15/11/2026.
//

#ifndef FILECAPTUREPAGE_H
#define FILECAPTUREPAGE_H

#include <QWidget>
#include <cstdint>
#include "Headers/Types.h"

namespace Ui {
    class FileForm;
}

class FileCapturePage : public QWidget {
    Q_OBJECT

public:
    explicit FileCapturePage(QWidget *parent = nullptr);
    ~FileCapturePage() override;

    void updateCounters(uint64_t packets, uint64_t activeFlows, uint64_t sessionAlerts);
    void appendAlert(const AlertEvent &alert);
    void setCapturingState(bool running);

    signals:
        void startFileRequested(const QString &pcapFilePath);
    void stopFileRequested();

private slots:
    void onBrowseClicked();
    void onStartClicked();
    void onStopClicked();

private:
    Ui::FileForm *ui;
    QString selectedFilePath;
};

#endif // FILECAPTUREPAGE_H