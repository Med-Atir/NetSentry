#ifndef FILECAPTUREPAGE_H
#define FILECAPTUREPAGE_H

#include <QWidget>
#include <cstdint>
#include "Headers/Types.h"
#include "Headers/Controller.h"

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
    void setController(Controller* controller);

private slots:
    void onBrowseClicked();
    void onStartClicked();
    void onStopClicked();
    void onCaptureFinished();

private:
    Ui::FileForm *ui;
    QString selectedFilePath;
    Controller *controller = nullptr;
};

#endif