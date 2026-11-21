//
// Created by mohammed on 15/11/2026.
//


#include "Headers/LiveCapturePage.h"
#include "Headers/Engine.h"
#include "GUI/ui_live_capture.h"
#include "Headers/Types.h"
#include <QDateTime>
#include <QHeaderView>
#include <QTableWidgetItem>
#include "Headers/Controller.h"
#include "Headers/Sniffer.h"
#include <QString>


LiveCapturePage::LiveCapturePage(QWidget *parent)
    : QWidget(parent), ui(new Ui::LiveForm) {
    ui->setupUi(this);

    ui->stopcap->setEnabled(false);
    ui->tableAlerts->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

    connect(ui->startcap, &QPushButton::clicked, this, &LiveCapturePage::onStartClicked);
    connect(ui->stopcap, &QPushButton::clicked, this, &LiveCapturePage::onStopClicked);
}

LiveCapturePage::~LiveCapturePage() {
    delete ui;
}

void LiveCapturePage::setInterfaces() {
    if (!controller) return;
    QStringList vect;
    for (const auto& i : controller->getInterfaces()) {
        vect.append(QString::fromStdString(i));
    }
    ui->interface_2->clear();
    ui->interface_2->addItems(vect);
}

void LiveCapturePage::updateCounters(uint64_t packets, uint64_t activeFlows, uint64_t sessionAlerts) {
    ui->packets->setText(QString::number(packets));
    ui->flows->setText(QString::number(activeFlows));
    ui->alerts->setText(QString::number(sessionAlerts));
}

void LiveCapturePage::setCapturingState(bool running) {
    ui->startcap->setEnabled(!running);
    ui->interface_2->setEnabled(!running);
    ui->stopcap->setEnabled(running);
}

void LiveCapturePage::onStartClicked() {
    const QString iface = ui->interface_2->currentText();
    if (!controller || iface.isEmpty()) {
        return;
    }
    ui->tableAlerts->setRowCount(0);
    updateCounters(0, 0, 0);
    setCapturingState(true);
    if (!controller->start_live(iface.toStdString())) {
        setCapturingState(false);
    }
}

void LiveCapturePage::onStopClicked() {
    if (!controller) return;
    setCapturingState(false);
    controller->stop();
}

void LiveCapturePage::appendAlert(const AlertEvent &alert) {
    const int row = ui->tableAlerts->rowCount();
    ui->tableAlerts->insertRow(row);

    const QString timeStr = QDateTime::fromMSecsSinceEpoch(
        static_cast<qint64>(alert.get_timestamp_us() / 1000))
        .toString("yyyy-MM-dd HH:mm:ss");
    const float displayScore = (alert.get_confidence() > 0.0f)
    ? alert.get_confidence()
    : alert.get_anomaly_score();
    ui->tableAlerts->setItem(row, 7, new QTableWidgetItem(QString::number(displayScore, 'f', 2)));

    ui->tableAlerts->setItem(row, 0, new QTableWidgetItem(timeStr));
    ui->tableAlerts->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(alert.get_src_ip())));
    ui->tableAlerts->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(alert.get_dst_ip())));
    ui->tableAlerts->setItem(row, 3, new QTableWidgetItem(QString::number(alert.get_src_port())));
    ui->tableAlerts->setItem(row, 4, new QTableWidgetItem(QString::number(alert.get_dst_port())));
    ui->tableAlerts->setItem(row, 5, new QTableWidgetItem(QString::number(alert.get_protocol())));
    ui->tableAlerts->setItem(row, 6, new QTableWidgetItem(QString::fromStdString(alert.get_attack_type())));
    ui->tableAlerts->setItem(row, 8, new QTableWidgetItem(QString::fromStdString(severity_to_string(alert.get_severity()))));
    ui->tableAlerts->scrollToBottom();
}
void LiveCapturePage::setController(Controller* ctrl) {
    if (!ctrl) return;
    controller = ctrl;

    setInterfaces();
    connect(controller, &Controller::alertDetected,
            this, &LiveCapturePage::appendAlert,
            static_cast<Qt::ConnectionType>(Qt::QueuedConnection | Qt::UniqueConnection));

    connect(controller, &Controller::statsUpdated,
            this, &LiveCapturePage::updateCounters,
            static_cast<Qt::ConnectionType>(Qt::QueuedConnection | Qt::UniqueConnection));
}