//
// Created by mohammed on 15/11/2026.
//


#include "Headers/LiveCapturePage.h"
#include "Headers/LiveCapturePage.h"
#include "GUI/ui_live_capture.h"
#include "Headers/Types.h"
#include <QDateTime>
#include <QHeaderView>
#include <QTableWidgetItem>

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

void LiveCapturePage::setInterfaces(const QStringList &interfaces) {
    ui->interface_2->clear();
    ui->interface_2->addItems(interfaces);
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
    if (iface.isEmpty()) {
        return;
    }
    ui->tableAlerts->setRowCount(0);
    updateCounters(0, 0, 0);
    setCapturingState(true);
    emit startRequested(iface);
}

void LiveCapturePage::onStopClicked() {
    setCapturingState(false);
    emit stopRequested();
}

void LiveCapturePage::appendAlert(const AlertEvent &alert) {
    const int row = ui->tableAlerts->rowCount();
    ui->tableAlerts->insertRow(row);

    const QString timeStr = QDateTime::fromMSecsSinceEpoch(
        static_cast<qint64>(alert.get_timestamp_us() / 1000))
        .toString("yyyy-MM-dd HH:mm:ss");

    ui->tableAlerts->setItem(row, 0, new QTableWidgetItem(timeStr));
    ui->tableAlerts->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(alert.get_src_ip())));
    ui->tableAlerts->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(alert.get_dst_ip())));
    ui->tableAlerts->setItem(row, 3, new QTableWidgetItem(QString::number(alert.get_src_port())));
    ui->tableAlerts->setItem(row, 4, new QTableWidgetItem(QString::number(alert.get_dst_port())));
    ui->tableAlerts->setItem(row, 5, new QTableWidgetItem(QString::number(alert.get_protocol())));
    ui->tableAlerts->setItem(row, 6, new QTableWidgetItem(QString::fromStdString(alert.get_attack_type())));
    ui->tableAlerts->setItem(row, 7, new QTableWidgetItem(QString::number(alert.get_confidence(), 'f', 2)));
    ui->tableAlerts->setItem(row, 8, new QTableWidgetItem(QString::fromStdString(severity_to_string(alert.get_severity()))));

    ui->tableAlerts->scrollToBottom();
}