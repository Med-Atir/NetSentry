//
// Created by mohammed on 15/11/2026.
//


#include <QApplication>
#include <QMetaType>
#include "Headers/MainWindow.h"
#include "Headers/Types.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("Net-Sentry");

    qRegisterMetaType<AlertEvent>("AlertEvent");

    MainWindow window;
    window.setWindowTitle("Net-Sentry — Network Intrusion Detection System");
    window.show();

    return app.exec();
}