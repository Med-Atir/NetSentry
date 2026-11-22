//
// Created by mohammed on 15/11/2026.
//

#include <QApplication>
#include <QMetaType>

#include "Headers/Types.h"
#include "Headers/Controller.h"
#include "Headers/MainWindow.h"

int main(int argc, char *argv[]) {
    qputenv("QT_QPA_PLATFORMTHEME", "generic");
    qputenv("QT_QPA_PLATFORM", "xcb");

    QApplication app(argc, argv);
    QApplication::setStyle("fusion");
    qRegisterMetaType<AlertEvent>("AlertEvent");
    std::string supPath = "/home/mohammed/Study/Projets/NetSentry/Models/ids_lightgbm.onnx";
    std::string unsupPath = "/home/mohammed/Study/Projets/NetSentry/Models/isolation_forest.onnx";
    std::string MetasupPath = "/home/mohammed/Study/Projets/NetSentry/Models/ids_metadata.json";
    std::string MetaUnsupPath = "/home/mohammed/Study/Projets/NetSentry/Models/unsup_metadata.json";
    std::string dbName = "/home/mohammed/Study/Projets/NetSentry/Database/ids";
    Controller controller(dbName,supPath,unsupPath,MetasupPath,MetaUnsupPath);

    MainWindow window;
    window.setController(&controller);
    window.setWindowTitle("Net-Sentry: Network Intrusion Detection System");
    window.show();

    return app.exec();
}