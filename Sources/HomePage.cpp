//
// Created by mohammed on 15/11/2026.
//


#include "Headers/HomePage.h"
#include "Headers/HomePage.h"
#include "GUI/ui_home.h"

HomePage::HomePage(QWidget *parent)
    : QWidget(parent), ui(new Ui::HomeForm) {
    ui->setupUi(this);
}

HomePage::~HomePage() {
    delete ui;
}