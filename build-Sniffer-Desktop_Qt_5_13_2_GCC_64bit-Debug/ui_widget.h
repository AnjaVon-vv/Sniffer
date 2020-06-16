/********************************************************************************
** Form generated from reading UI file 'widget.ui'
**
** Created by: Qt User Interface Compiler version 5.13.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_WIDGET_H
#define UI_WIDGET_H

#include <QtCore/QVariant>
#include <QtGui/QIcon>
#include <QtWidgets/QApplication>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QTextBrowser>
#include <QtWidgets/QToolButton>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_Widget
{
public:
    QGridLayout *gridLayout;
    QTreeWidget *treeWidget;
    QWidget *widgetStatus;
    QVBoxLayout *verticalLayout_2;
    QLabel *label;
    QTextBrowser *textBrowser;
    QWidget *widgetSniffer;
    QGridLayout *gridLayout_2;
    QWidget *widget_3;
    QVBoxLayout *verticalLayout_4;
    QLabel *label_8;
    QLineEdit *filterLine;
    QSpacerItem *verticalSpacer;
    QWidget *widget_2;
    QVBoxLayout *verticalLayout_3;
    QLabel *label_4;
    QLineEdit *inputLineEdit;
    QToolButton *startBtn;
    QSpacerItem *horizontalSpacer;
    QWidget *widgetClearBtn;
    QVBoxLayout *verticalLayout;
    QPushButton *clrB;
    QPushButton *clrF;
    QPushButton *clrT;
    QToolButton *stopBtn;
    QWidget *widgetStatus_2;
    QGridLayout *gridLayout_3;
    QWidget *widget;
    QHBoxLayout *horizontalLayout_2;
    QLabel *label_6;
    QLineEdit *flowLine;
    QLabel *label_7;
    QLabel *label_5;
    QTableWidget *tableWidget;

    void setupUi(QWidget *Widget)
    {
        if (Widget->objectName().isEmpty())
            Widget->setObjectName(QString::fromUtf8("Widget"));
        Widget->resize(1300, 900);
        QSizePolicy sizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(Widget->sizePolicy().hasHeightForWidth());
        Widget->setSizePolicy(sizePolicy);
        Widget->setMaximumSize(QSize(1300, 900));
        QIcon icon;
        icon.addFile(QString::fromUtf8(":/logo.png"), QSize(), QIcon::Normal, QIcon::Off);
        Widget->setWindowIcon(icon);
        Widget->setStyleSheet(QString::fromUtf8("background-color: rgb(35, 35, 35);"));
        gridLayout = new QGridLayout(Widget);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        treeWidget = new QTreeWidget(Widget);
        QTreeWidgetItem *__qtreewidgetitem = new QTreeWidgetItem();
        __qtreewidgetitem->setText(1, QString::fromUtf8("2"));
        __qtreewidgetitem->setText(0, QString::fromUtf8("1"));
        treeWidget->setHeaderItem(__qtreewidgetitem);
        treeWidget->setObjectName(QString::fromUtf8("treeWidget"));
        treeWidget->setStyleSheet(QString::fromUtf8("background-color: rgb(51, 51, 51);\n"
"font: 13pt \"Cantarell\";\n"
"color: rgb(255, 255, 243);"));
        treeWidget->setColumnCount(2);

        gridLayout->addWidget(treeWidget, 1, 0, 1, 3);

        widgetStatus = new QWidget(Widget);
        widgetStatus->setObjectName(QString::fromUtf8("widgetStatus"));
        verticalLayout_2 = new QVBoxLayout(widgetStatus);
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        label = new QLabel(widgetStatus);
        label->setObjectName(QString::fromUtf8("label"));
        label->setStyleSheet(QString::fromUtf8("font: 13pt \"Cantarell\";\n"
"color: rgb(224, 227, 218);"));

        verticalLayout_2->addWidget(label);

        textBrowser = new QTextBrowser(widgetStatus);
        textBrowser->setObjectName(QString::fromUtf8("textBrowser"));
        textBrowser->setEnabled(true);
        QSizePolicy sizePolicy1(QSizePolicy::Expanding, QSizePolicy::Fixed);
        sizePolicy1.setHorizontalStretch(0);
        sizePolicy1.setVerticalStretch(0);
        sizePolicy1.setHeightForWidth(textBrowser->sizePolicy().hasHeightForWidth());
        textBrowser->setSizePolicy(sizePolicy1);
        textBrowser->setMinimumSize(QSize(0, 330));
        textBrowser->setMaximumSize(QSize(1000, 16777215));
        textBrowser->setAutoFillBackground(false);
        textBrowser->setStyleSheet(QString::fromUtf8("background-color: rgb(51, 51, 51);\n"
"font: 13pt \"Cantarell\";\n"
"color: rgb(255, 255, 243);"));

        verticalLayout_2->addWidget(textBrowser);


        gridLayout->addWidget(widgetStatus, 0, 0, 1, 1);

        widgetSniffer = new QWidget(Widget);
        widgetSniffer->setObjectName(QString::fromUtf8("widgetSniffer"));
        QSizePolicy sizePolicy2(QSizePolicy::Preferred, QSizePolicy::Fixed);
        sizePolicy2.setHorizontalStretch(0);
        sizePolicy2.setVerticalStretch(0);
        sizePolicy2.setHeightForWidth(widgetSniffer->sizePolicy().hasHeightForWidth());
        widgetSniffer->setSizePolicy(sizePolicy2);
        widgetSniffer->setMinimumSize(QSize(0, 370));
        gridLayout_2 = new QGridLayout(widgetSniffer);
        gridLayout_2->setObjectName(QString::fromUtf8("gridLayout_2"));
        widget_3 = new QWidget(widgetSniffer);
        widget_3->setObjectName(QString::fromUtf8("widget_3"));
        verticalLayout_4 = new QVBoxLayout(widget_3);
        verticalLayout_4->setObjectName(QString::fromUtf8("verticalLayout_4"));
        label_8 = new QLabel(widget_3);
        label_8->setObjectName(QString::fromUtf8("label_8"));
        QSizePolicy sizePolicy3(QSizePolicy::Preferred, QSizePolicy::Maximum);
        sizePolicy3.setHorizontalStretch(0);
        sizePolicy3.setVerticalStretch(0);
        sizePolicy3.setHeightForWidth(label_8->sizePolicy().hasHeightForWidth());
        label_8->setSizePolicy(sizePolicy3);
        label_8->setStyleSheet(QString::fromUtf8("color: rgb(255,255,243);"));

        verticalLayout_4->addWidget(label_8);

        filterLine = new QLineEdit(widget_3);
        filterLine->setObjectName(QString::fromUtf8("filterLine"));
        QSizePolicy sizePolicy4(QSizePolicy::Expanding, QSizePolicy::Preferred);
        sizePolicy4.setHorizontalStretch(0);
        sizePolicy4.setVerticalStretch(0);
        sizePolicy4.setHeightForWidth(filterLine->sizePolicy().hasHeightForWidth());
        filterLine->setSizePolicy(sizePolicy4);
        filterLine->setStyleSheet(QString::fromUtf8("color: rgb(255, 255, 243);\n"
"background-color: rgb(51, 51, 51);"));
        filterLine->setMaxLength(20);
        filterLine->setCursorPosition(0);

        verticalLayout_4->addWidget(filterLine);

        verticalSpacer = new QSpacerItem(20, 100, QSizePolicy::Minimum, QSizePolicy::Fixed);

        verticalLayout_4->addItem(verticalSpacer);


        gridLayout_2->addWidget(widget_3, 1, 0, 2, 1);

        widget_2 = new QWidget(widgetSniffer);
        widget_2->setObjectName(QString::fromUtf8("widget_2"));
        QSizePolicy sizePolicy5(QSizePolicy::Preferred, QSizePolicy::Minimum);
        sizePolicy5.setHorizontalStretch(0);
        sizePolicy5.setVerticalStretch(0);
        sizePolicy5.setHeightForWidth(widget_2->sizePolicy().hasHeightForWidth());
        widget_2->setSizePolicy(sizePolicy5);
        widget_2->setMinimumSize(QSize(0, 70));
        widget_2->setMaximumSize(QSize(16777215, 70));
        verticalLayout_3 = new QVBoxLayout(widget_2);
        verticalLayout_3->setObjectName(QString::fromUtf8("verticalLayout_3"));
        label_4 = new QLabel(widget_2);
        label_4->setObjectName(QString::fromUtf8("label_4"));
        sizePolicy3.setHeightForWidth(label_4->sizePolicy().hasHeightForWidth());
        label_4->setSizePolicy(sizePolicy3);
        label_4->setStyleSheet(QString::fromUtf8("color: rgb(255,255,243);"));

        verticalLayout_3->addWidget(label_4);

        inputLineEdit = new QLineEdit(widget_2);
        inputLineEdit->setObjectName(QString::fromUtf8("inputLineEdit"));
        QSizePolicy sizePolicy6(QSizePolicy::Expanding, QSizePolicy::Maximum);
        sizePolicy6.setHorizontalStretch(0);
        sizePolicy6.setVerticalStretch(0);
        sizePolicy6.setHeightForWidth(inputLineEdit->sizePolicy().hasHeightForWidth());
        inputLineEdit->setSizePolicy(sizePolicy6);
        inputLineEdit->setStyleSheet(QString::fromUtf8("color: rgb(255, 255, 243);\n"
"background-color: rgb(51, 51, 51);"));
        inputLineEdit->setMaxLength(20);
        inputLineEdit->setCursorPosition(0);

        verticalLayout_3->addWidget(inputLineEdit);


        gridLayout_2->addWidget(widget_2, 0, 0, 1, 1);

        startBtn = new QToolButton(widgetSniffer);
        startBtn->setObjectName(QString::fromUtf8("startBtn"));
        QSizePolicy sizePolicy7(QSizePolicy::Expanding, QSizePolicy::Expanding);
        sizePolicy7.setHorizontalStretch(0);
        sizePolicy7.setVerticalStretch(0);
        sizePolicy7.setHeightForWidth(startBtn->sizePolicy().hasHeightForWidth());
        startBtn->setSizePolicy(sizePolicy7);
        startBtn->setCursor(QCursor(Qt::PointingHandCursor));
        startBtn->setStyleSheet(QString::fromUtf8("color: rgb(165, 147, 224);\n"
"font: 75 23pt \"URW Bookman L\";"));

        gridLayout_2->addWidget(startBtn, 0, 2, 1, 1);

        horizontalSpacer = new QSpacerItem(30, 20, QSizePolicy::Fixed, QSizePolicy::Minimum);

        gridLayout_2->addItem(horizontalSpacer, 0, 1, 1, 1);

        widgetClearBtn = new QWidget(widgetSniffer);
        widgetClearBtn->setObjectName(QString::fromUtf8("widgetClearBtn"));
        QSizePolicy sizePolicy8(QSizePolicy::Preferred, QSizePolicy::MinimumExpanding);
        sizePolicy8.setHorizontalStretch(0);
        sizePolicy8.setVerticalStretch(0);
        sizePolicy8.setHeightForWidth(widgetClearBtn->sizePolicy().hasHeightForWidth());
        widgetClearBtn->setSizePolicy(sizePolicy8);
        widgetClearBtn->setMinimumSize(QSize(0, 0));
        widgetClearBtn->setStyleSheet(QString::fromUtf8("font: 75 15pt \"C059\";"));
        verticalLayout = new QVBoxLayout(widgetClearBtn);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        clrB = new QPushButton(widgetClearBtn);
        clrB->setObjectName(QString::fromUtf8("clrB"));
        sizePolicy7.setHeightForWidth(clrB->sizePolicy().hasHeightForWidth());
        clrB->setSizePolicy(sizePolicy7);
        clrB->setCursor(QCursor(Qt::PointingHandCursor));
        clrB->setStyleSheet(QString::fromUtf8("color: rgb(224, 227, 218);"));

        verticalLayout->addWidget(clrB);

        clrF = new QPushButton(widgetClearBtn);
        clrF->setObjectName(QString::fromUtf8("clrF"));
        sizePolicy7.setHeightForWidth(clrF->sizePolicy().hasHeightForWidth());
        clrF->setSizePolicy(sizePolicy7);
        clrF->setCursor(QCursor(Qt::PointingHandCursor));
        clrF->setStyleSheet(QString::fromUtf8("color: rgb(224, 227, 218);"));

        verticalLayout->addWidget(clrF);

        clrT = new QPushButton(widgetClearBtn);
        clrT->setObjectName(QString::fromUtf8("clrT"));
        sizePolicy7.setHeightForWidth(clrT->sizePolicy().hasHeightForWidth());
        clrT->setSizePolicy(sizePolicy7);
        clrT->setCursor(QCursor(Qt::PointingHandCursor));
        clrT->setStyleSheet(QString::fromUtf8("color: rgb(224, 227, 218);"));

        verticalLayout->addWidget(clrT);


        gridLayout_2->addWidget(widgetClearBtn, 2, 2, 1, 1);

        stopBtn = new QToolButton(widgetSniffer);
        stopBtn->setObjectName(QString::fromUtf8("stopBtn"));
        sizePolicy1.setHeightForWidth(stopBtn->sizePolicy().hasHeightForWidth());
        stopBtn->setSizePolicy(sizePolicy1);
        stopBtn->setMinimumSize(QSize(0, 70));
        stopBtn->setMaximumSize(QSize(16777215, 70));
        stopBtn->setCursor(QCursor(Qt::PointingHandCursor));
        stopBtn->setStyleSheet(QString::fromUtf8("color: rgb(224, 227, 218);"));

        gridLayout_2->addWidget(stopBtn, 1, 2, 1, 1);


        gridLayout->addWidget(widgetSniffer, 0, 2, 1, 1);

        widgetStatus_2 = new QWidget(Widget);
        widgetStatus_2->setObjectName(QString::fromUtf8("widgetStatus_2"));
        gridLayout_3 = new QGridLayout(widgetStatus_2);
        gridLayout_3->setObjectName(QString::fromUtf8("gridLayout_3"));
        widget = new QWidget(widgetStatus_2);
        widget->setObjectName(QString::fromUtf8("widget"));
        QSizePolicy sizePolicy9(QSizePolicy::Fixed, QSizePolicy::Minimum);
        sizePolicy9.setHorizontalStretch(0);
        sizePolicy9.setVerticalStretch(0);
        sizePolicy9.setHeightForWidth(widget->sizePolicy().hasHeightForWidth());
        widget->setSizePolicy(sizePolicy9);
        widget->setMinimumSize(QSize(10, 0));
        widget->setLayoutDirection(Qt::RightToLeft);
        widget->setStyleSheet(QString::fromUtf8(""));
        horizontalLayout_2 = new QHBoxLayout(widget);
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        label_6 = new QLabel(widget);
        label_6->setObjectName(QString::fromUtf8("label_6"));
        label_6->setStyleSheet(QString::fromUtf8("color: rgb(255, 255, 243);"));

        horizontalLayout_2->addWidget(label_6);

        flowLine = new QLineEdit(widget);
        flowLine->setObjectName(QString::fromUtf8("flowLine"));
        sizePolicy.setHeightForWidth(flowLine->sizePolicy().hasHeightForWidth());
        flowLine->setSizePolicy(sizePolicy);
        flowLine->setMinimumSize(QSize(30, 0));
        flowLine->setMaximumSize(QSize(70, 16777215));
        flowLine->setStyleSheet(QString::fromUtf8("color: rgb(251, 209, 75);"));

        horizontalLayout_2->addWidget(flowLine);

        label_7 = new QLabel(widget);
        label_7->setObjectName(QString::fromUtf8("label_7"));
        label_7->setStyleSheet(QString::fromUtf8("font: bold;\n"
"color: rgb(255, 255, 243);"));

        horizontalLayout_2->addWidget(label_7);


        gridLayout_3->addWidget(widget, 2, 0, 1, 1);

        label_5 = new QLabel(widgetStatus_2);
        label_5->setObjectName(QString::fromUtf8("label_5"));
        label_5->setStyleSheet(QString::fromUtf8("font: 13pt \"Cantarell\";\n"
"color: rgb(224, 227, 218);"));

        gridLayout_3->addWidget(label_5, 0, 0, 1, 1);

        tableWidget = new QTableWidget(widgetStatus_2);
        tableWidget->setObjectName(QString::fromUtf8("tableWidget"));
        sizePolicy1.setHeightForWidth(tableWidget->sizePolicy().hasHeightForWidth());
        tableWidget->setSizePolicy(sizePolicy1);
        tableWidget->setMinimumSize(QSize(0, 273));
        tableWidget->setStyleSheet(QString::fromUtf8("color: rgb(224, 227, 218);"));

        gridLayout_3->addWidget(tableWidget, 1, 0, 1, 1);


        gridLayout->addWidget(widgetStatus_2, 0, 1, 1, 1);


        retranslateUi(Widget);

        QMetaObject::connectSlotsByName(Widget);
    } // setupUi

    void retranslateUi(QWidget *Widget)
    {
        Widget->setWindowTitle(QCoreApplication::translate("Widget", "Von's Sniffer", nullptr));
        label->setText(QCoreApplication::translate("Widget", "\347\212\266\346\200\201 ", nullptr));
        label_8->setText(QCoreApplication::translate("Widget", "\350\257\267\350\276\223\345\205\245\350\277\207\346\273\244\350\247\204\345\210\231\357\274\232", nullptr));
        filterLine->setText(QString());
        label_4->setText(QCoreApplication::translate("Widget", "\350\257\267\350\276\223\345\205\245\346\212\223\345\214\205\346\225\260\351\207\217\357\274\232\357\274\210\351\273\230\350\256\244\345\276\252\347\216\257\346\212\223\345\217\226\357\274\211", nullptr));
        inputLineEdit->setText(QString());
        startBtn->setText(QCoreApplication::translate("Widget", "START", nullptr));
        clrB->setText(QCoreApplication::translate("Widget", "clear status screen", nullptr));
        clrF->setText(QCoreApplication::translate("Widget", "clear flow table", nullptr));
        clrT->setText(QCoreApplication::translate("Widget", "clear packet info screen", nullptr));
        stopBtn->setText(QCoreApplication::translate("Widget", "STOP", nullptr));
        label_6->setText(QCoreApplication::translate("Widget", "Bytes", nullptr));
        label_7->setText(QCoreApplication::translate("Widget", "\346\200\273\346\265\201\351\207\217\357\274\232", nullptr));
        label_5->setText(QCoreApplication::translate("Widget", "\346\265\201\351\207\217\347\273\237\350\256\241", nullptr));
    } // retranslateUi

};

namespace Ui {
    class Widget: public Ui_Widget {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_WIDGET_H
