#include "widget.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    setvbuf(stdout, (char *)nullptr, _IONBF, 0);
    QApplication a(argc, argv);
    Widget w;
    w.show();
    return a.exec();
}
