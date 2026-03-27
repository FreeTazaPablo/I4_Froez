set -e

   g++ -std=c++20 main.cpp -o main        $(pkg-config --cflags --libs gtk4 webkitgtk-6.0 glib-2.0 gio-2.0)        -lcrypto

chmod a+x main

echo "⑀ COMPILED ⑀"

