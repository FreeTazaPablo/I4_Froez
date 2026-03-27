/*
 *  Nombre del Proyecto - I4 Froez
 *  Copyright (C) [2026] FreeTazaPablo
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org>.
 */

// VERSION BETA 0.8 — Perfiles aislados por modo de red
// Compilar:
//   g++ -std=c++20 main.cpp -o main \
//       $(pkg-config --cflags --libs gtk4 webkitgtk-6.0 glib-2.0 gio-2.0) \
//       -lcrypto

#include <gtk/gtk.h>
#include <webkit/webkit.h>
#include <glib.h>
#include <gio/gio.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

#include <string>
#include <vector>
#include <functional>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <ctime>
#include <cmath>
#include <cassert>
#include <memory>
#include <cstring>
#include <filesystem>
#include <unordered_map>
#include <optional>

// ─── nlohmann/json (header-only, incluir aparte o usar submodule) ──────────
// Si no tienes nlohmann instalado: sudo apt install nlohmann-json3-dev
#include <nlohmann/json.hpp>
using json = nlohmann::json;

// ─── Identificadores de perfil ────────────────────────────────────────────────
// Cada modo de red es un perfil completamente independiente:
//   ~/.local/share/i4froez/profiles/clearnet/
//   ~/.local/share/i4froez/profiles/tor/
//   ~/.local/share/i4froez/profiles/i2p/
// Cada perfil tiene su propio salt, verifier, historial, marcadores y ajustes.
// La clave maestra en RAM se limpia completamente al cambiar de perfil.

enum class BrowserProfile { CLEARNET, TOR, I2P };

static BrowserProfile g_activeProfile = BrowserProfile::CLEARNET;

static std::string profileDirName(BrowserProfile p) {
    switch (p) {
        case BrowserProfile::TOR:  return "tor";
        case BrowserProfile::I2P:  return "i2p";
        default:                   return "clearnet";
    }
}

// Nombre para mostrar al usuario — capitalización correcta
static std::string profileDisplayName(BrowserProfile p) {
    switch (p) {
        case BrowserProfile::TOR:  return "Tor";
        case BrowserProfile::I2P:  return "I2P";
        default:                   return "Clearnet";
    }
}

// Alias para compatibilidad con el resto del código que usa profileName()
static std::string profileName(BrowserProfile p) { return profileDirName(p); }

static BrowserProfile profileFromString(const std::string& s) {
    if (s == "tor")  return BrowserProfile::TOR;
    if (s == "i2p")  return BrowserProfile::I2P;
    return BrowserProfile::CLEARNET;
}

// Helper: máscara de todos los tipos de datos de sitio web a limpiar
static constexpr WebKitWebsiteDataTypes ALL_WEBSITE_DATA =
    static_cast<WebKitWebsiteDataTypes>(
        WEBKIT_WEBSITE_DATA_COOKIES              |
        WEBKIT_WEBSITE_DATA_DISK_CACHE           |
        WEBKIT_WEBSITE_DATA_MEMORY_CACHE         |
        WEBKIT_WEBSITE_DATA_SESSION_STORAGE      |
        WEBKIT_WEBSITE_DATA_LOCAL_STORAGE        |
        WEBKIT_WEBSITE_DATA_INDEXEDDB_DATABASES  |
        WEBKIT_WEBSITE_DATA_OFFLINE_APPLICATION_CACHE
    );

// ─── Base64 (usamos GLib) ──────────────────────────────────────────────────

static std::string base64_encode(const std::vector<uint8_t>& data) {
    gchar* enc = g_base64_encode(data.data(), data.size());
    std::string result(enc);
    g_free(enc);
    return result;
}

static std::vector<uint8_t> base64_decode(const std::string& s) {
    gsize out_len = 0;
    guchar* dec = g_base64_decode(s.c_str(), &out_len);
    std::vector<uint8_t> result(dec, dec + out_len);
    g_free(dec);
    return result;
}

// ─── Rutas de datos ────────────────────────────────────────────────────────

static std::string dataDir() {
    return std::string(g_get_home_dir()) + "/.local/share/i4froez";
}
// Directorio base para todos los perfiles
static std::string profilesDir() {
    return dataDir() + "/profiles";
}
// Directorio del perfil activo
static std::string profileDir(BrowserProfile p) {
    return profilesDir() + "/" + profileName(p);
}
static std::string profileDir() { return profileDir(g_activeProfile); }

static std::string historyFile()   { return profileDir() + "/history.json";   }
static std::string bookmarksFile() { return profileDir() + "/bookmarks.json"; }
static std::string saltFile()      { return profileDir() + "/.salt";          }
static std::string settingsFile()  { return profileDir() + "/settings.json";  }
static std::string verifierFile()  { return profileDir() + "/.verifier";      }

// ─── Cifrado AES-256-GCM + PBKDF2 ─────────────────────────────────────────
// Formato en disco: base64( IV[12] || TAG[16] || CIPHERTEXT )
// La clave se deriva con PBKDF2-HMAC-SHA256 (200 000 iteraciones).
// Versión anterior usaba XOR simple — los ficheros viejos se migran automáticamente.

static std::vector<uint8_t> getOrCreateSalt() {
    std::ifstream f(saltFile(), std::ios::binary);
    if (f) {
        std::vector<uint8_t> salt(32);
        f.read(reinterpret_cast<char*>(salt.data()), 32);
        if (f.gcount() == 32) return salt;
    }
    std::vector<uint8_t> salt(32);
    RAND_bytes(salt.data(), 32);
    std::ofstream of(saltFile(), std::ios::binary);
    of.write(reinterpret_cast<const char*>(salt.data()), 32);
    return salt;
}

static std::vector<uint8_t> g_masterKey; // 32 bytes para AES-256

// Muestra un diálogo modal para pedir la contraseña maestra al usuario.
// Bloquea hasta que el usuario confirma. Si cancela, sale de la aplicación.
// ─── Diálogo de contraseña maestra ────────────────────────────────────────
// Acepta un mensaje opcional que se muestra en rojo (para errores de auth).
// Si el usuario cancela, retorna nullopt. Nunca llama g_application_quit
// (eso lo hace el llamador para evitar problemas con el event loop).
static std::optional<std::string> askMasterPassword(GtkApplication* app,
                                     const std::string& extraMsg = "") {
    std::string profileLabel = profileDisplayName(g_activeProfile);
    std::string winTitle = "I4 Froez [" + profileLabel + "] — Contraseña maestra";

    GtkWidget* dialog = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(dialog), winTitle.c_str());
    gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);
    gtk_window_set_resizable(GTK_WINDOW(dialog), FALSE);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 380, -1);

    GtkWindow* appWin = gtk_application_get_active_window(app);
    if (appWin) gtk_window_set_transient_for(GTK_WINDOW(dialog), appWin);

    GtkBox* vbox = GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL, 12));
    gtk_widget_set_margin_top   (GTK_WIDGET(vbox), 24);
    gtk_widget_set_margin_bottom(GTK_WIDGET(vbox), 24);
    gtk_widget_set_margin_start (GTK_WIDGET(vbox), 24);
    gtk_widget_set_margin_end   (GTK_WIDGET(vbox), 24);

    GtkLabel* lbl = GTK_LABEL(gtk_label_new(
        ("Perfil: " + profileLabel + "\n"
         "Introduce tu contraseña maestra\n"
         "para descifrar historial y marcadores:").c_str()));
    gtk_label_set_justify(lbl, GTK_JUSTIFY_CENTER);
    gtk_box_append(vbox, GTK_WIDGET(lbl));

    // Mensaje de error/aviso (solo si se pasa)
    if (!extraMsg.empty()) {
        GtkLabel* errLbl = GTK_LABEL(gtk_label_new(extraMsg.c_str()));
        gtk_label_set_justify(errLbl, GTK_JUSTIFY_CENTER);
        GtkCssProvider* ep = gtk_css_provider_new();
        gtk_css_provider_load_from_string(ep,
            ".auth-error { color: #f38ba8; font-weight: bold; font-size: 12px; }");
        gtk_style_context_add_provider_for_display(
            gdk_display_get_default(), GTK_STYLE_PROVIDER(ep),
            GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
        g_object_unref(ep);
        gtk_widget_add_css_class(GTK_WIDGET(errLbl), "auth-error");
        gtk_box_append(vbox, GTK_WIDGET(errLbl));
    }

    GtkEntry* entry = GTK_ENTRY(gtk_entry_new());
    gtk_entry_set_visibility    (entry, FALSE);
    gtk_entry_set_input_purpose (entry, GTK_INPUT_PURPOSE_PASSWORD);
    gtk_entry_set_placeholder_text(entry, "Contraseña...");
    gtk_box_append(vbox, GTK_WIDGET(entry));

    GtkBox* btnBox = GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8));
    gtk_widget_set_halign(GTK_WIDGET(btnBox), GTK_ALIGN_END);
    GtkButton* cancelBtn = GTK_BUTTON(gtk_button_new_with_label("Cancelar"));
    GtkButton* okBtn     = GTK_BUTTON(gtk_button_new_with_label("Aceptar"));
    gtk_box_append(btnBox, GTK_WIDGET(cancelBtn));
    gtk_box_append(btnBox, GTK_WIDGET(okBtn));
    gtk_box_append(vbox, GTK_WIDGET(btnBox));

    gtk_window_set_child(GTK_WINDOW(dialog), GTK_WIDGET(vbox));

    // Estado en heap para que los callbacks puedan referenciarlo con seguridad
    // incluso después de que el stack frame de esta función desaparezca.
    struct PwdResult {
        std::string password;
        bool done      = false;
        bool cancelled = false;
    };
    auto* res = new PwdResult{};

    auto doAccept = [res, entry, dialog]() {
        const char* txt = gtk_editable_get_text(GTK_EDITABLE(entry));
        res->password = txt ? txt : "";
        res->done     = true;
        gtk_window_close(GTK_WINDOW(dialog));
    };

    // ok y entry→activate comparten la misma función de aceptar
    g_signal_connect_data(okBtn, "clicked",
        G_CALLBACK(+[](GtkButton*, gpointer p) {
            (*static_cast<std::function<void()>*>(p))();
        }),
        new std::function<void()>(doAccept),
        +[](gpointer p, GClosure*) { delete static_cast<std::function<void()>*>(p); },
        GConnectFlags(0));
    g_signal_connect_data(entry, "activate",
        G_CALLBACK(+[](GtkEntry*, gpointer p) {
            (*static_cast<std::function<void()>*>(p))();
        }),
        new std::function<void()>(doAccept),
        +[](gpointer p, GClosure*) { delete static_cast<std::function<void()>*>(p); },
        GConnectFlags(0));

    g_signal_connect_data(cancelBtn, "clicked",
        G_CALLBACK(+[](GtkButton*, gpointer p) {
            auto* r = static_cast<PwdResult*>(p);
            r->cancelled = true;
            r->done      = true;
            // No cerramos el dialog aquí — lo cierra el destroy del window
            // o lo hace el llamador; simplemente marcamos done para salir del loop.
        }),
        res, nullptr, GConnectFlags(0));

    // destroy: si se cierra la ventana por cualquier vía sin haber completado, marcar cancelado
    g_signal_connect_data(dialog, "destroy",
        G_CALLBACK(+[](GtkWidget*, gpointer p) {
            auto* r = static_cast<PwdResult*>(p);
            if (!r->done) { r->cancelled = true; r->done = true; }
        }),
        res, nullptr, GConnectFlags(0));

    gtk_window_present(GTK_WINDOW(dialog));
    gtk_widget_grab_focus(GTK_WIDGET(entry));

    GMainContext* ctx = g_main_context_default();
    while (!res->done) g_main_context_iteration(ctx, TRUE);

    // Cerrar la ventana si cancelaron con el botón (no se cierra sola)
    if (res->cancelled) {
        gtk_window_close(GTK_WINDOW(dialog));
        // Procesar el cierre antes de retornar
        while (g_main_context_pending(ctx)) g_main_context_iteration(ctx, FALSE);
    }

    std::optional<std::string> result;
    if (!res->cancelled) result = res->password;
    delete res;
    return result;
}

// ─── Verificador de contraseña (HMAC-SHA256) ───────────────────────────────
// Guarda en disco un HMAC de una cadena fija firmado con la master key.
// Permite verificar si la contraseña es correcta en arranques posteriores
// sin almacenar la contraseña ni información sensible.

static void saveVerifier() {
    const std::string sentinel = "i4froez-auth-ok";
    unsigned char hmac[32]; unsigned int hlen = 0;
    HMAC(EVP_sha256(),
         g_masterKey.data(), (int)g_masterKey.size(),
         reinterpret_cast<const unsigned char*>(sentinel.data()), sentinel.size(),
         hmac, &hlen);
    std::string b64 = base64_encode(std::vector<uint8_t>(hmac, hmac + hlen));
    std::ofstream f(verifierFile(), std::ios::binary);
    f.write(b64.c_str(), (std::streamsize)b64.size());
}

static bool checkVerifier() {
    std::ifstream f(verifierFile(), std::ios::binary);
    if (!f) return false; // primera vez
    std::string b64((std::istreambuf_iterator<char>(f)), {});
    auto stored = base64_decode(b64);

    const std::string sentinel = "i4froez-auth-ok";
    unsigned char hmac[32]; unsigned int hlen = 0;
    HMAC(EVP_sha256(),
         g_masterKey.data(), (int)g_masterKey.size(),
         reinterpret_cast<const unsigned char*>(sentinel.data()), sentinel.size(),
         hmac, &hlen);

    if (hlen != (unsigned int)stored.size()) return false;
    return CRYPTO_memcmp(stored.data(), hmac, hlen) == 0;
}

// ─── Structs de soporte para askProfileSelection ───────────────────────────
// Se definen a nivel de archivo (no dentro de la función) para que los lambdas
// convertidos a puntero de función (+[]) puedan hacer static_cast sin problemas.

struct ProfileSelResult {
    BrowserProfile chosen   = BrowserProfile::CLEARNET;
    bool           done     = false;
    bool           cancelled= false;
};

struct ProfileSelBtnCtx {
    ProfileSelResult* result;
    BrowserProfile    profile;
    GtkWidget*        dialog;
};

// ─── Diálogo de selección de perfil ───────────────────────────────────────
static BrowserProfile askProfileSelection(GtkApplication* app) {
    GtkWidget* dialog = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(dialog), "I4 Froez — Seleccionar perfil");
    gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);
    gtk_window_set_resizable(GTK_WINDOW(dialog), FALSE);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 420, -1);

    GtkWindow* appWin = gtk_application_get_active_window(app);
    if (appWin) gtk_window_set_transient_for(GTK_WINDOW(dialog), appWin);

    GtkCssProvider* pcp = gtk_css_provider_new();
    gtk_css_provider_load_from_string(pcp, R"CSS(
    .profile-title  { font-size: 18px; font-weight: 700; color: #cdd6f4; }
    .profile-sub    { font-size: 12px; color: #6c7086; }
    .btn-clearnet   { background: #1a3a6b; color: #89b4fa; border: 2px solid #89b4fa;
                      border-radius: 10px; padding: 14px 20px; font-size: 14px; font-weight: 600; }
    .btn-clearnet:hover { background: #2a4a8b; }
    .btn-tor        { background: #4a1a6b; color: #cba6f7; border: 2px solid #cba6f7;
                      border-radius: 10px; padding: 14px 20px; font-size: 14px; font-weight: 600; }
    .btn-tor:hover  { background: #5a2a7b; }
    .btn-i2p        { background: #6b3a00; color: #fab387; border: 2px solid #fab387;
                      border-radius: 10px; padding: 14px 20px; font-size: 14px; font-weight: 600; }
    .btn-i2p:hover  { background: #7b4a10; }
    )CSS");
    gtk_style_context_add_provider_for_display(
        gdk_display_get_default(), GTK_STYLE_PROVIDER(pcp),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(pcp);

    GtkBox* vbox = GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL, 16));
    gtk_widget_set_margin_top   (GTK_WIDGET(vbox), 28);
    gtk_widget_set_margin_bottom(GTK_WIDGET(vbox), 28);
    gtk_widget_set_margin_start (GTK_WIDGET(vbox), 32);
    gtk_widget_set_margin_end   (GTK_WIDGET(vbox), 32);

    GtkLabel* title = GTK_LABEL(gtk_label_new("I4 Froez"));
    gtk_widget_add_css_class(GTK_WIDGET(title), "profile-title");
    gtk_box_append(vbox, GTK_WIDGET(title));

    GtkLabel* sub = GTK_LABEL(gtk_label_new(
        "Selecciona el perfil de red para esta sesion.\n"
        "Cada perfil tiene almacenamiento, historial y contraseña independientes."));
    gtk_label_set_justify(sub, GTK_JUSTIFY_CENTER);
    gtk_widget_add_css_class(GTK_WIDGET(sub), "profile-sub");
    gtk_box_append(vbox, GTK_WIDGET(sub));

    gtk_box_append(vbox, GTK_WIDGET(gtk_separator_new(GTK_ORIENTATION_HORIZONTAL)));

    // Definición de los tres botones
    struct BtnDef { const char* label; const char* desc; const char* css; BrowserProfile profile; };
    static const BtnDef BTNS[] = {
        { "Clearnet", "Conexion directa — Chrome/Windows",       "btn-clearnet", BrowserProfile::CLEARNET },
        { "Tor",      "Red Tor — Firefox/Windows (Tor Browser)", "btn-tor",      BrowserProfile::TOR      },
        { "I2P",      "Red I2P — trafico aislado a .i2p",        "btn-i2p",      BrowserProfile::I2P      },
    };

    ProfileSelResult* res = new ProfileSelResult{};

    for (const auto& b : BTNS) {
        GtkBox* row = GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL, 4));
        GtkButton* btn = GTK_BUTTON(gtk_button_new_with_label(b.label));
        gtk_widget_add_css_class(GTK_WIDGET(btn), b.css);

        GtkLabel* descLbl = GTK_LABEL(gtk_label_new(b.desc));
        gtk_widget_add_css_class(GTK_WIDGET(descLbl), "profile-sub");

        gtk_box_append(row, GTK_WIDGET(btn));
        gtk_box_append(row, GTK_WIDGET(descLbl));
        gtk_box_append(vbox, GTK_WIDGET(row));

        // Un contexto por botón en heap — liberado por el GClosure destroy
        auto* bctx = new ProfileSelBtnCtx{ res, b.profile, dialog };

        g_signal_connect_data(btn, "clicked",
            G_CALLBACK(+[](GtkButton*, gpointer p) {
                auto* c = static_cast<ProfileSelBtnCtx*>(p);
                c->result->chosen = c->profile;
                c->result->done   = true;
                gtk_window_close(GTK_WINDOW(c->dialog));
            }),
            bctx,
            +[](gpointer p, GClosure*) { delete static_cast<ProfileSelBtnCtx*>(p); },
            GConnectFlags(0));
    }

    // Botón cancelar
    GtkButton* cancelBtn = GTK_BUTTON(gtk_button_new_with_label("Cancelar"));
    gtk_widget_add_css_class(GTK_WIDGET(cancelBtn), "nav-button");
    gtk_widget_set_halign(GTK_WIDGET(cancelBtn), GTK_ALIGN_END);
    g_signal_connect_data(cancelBtn, "clicked",
        G_CALLBACK(+[](GtkButton*, gpointer p) {
            auto* r = static_cast<ProfileSelResult*>(p);
            r->cancelled = true;
            r->done      = true;
        }),
        res, nullptr, GConnectFlags(0));
    gtk_box_append(vbox, GTK_WIDGET(cancelBtn));

    g_signal_connect_data(dialog, "destroy",
        G_CALLBACK(+[](GtkWidget*, gpointer p) {
            auto* r = static_cast<ProfileSelResult*>(p);
            if (!r->done) { r->cancelled = true; r->done = true; }
        }),
        res, nullptr, GConnectFlags(0));

    gtk_window_set_child(GTK_WINDOW(dialog), GTK_WIDGET(vbox));
    gtk_window_present(GTK_WINDOW(dialog));

    GMainContext* ctx = g_main_context_default();
    while (!res->done) g_main_context_iteration(ctx, TRUE);

    BrowserProfile chosen = res->chosen;
    bool cancelled = res->cancelled;
    delete res;

    if (cancelled) {
        g_application_quit(G_APPLICATION(app));
        exit(0);
    }
    return chosen;
}

// ─── Inicialización de la clave maestra ───────────────────────────────────
// Primera vez: pide contraseña, guarda verificador.
// Siguientes veces: pide contraseña, verifica contra el HMAC guardado.
// Si la contraseña es incorrecta, muestra error y vuelve a preguntar.

static void initMasterKey(GtkApplication* app) {
    auto salt = getOrCreateSalt();
    bool firstTime = !std::ifstream(verifierFile()).good();

    std::string errorMsg;
    if (firstTime)
        errorMsg = "Primera vez — elige una contraseña maestra.\n"
                   "La necesitaras cada vez que abras el navegador.";

    while (true) {
        auto pwdOpt = askMasterPassword(app, errorMsg);

        // Cancelar o cerrar ventana = salir limpiamente
        if (!pwdOpt.has_value()) {
            g_application_quit(G_APPLICATION(app));
            // Forzar salida inmediata — g_application_quit es asíncrono
            // y no podemos continuar construyendo la ventana del navegador.
            exit(0);
        }

        std::string password = std::move(*pwdOpt);

        g_masterKey.resize(32);
        PKCS5_PBKDF2_HMAC(
            password.c_str(), (int)password.size(),
            salt.data(),      (int)salt.size(),
            200000, EVP_sha256(),
            (int)g_masterKey.size(), g_masterKey.data()
        );
        OPENSSL_cleanse(password.data(), password.size());

        if (firstTime) {
            saveVerifier();
            break;
        }

        if (checkVerifier()) break;

        OPENSSL_cleanse(g_masterKey.data(), g_masterKey.size());
        errorMsg = "Contraseña incorrecta. Intenta de nuevo:";
    }
}

// Cifra con AES-256-GCM. Devuelve IV(12) + TAG(16) + CIPHERTEXT.
static std::vector<uint8_t> aesGcmEncrypt(const std::vector<uint8_t>& plain) {
    constexpr int IV_LEN  = 12;
    constexpr int TAG_LEN = 16;

    std::vector<uint8_t> iv(IV_LEN);
    RAND_bytes(iv.data(), IV_LEN);

    std::vector<uint8_t> out(IV_LEN + TAG_LEN + plain.size());
    std::copy(iv.begin(), iv.end(), out.begin());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, g_masterKey.data(), iv.data());

    int len = 0;
    EVP_EncryptUpdate(ctx, out.data() + IV_LEN + TAG_LEN, &len,
                      plain.data(), (int)plain.size());
    int finalLen = 0;
    EVP_EncryptFinal_ex(ctx, out.data() + IV_LEN + TAG_LEN + len, &finalLen);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, out.data() + IV_LEN);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

// Descifra AES-256-GCM. Devuelve {} si falla la autenticación.
static std::optional<std::vector<uint8_t>> aesGcmDecrypt(const std::vector<uint8_t>& blob) {
    constexpr int IV_LEN  = 12;
    constexpr int TAG_LEN = 16;
    if ((int)blob.size() < IV_LEN + TAG_LEN) return std::nullopt;

    const uint8_t* iv  = blob.data();
    // TAG viene después del IV y antes del ciphertext
    std::vector<uint8_t> tag(blob.begin() + IV_LEN, blob.begin() + IV_LEN + TAG_LEN);
    const uint8_t* ct  = blob.data() + IV_LEN + TAG_LEN;
    int ct_len         = (int)blob.size() - IV_LEN - TAG_LEN;

    std::vector<uint8_t> plain(ct_len);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, g_masterKey.data(), iv);
    int len = 0;
    EVP_DecryptUpdate(ctx, plain.data(), &len, ct, ct_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag.data());
    int ok = EVP_DecryptFinal_ex(ctx, plain.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (ok <= 0) return std::nullopt;
    return plain;
}

// Compatibilidad: descifrar ficheros viejos (XOR con clave expandida a 64 bytes)
// NOTA: la clave legacy usaba la cadena hardcodeada original. Se mantiene solo
// para migrar datos de versiones anteriores. Una vez migrados, este código
// no vuelve a ejecutarse porque loadJson re-guarda con AES-GCM.
static std::vector<uint8_t> legacyXorDecrypt(const std::vector<uint8_t>& data) {
    // Reproducir la clave legacy de 64 bytes (igual que en la versión XOR original)
    const char* user = g_get_user_name();
    std::string legacyPass = std::string(user ? user : "i4froez")
                             + "subscribe-to-freetazapablo-in-yt-i4froez-haha";
    auto salt = getOrCreateSalt();
    std::vector<uint8_t> legacyKey(64);
    PKCS5_PBKDF2_HMAC(legacyPass.c_str(), (int)legacyPass.size(),
                      salt.data(), (int)salt.size(), 200000,
                      EVP_sha256(), 64, legacyKey.data());
    std::vector<uint8_t> out(data.size());
    for (size_t i = 0; i < data.size(); i++)
        out[i] = data[i] ^ legacyKey[i % 64];
    return out;
}

static void saveJson(const std::string& path, const json& data) {
    try {
        std::string s  = data.dump(2);
        std::vector<uint8_t> raw(s.begin(), s.end());
        auto ciphered  = aesGcmEncrypt(raw);
        std::string b64 = base64_encode(ciphered);
        std::ofstream fout(path, std::ios::binary);
        fout.write(b64.c_str(), (std::streamsize)b64.size());
    } catch (const std::exception& e) {
        g_warning("[i4froez] Error guardando %s: %s", path.c_str(), e.what());
    }
}

static json loadJson(const std::string& path, const json& def) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return def;
    std::string raw((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

    // 1. Intentar AES-GCM (formato nuevo)
    try {
        auto decoded = base64_decode(raw);
        if (auto plain = aesGcmDecrypt(decoded))
            return json::parse(plain->begin(), plain->end());
    } catch (...) {}

    // 2. Migración: intentar formato legacy XOR
    try {
        auto decoded = base64_decode(raw);
        auto plain   = legacyXorDecrypt(decoded);
        json j = json::parse(plain.begin(), plain.end());
        // Re-guardar con cifrado fuerte
        saveJson(path, j); // se llama desde abajo — OK porque ya tenemos la clave
        return j;
    } catch (...) {}

    // 3. Fallback: JSON en texto plano (primera ejecución tras migración)
    try { return json::parse(raw); } catch (...) {}
    return def;
}

// ─── CSS global ────────────────────────────────────────────────────────────

static const char* GLOBAL_CSS = R"CSS(
.toolbar { background-color: #1e1e2e; border-bottom: 1px solid #313244; padding: 4px 8px; }
.url-entry { background-color: #313244; color: #cdd6f4; border: 1px solid #45475a;
    border-radius: 6px; padding: 4px 10px; font-size: 14px; min-height: 32px; }
.url-entry:focus { border-color: #89b4fa; background-color: #1e1e2e; }
.nav-button { background-color: transparent; color: #cdd6f4; border: none;
    border-radius: 6px; padding: 4px 8px; min-width: 32px; min-height: 32px; font-size: 16px; }
.nav-button:hover { background-color: #313244; }
.nav-button:disabled { color: #45475a; }
.tabbar { background-color: #181825; border-bottom: 1px solid #313244;
    padding: 4px 8px 0 8px; min-height: 36px; }
.tab-title-btn { background-color: transparent; color: inherit; border: none;
    border-radius: 4px 0 0 4px; padding: 4px 8px; font-size: 13px; min-width: 60px; }
.tab-title-btn:hover { background-color: rgba(255,255,255,0.05); }
.tab-btn { background-color: #1e1e2e; color: #6c7086; border: 1px solid #313244;
    border-bottom: none; border-radius: 6px 6px 0 0; padding: 4px 10px; font-size: 13px; min-width: 80px; }
.tab-btn:hover { background-color: #313244; color: #cdd6f4; }
.tab-active { background-color: #1e1e2e; color: #cdd6f4; border: 1px solid #45475a;
    border-bottom: 2px solid #89b4fa; font-weight: bold; }
.badge-normal  { background-color: #313244; color: #a6e3a1; border-radius: 4px; padding: 2px 8px; font-size: 12px; font-family: monospace; }
.badge-tor     { background-color: #7f49a0; color: #f5c2e7; border-radius: 4px; padding: 2px 8px; font-size: 12px; font-family: monospace; font-weight: bold; }
.badge-i2p     { background-color: #7a3a00; color: #fab387; border-radius: 4px; padding: 2px 8px; font-size: 12px; font-family: monospace; font-weight: bold; }
.badge-clear   { background-color: #1a3a6b; color: #89b4fa; border-radius: 4px; padding: 2px 8px; font-size: 12px; font-family: monospace; font-weight: bold; }
.badge-file    { background-color: #2a3550; color: #89b4fa; border-radius: 4px; padding: 2px 8px; font-size: 12px; font-family: monospace; font-weight: bold; }
.badge-secure  { background-color: #1a4731; color: #a6e3a1; border-radius: 4px; padding: 2px 8px; font-size: 12px; font-family: monospace; font-weight: bold; }
.badge-insecure{ background-color: #4a1a1a; color: #f38ba8; border-radius: 4px; padding: 2px 8px; font-size: 12px; font-family: monospace; font-weight: bold; }
.badge-onion   { background-color: #7f49a0; color: #f5c2e7; border-radius: 4px; padding: 2px 8px; font-size: 12px; font-family: monospace; font-weight: bold; }
.badge-eepsite { background-color: #7a3a00; color: #fab387; border-radius: 4px; padding: 2px 8px; font-size: 12px; font-family: monospace; font-weight: bold; }
.badge-onion-s { background-color: #6b2a5a; color: #ffb3e6; border-radius: 4px; padding: 2px 8px; font-size: 12px; font-family: monospace; font-weight: bold; }
.findbar       { background-color: #1e1e2e; border-top: 1px solid #313244; padding: 4px 8px; }
.findbar-entry { background-color: #313244; color: #cdd6f4; border: 1px solid #45475a;
    border-radius: 6px; padding: 2px 8px; font-size: 13px; min-height: 28px; min-width: 200px; }
.findbar-entry:focus { border-color: #89b4fa; }
.findbar-label { color: #6c7086; font-size: 12px; padding: 0 8px; }
.inspector-tv  { background-color: #0a0a1a; color: #89b4fa; font-family: monospace; font-size: 13px; padding: 10px; }
.terminal      { background-color: #0d0d0d; color: #00ff41; font-family: monospace; font-size: 13px; padding: 10px; }
.js-console    { background-color: #0a0a0a; color: #f1c40f; font-family: monospace; font-size: 13px; padding: 10px; }
.statusbar     { background-color: #181825; border-top: 1px solid #313244; color: #6c7086; font-size: 11px; padding: 2px 10px; }
.dl-progress trough { background-color: #313244; border-radius: 4px; min-height: 8px; }
.dl-progress progress { background-color: #89b4fa; border-radius: 4px; min-height: 8px; }
.new-tab-btn { background-color: transparent; color: #6c7086; border: none;
    border-radius: 4px; padding: 2px 8px; font-size: 18px; min-height: 28px; }
.new-tab-btn:hover { background-color: #313244; color: #cdd6f4; }
.tab-drag-over { background-color: #45475a; border-color: #89b4fa; outline: 2px solid #89b4fa; }
.sidebar       { background-color: #181825; border-right: 1px solid #313244; min-width: 240px; }
.sidebar-title { background-color: #1e1e2e; color: #89b4fa; font-weight: bold; font-size: 13px;
    padding: 8px 12px; border-bottom: 1px solid #313244; }
.sidebar-item  { background-color: transparent; color: #cdd6f4; border: none;
    border-radius: 4px; padding: 6px 10px; font-size: 12px; }
.sidebar-item:hover { background-color: #313244; }
.close-tab-btn { background-color: transparent; color: #6c7086; border: none;
    border-radius: 3px; padding: 0 3px; font-size: 12px; min-width: 16px; min-height: 16px; }
.close-tab-btn:hover { background-color: #f38ba8; color: #1e1e2e; }
/* Barra de progreso de carga en el URL entry */
.url-entry-loading { border-color: #89b4fa; }
/* Scrollbar fina para tabbar */
scrollbar { min-width: 4px; min-height: 4px; }
scrollbar slider { background-color: #45475a; border-radius: 4px; min-width: 4px; min-height: 4px; }
scrollbar slider:hover { background-color: #6c7086; }
/* Resaltado de resultado de búsqueda en findbar */
.findbar-count { color: #a6e3a1; font-size: 12px; font-family: monospace; }
/* Notificación toast */
.toast { background-color: #313244; color: #cdd6f4; border: 1px solid #45475a;
    border-radius: 8px; padding: 8px 16px; font-size: 13px; }
)CSS";

// ─── JS de anti-fingerprinting — diferente por perfil ─────────────────────
// Clearnet : parece Chrome real en Windows
// Tor      : parece Tor Browser (Firefox ESR en Windows) — coherente con la red
// I2P      : perfil genérico consistente, timezone UTC

// Genera el script de FP según el perfil activo.
// Se llama en makeWebview() para inyectarlo en cada WebView.
static std::string buildFpJs(BrowserProfile profile) {
    // Parámetros que varían por perfil
    std::string uaStr, platformStr, vendorStr, appVersionStr, productSubStr;
    int hwConcurrency = 4;
    switch (profile) {
        case BrowserProfile::TOR:
            // Tor Browser se identifica exactamente como Firefox/128 en Windows
            uaStr        = "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0";
            platformStr  = "Win32";
            vendorStr    = "";                // Firefox no tiene navigator.vendor
            appVersionStr= "5.0 (Windows)";
            productSubStr= "20030107";
            hwConcurrency= 4;               // Tor Browser normaliza a 4
            break;
        case BrowserProfile::I2P:
            // Perfil I2P: Firefox genérico, sin rasgos únicos
            uaStr        = "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0";
            platformStr  = "Win32";
            vendorStr    = "";
            appVersionStr= "5.0 (Windows)";
            productSubStr= "20030107";
            hwConcurrency= 4;
            break;
        default: // CLEARNET — parece Chrome en Windows
            uaStr        = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
            platformStr  = "Win32";
            vendorStr    = "Google Inc.";
            appVersionStr= "5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
            productSubStr= "20030107";
            hwConcurrency= 8;
            break;
    }

    // Construir el script combinando la plantilla con los valores
    // Las secciones 1-8 y 10-17 son idénticas; solo cambia la sección 5 (navigator)
    std::string js = R"JS(
(function() {
    'use strict';
    // 1. LETTERBOXING
    (function() {
        function rounded(v, step) { return Math.floor(v / step) * step || step; }
        const RW = rounded(window.innerWidth,  100);
        const RH = rounded(window.innerHeight, 100);
        const props = { innerWidth: RW, innerHeight: RH, outerWidth: RW, outerHeight: RH };
        for (const [k, v] of Object.entries(props)) {
            try { Object.defineProperty(window, k, { get: () => v, configurable: true }); } catch(e) {}
        }
    })();
    // 2. TIMING ATTACKS
    (function() {
        const G = 2;
        const origNow = performance.now.bind(performance);
        performance.now = function() { return Math.round(origNow() / G) * G; };
        Date.now = (function(origDN) { return function() { return Math.round(origDN() / G) * G; }; })(Date.now);
        try { delete window.SharedArrayBuffer; } catch(e) {}
        try { delete window.Atomics; } catch(e) {}
    })();
    // 3. CANVAS
    (function() {
        const SEED = (Math.random() * 0xFFFFFFFF) | 0;
        function nb(i) { return ((SEED ^ (i * 1664525 + 1013904223)) >>> 24) & 1; }
        const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = function(t, ...a) {
            const ctx = this.getContext('2d');
            if (ctx && this.width > 0 && this.height > 0) {
                const id = ctx.getImageData(0, 0, this.width, this.height);
                for (let i = 0; i < id.data.length; i += 4) { id.data[i]^=nb(i); id.data[i+1]^=nb(i+1); id.data[i+2]^=nb(i+2); }
                ctx.putImageData(id, 0, 0);
            }
            return origToDataURL.call(this, t, ...a);
        };
    })();
    // 4. AUDIOCONTEXT
    (function() {
        const ACtx = window.AudioContext || window.webkitAudioContext;
        if (!ACtx) return;
        const P = function(...args) {
            const ctx = new ACtx(...args);
            const origCA = ctx.createAnalyser.bind(ctx);
            ctx.createAnalyser = function() {
                const a = origCA();
                const origGF = a.getFloatFrequencyData.bind(a);
                a.getFloatFrequencyData = function(arr) { origGF(arr); for (let i=0;i<arr.length;i++) arr[i]+=(Math.random()-0.5)*0.1; };
                return a;
            };
            return ctx;
        };
        try { if (window.AudioContext) window.AudioContext = P; } catch(e) {}
        try { if (window.webkitAudioContext) window.webkitAudioContext = P; } catch(e) {}
    })();
)JS";

    // 5. NAVIGATOR — varía por perfil
    js += "    // 5. NAVIGATOR\n    (function() {\n";
    js += "        const ov = { platform:'" + platformStr + "', hardwareConcurrency:" + std::to_string(hwConcurrency) + ", deviceMemory:8,\n";
    js += "            languages:['en-US','en'], language:'en-US', plugins:[], mimeTypes:[],\n";
    js += "            doNotTrack:'1', maxTouchPoints:0, vendor:'" + vendorStr + "',\n";
    js += "            vendorSub:'', productSub:'" + productSubStr + "', appName:'Netscape', appVersion:'" + appVersionStr + "' };\n";
    js += R"JS(
        for (const [k,v] of Object.entries(ov)) {
            try { Object.defineProperty(navigator, k, { get: () => v, configurable: true }); } catch(e) {}
        }
    })();
)JS";

    js += R"JS(
    // 6. SCREEN — fijo 1920x1080 para todos los perfiles
    (function() {
        const s = { width:1920, height:1080, availWidth:1920, availHeight:1080, colorDepth:24, pixelDepth:24 };
        for (const [k,v] of Object.entries(s)) {
            try { Object.defineProperty(screen, k, { get: () => v, configurable: true }); } catch(e) {}
        }
        try { Object.defineProperty(window, 'devicePixelRatio', { get: () => 1, configurable: true }); } catch(e) {}
    })();
    // 7. WEBGL
    (function() {
        function patchGL(ctx) {
            const ogp = ctx.getParameter.bind(ctx);
            ctx.getParameter = function(p) {
                if (p === 37445) return 'Intel Inc.';
                if (p === 37446) return 'Intel Iris OpenGL Engine';
                return ogp(p);
            };
            const oge = ctx.getExtension.bind(ctx);
            const blocked = ['WEBGL_debug_renderer_info','EXT_disjoint_timer_query','EXT_disjoint_timer_query_webgl2'];
            ctx.getExtension = function(n) { return blocked.includes(n) ? null : oge(n); };
            const ogs = ctx.getSupportedExtensions.bind(ctx);
            ctx.getSupportedExtensions = function() { return (ogs()||[]).filter(e=>!blocked.includes(e)); };
        }
        const origGC = HTMLCanvasElement.prototype.getContext;
        HTMLCanvasElement.prototype.getContext = function(t, ...a) {
            const ctx = origGC.call(this, t, ...a);
            if (ctx && (t==='webgl'||t==='webgl2'||t==='experimental-webgl')) patchGL(ctx);
            return ctx;
        };
    })();
    // 8. BATTERY
    if (navigator.getBattery) navigator.getBattery = () => Promise.resolve({ charging:true, chargingTime:0, dischargingTime:Infinity, level:1.0, addEventListener:()=>{}, removeEventListener:()=>{} });
    // 9. TIMEZONE — UTC fija para todos los perfiles (protección anti-correlación)
    Date.prototype.getTimezoneOffset = function() { return 0; };
    // 10. FUENTES
    if (document.fonts && document.fonts.check) {
        const gen = ['serif','sans-serif','monospace','cursive','fantasy','system-ui'];
        const oc = document.fonts.check.bind(document.fonts);
        document.fonts.check = (f, t) => gen.some(g => f.toLowerCase().includes(g)) ? oc(f, t) : false;
        const ol = document.fonts.load.bind(document.fonts);
        document.fonts.load = (f, t) => gen.some(g => f.toLowerCase().includes(g)) ? ol(f, t) : Promise.resolve([]);
    }
    // 11. WINDOW.NAME
    window.name = '';
    // 12. GEOLOCATION
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition = (ok, err) => { if (err) err({ code:1, message:'Permission denied' }); };
        navigator.geolocation.watchPosition = (ok, err) => { if (err) err({ code:1, message:'Permission denied' }); return 0; };
    }
    // 13. MEDIA DEVICES
    if (navigator.mediaDevices) {
        navigator.mediaDevices.enumerateDevices = () => Promise.resolve([]);
        navigator.mediaDevices.getUserMedia    = () => Promise.reject(new DOMException('NotAllowedError'));
        navigator.mediaDevices.getDisplayMedia = () => Promise.reject(new DOMException('NotAllowedError'));
    }
    // 14. SPEECH
    try { if (window.speechSynthesis) window.speechSynthesis.getVoices = () => []; delete window.SpeechRecognition; delete window.webkitSpeechRecognition; } catch(e) {}
    // 15. CONNECTION API
    try { Object.defineProperty(navigator, 'connection', { get: () => undefined, configurable: true }); } catch(e) {}
    try { Object.defineProperty(navigator, 'onLine', { get: () => true, configurable: true }); } catch(e) {}
    // 16. CLIPBOARD — bloquear lectura silenciosa
    try {
        if (navigator.clipboard) {
            navigator.clipboard.readText = () => Promise.reject(new DOMException('NotAllowedError'));
            navigator.clipboard.read     = () => Promise.reject(new DOMException('NotAllowedError'));
        }
    } catch(e) {}
    // 17. STORAGE ESTIMATE
    try {
        if (navigator.storage && navigator.storage.estimate)
            navigator.storage.estimate = () => Promise.resolve({ quota: 107374182400, usage: 0 });
    } catch(e) {}
})();
)JS";
    return js;
}

// Mantener la constante global para compatibilidad (se reemplaza en makeWebview con buildFpJs)
static const char* FP_PROTECTION_JS = R"JS(
(function() {
    'use strict';
    // Fallback — no debería usarse directamente; ver buildFpJs()
    Date.prototype.getTimezoneOffset = function() { return 0; };
    window.name = '';
})();
)JS";

// ─── Utilidades de cadenas ─────────────────────────────────────────────────

static std::string strLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

static bool startsWith(const std::string& s, const std::string& prefix) {
    return s.starts_with(prefix);
}

static bool endsWith(const std::string& s, const std::string& suffix) {
    return s.ends_with(suffix);
}

// Escapa caracteres especiales HTML para prevenir XSS en páginas internas
static std::string htmlEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '&':  out += "&amp;";  break;
            case '<':  out += "&lt;";   break;
            case '>':  out += "&gt;";   break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&#39;";  break;
            default:   out += c;        break;
        }
    }
    return out;
}

static std::string urlEncode(const std::string& s) {
    gchar* enc = g_uri_escape_string(s.c_str(), nullptr, FALSE);
    std::string result(enc);
    g_free(enc);
    return result;
}

// Formato ISO de fecha actual (thread-safe)
static std::string isoNow() {
    time_t t = time(nullptr);
    struct tm tm_info{};
    gmtime_r(&t, &tm_info);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_info);
    return buf;
}

// ─── Motores de búsqueda ───────────────────────────────────────────────────

struct SearchEngine {
    std::string id;
    std::string name;
    std::string homeUrl;
    std::string searchUrl; // usa %s como placeholder de la query
};

static const std::vector<SearchEngine> SEARCH_ENGINES = {
    {"duckduckgo",      "DuckDuckGo",        "https://duckduckgo.com",
        "https://duckduckgo.com/?q=%s"},
    {"duckduckgo_onion","DuckDuckGo (Onion)", "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/",
        "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/?q=%s"},
    {"google",          "Google",            "https://www.google.com",
        "https://www.google.com/search?q=%s"},
    {"bing",            "Bing",              "https://www.bing.com",
        "https://www.bing.com/search?q=%s"},
    {"brave",           "Brave Search",      "https://search.brave.com",
        "https://search.brave.com/search?q=%s"},
    {"startpage",       "Startpage",         "https://www.startpage.com",
        "https://www.startpage.com/search?q=%s"},
    {"qwant",           "Qwant",             "https://www.qwant.com",
        "https://www.qwant.com/?q=%s"},
    {"ecosia",          "Ecosia",            "https://www.ecosia.org",
        "https://www.ecosia.org/search?q=%s"},
    {"yahoo",           "Yahoo",             "https://search.yahoo.com",
        "https://search.yahoo.com/search?p=%s"},
    {"yandex",          "Yandex",            "https://yandex.com",
        "https://yandex.com/search/?text=%s"},
    {"baidu",           "Baidu",             "https://www.baidu.com",
        "https://www.baidu.com/s?wd=%s"},
    {"naver",           "Naver",             "https://www.naver.com",
        "https://search.naver.com/search.naver?query=%s"},
    {"searxng",         "SearXNG",           "https://searx.bndkt.io",
        "https://searx.bndkt.io/search?q=%s"},
    {"whoogle",         "Whoogle",           "https://search.sethforprivacy.com",
        "https://search.sethforprivacy.com/search?q=%s"},
    {"youtube",         "YouTube",           "https://www.youtube.com",
        "https://www.youtube.com/results?search_query=%s"},
    {"wikipedia",       "Wikipedia",         "https://es.wikipedia.org",
        "https://es.wikipedia.org/wiki/%s"},
};

static const SearchEngine* findEngine(const std::string& id) {
    for (const auto& e : SEARCH_ENGINES)
        if (e.id == id) return &e;
    return nullptr;
}

// Construye URL de búsqueda con el motor por defecto.
// searxngOverride / whoogleOverride: si no vacíos, reemplazan la URL base del motor.
static std::string searchWithDefault(const std::string& query, const std::string& engineId,
                                     const std::string& searxngOverride = "",
                                     const std::string& whoogleOverride = "") {
    const SearchEngine* eng = findEngine(engineId);
    if (!eng) eng = &SEARCH_ENGINES[0]; // fallback: DuckDuckGo
    std::string url = eng->searchUrl;
    if (engineId == "searxng" && !searxngOverride.empty())
        url = searxngOverride + "/search?q=%s";
    else if (engineId == "whoogle" && !whoogleOverride.empty())
        url = whoogleOverride + "/search?q=%s";
    size_t pos = url.find("%s");
    if (pos != std::string::npos)
        url.replace(pos, 2, urlEncode(query));
    return url;
}

// ─── Páginas internas froez:// ─────────────────────────────────────────────

// Declaración adelantada — AppData se define completamente más adelante
struct AppData;

static const char* FROEZ_CSS = R"(
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#1e1e2e;color:#cdd6f4;
  min-height:100vh;padding:32px 40px}
h1{color:#89b4fa;font-size:22px;font-weight:700;margin-bottom:24px;
  border-bottom:1px solid #313244;padding-bottom:12px}
h2{color:#a6adc8;font-size:15px;font-weight:600;margin:20px 0 10px}
.card{background:#181825;border:1px solid #313244;border-radius:10px;
  padding:20px;margin-bottom:20px}
label{display:block;color:#a6adc8;font-size:13px;margin-bottom:6px}
select,input[type=text]{background:#313244;color:#cdd6f4;border:1px solid #45475a;
  border-radius:6px;padding:6px 10px;font-size:13px;width:100%;max-width:400px}
select:focus,input:focus{outline:none;border-color:#89b4fa}
button{background:#313244;color:#cdd6f4;border:1px solid #45475a;border-radius:6px;
  padding:6px 14px;font-size:13px;cursor:pointer;margin-top:10px}
button:hover{background:#45475a}
button.primary{background:#89b4fa;color:#1e1e2e;border-color:#89b4fa;font-weight:600}
button.primary:hover{background:#74c7ec}
button.danger{background:#f38ba8;color:#1e1e2e;border-color:#f38ba8}
button.danger:hover{background:#eba0ac}
.row{display:flex;align-items:center;gap:8px;padding:8px 0;
  border-bottom:1px solid #313244}
.row:last-child{border-bottom:none}
.row-title{flex:1;font-size:13px;color:#cdd6f4;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.row-sub{font-size:11px;color:#6c7086;margin-top:2px}
.row-url{font-size:11px;color:#6c7086;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
a{color:#89b4fa;text-decoration:none}
a:hover{text-decoration:underline}
.empty{color:#585b70;font-size:13px;padding:20px 0;text-align:center}
.badge{background:#313244;color:#a6e3a1;border-radius:4px;padding:2px 8px;
  font-size:11px;font-family:monospace;margin-left:8px}
.section-info{color:#6c7086;font-size:12px;margin-bottom:12px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:#6c7086;font-weight:600;padding:6px 8px;
  border-bottom:1px solid #313244}
td{padding:6px 8px;border-bottom:1px solid #1e1e2e;vertical-align:top}
tr:hover td{background:#1e1e2e}
.config-key{color:#89b4fa;font-family:monospace;font-size:12px}
.config-val{color:#a6e3a1;font-family:monospace;font-size:12px}
.config-desc{color:#6c7086;font-size:11px}
.nav-links{display:flex;gap:16px;margin-bottom:24px;flex-wrap:wrap}
.nav-links a{color:#6c7086;font-size:13px;padding:4px 10px;border-radius:6px;
  background:#181825;border:1px solid #313244}
.nav-links a:hover,.nav-links a.active{color:#89b4fa;border-color:#89b4fa;
  text-decoration:none;background:#1e1e2e}
</style>
)";

static std::string htmlHead(const std::string& title) {
    return "<!DOCTYPE html><html><head><meta charset='utf-8'>"
           "<title>" + title + "</title>" + FROEZ_CSS + "</head><body>";
}

static std::string htmlNavLinks(const std::string& active) {
    auto link = [&](const std::string& href, const std::string& label, const std::string& id) {
        std::string cls = (id == active) ? " class='active'" : "";
        return "<a href='froez://" + href + "'" + cls + ">" + label + "</a>";
    };
    return "<div class='nav-links'>"
        + link("newtab",    "Nueva pestaña",  "newtab")
        + link("bookmarks", "Marcadores",     "bookmarks")
        + link("history",   "Historial",      "history")
        + link("settings",  "Ajustes",        "settings")
        + link("peru",      "Perú",             "peru")
        + "</div>";
}

// Genera la pagina froez://newtab
static std::string buildFroezNewtab(const std::string& defaultEngine) {
    const SearchEngine* eng = findEngine(defaultEngine);
    std::string engName = eng ? eng->name : "DuckDuckGo";
    std::string html = htmlHead("Nueva pestaña — I4 Froez");
    html += htmlNavLinks("newtab");
    html += "<h1>I4 Froez <span class='badge'>v0.8 (BETA)</span></h1>";
    html += "<div class='card'>";
    html += "<label>Buscar con <strong style='color:#89b4fa'>" + htmlEscape(engName) + "</strong></label>";
    html += "<form id='sf' style='display:flex;gap:8px;max-width:600px;margin-top:8px'>"
            "<input type='text' id='q' placeholder='Buscar o escribir una URL...' autofocus "
            "style='flex:1;max-width:none'>"
            "<button type='submit' class='primary'>Buscar</button>"
            "</form>";
    html += "<script>"
            "document.getElementById('sf').onsubmit=function(e){"
            "e.preventDefault();"
            "var q=document.getElementById('q').value.trim();"
            "if(!q)return;"
            "var lower=q.toLowerCase();"
            // Esquemas conocidos
            "if(q.match(/^https?:\\/\\//)||q.match(/^file:\\/\\//)||q.match(/^froez:\\/\\//))"
            "{ window.location.href=q; return; }"
            // .onion / .i2p → http sin s
            "if(lower.match(/\\.onion(:\\d+)?(\\/.*)?$/) || lower.match(/\\.i2p(:\\d+)?(\\/.*)?$/))"
            "{ window.location.href='http://'+q; return; }"
            // Parece dominio
            "if(q.includes('.')&&!q.includes(' '))"
            "{ window.location.href='https://'+q; return; }"
            "window.location.href='froez://search?q='+encodeURIComponent(q);"
            "};</script>";
    html += "</div>";

    // Quick links de motores agrupados
    html += "<div class='card'><h2>Acceso rápido</h2>"
            "<div style='display:flex;gap:10px;flex-wrap:wrap'>";
    for (const auto& e : SEARCH_ENGINES) {
        std::string active = (e.id == defaultEngine) ? "border-color:#89b4fa;color:#89b4fa" : "";
        html += "<a href='" + htmlEscape(e.homeUrl) + "' style='display:inline-block;"
                "background:#1e1e2e;border:1px solid #313244;border-radius:8px;"
                "padding:7px 13px;font-size:12px;color:#a6adc8;" + active + "'>" + htmlEscape(e.name) + "</a>";
    }
    html += "</div></div></body></html>";
    return html;
}

// buildFroezSettings se define más adelante (requiere AppData completo)
static std::string buildFroezSettings(AppData* app);

// Genera la pagina froez://bookmarks
static std::string buildFroezBookmarks(const json& bookmarks) {
    std::string html = htmlHead("Marcadores — I4 Froez");
    html += htmlNavLinks("bookmarks");
    html += "<h1>Marcadores</h1>";
    html += "<div class='card'>";
    if (bookmarks.empty()) {
        html += "<p class='empty'>No hay marcadores guardados.<br>"
                "Usa el boton o en la barra o el comando <code>bookmark</code> en el terminal.</p>";
    } else {
        for (const auto& b : bookmarks) {
            std::string title = htmlEscape(b.value("title", ""));
            std::string url   = b.value("url", "");
            html += "<div class='row'><div style='flex:1;overflow:hidden'>"
                    "<div class='row-title'><a href='" + htmlEscape(url) + "'>" + title + "</a></div>"
                    "<div class='row-url'>" + htmlEscape(url) + "</div>"
                    "</div>"
                    "<button class='danger' style='padding:3px 10px;font-size:11px' "
                    "onclick=\"window.location.href='froez://remove-bookmark?url="
                    + urlEncode(url) + "'\">Quitar</button>"
                    "</div>";
        }
    }
    html += "</div></body></html>";
    return html;
}

// Genera la pagina froez://history
static std::string buildFroezHistory(const json& history) {
    std::string html = htmlHead("Historial — I4 Froez");
    html += htmlNavLinks("history");
    html += "<h1>Historial</h1>";
    html += "<div class='card'>"
            "<a href='froez://clear-history' class='danger' "
            "style='display:inline-block;padding:6px 14px;border-radius:6px;"
            "text-decoration:none;font-size:13px;'>Borrar historial completo</a>"
            "</div>";
    html += "<div class='card'>";
    if (history.empty()) {
        html += "<p class='empty'>El historial esta vacio.</p>";
    } else {
        int total = (int)history.size();
        int start = std::max(0, total - 500);
        for (int i = total - 1; i >= start; i--) {
            const auto& h = history[i];
            std::string url   = h.value("url", "");
            std::string title = h.value("title", url);
            std::string ts    = h.value("ts", "").substr(0, 19);
            std::replace(ts.begin(), ts.end(), 'T', ' ');
            // Usar url+ts como clave de eliminación (más robusto que índice absoluto)
            html += "<div class='row'>"
                    "<div style='flex:1;overflow:hidden'>"
                    "<div class='row-title'><a href='" + htmlEscape(url) + "'>" + htmlEscape(title) + "</a></div>"
                    "<div class='row-sub'>" + htmlEscape(ts) + " &nbsp; <span class='row-url'>" + htmlEscape(url) + "</span></div>"
                    "</div>"
                    "<a href='froez://remove-history?url=" + urlEncode(url) + "&ts=" + urlEncode(h.value("ts","")) + "' "
                    "title='Eliminar esta entrada' "
                    "style='color:#f38ba8;text-decoration:none;padding:4px 8px;font-size:16px;flex-shrink:0;align-self:center;'>✕</a>"
                    "</div>";
        }
    }
    html += "</div></body></html>";
    return html;
}

// ─── Estructuras de datos ─────────────────────────────────────────────────

struct TabData {
    WebKitWebView* webview = nullptr;
    std::string mode = "normal"; // "normal" | "tor" | "i2p"
};

// ─── Datos globales de la app ──────────────────────────────────────────────

struct AppData {
    std::string homeUri;
    bool darkMode = false;
    json history   = json::array();
    json bookmarks = json::array();
    std::string defaultSearchEngine = "duckduckgo";

    // Configuración avanzada editable
    std::string torProxy     = "socks5://127.0.0.1:9050";
    std::string i2pProxy     = "http://127.0.0.1:4444";
    std::string searxngUrl   = "https://searx.bndkt.io";
    std::string whoogleUrl   = "https://search.sethforprivacy.com";
    int         maxHistory   = 2000;

    // Nuevas funciones
    bool httpsOnly  = false;  // Modo HTTPS-Only
    bool jsBlocked  = false;  // Bloqueo global de JavaScript
    std::unordered_map<std::string, double> zoomPerDomain; // Zoom persistente por dominio

    void addHistory(const std::string& url, const std::string& title) {
        if (url.empty() || startsWith(url, "file://") || url == "about:blank"
            || startsWith(url, "froez://")) return;
        if (!history.empty() && history.back()["url"] == url) return;
        json entry;
        entry["url"]   = url;
        entry["title"] = title.empty() ? url : title;
        entry["ts"]    = isoNow();
        history.push_back(entry);
        if ((int)history.size() > maxHistory)
            history = json(history.end() - maxHistory, history.end());
        saveJson(historyFile(), history);
    }

    bool addBookmark(const std::string& url, const std::string& title) {
        if (url.empty() || url == "about:blank") return false;
        for (const auto& b : bookmarks)
            if (b["url"] == url) return false;
        json bm; bm["url"] = url; bm["title"] = title.empty() ? url : title;
        bookmarks.push_back(bm);
        saveJson(bookmarksFile(), bookmarks);
        return true;
    }

    void removeBookmark(const std::string& url) {
        json nb = json::array();
        for (const auto& b : bookmarks)
            if (b["url"] != url) nb.push_back(b);
        bookmarks = nb;
        saveJson(bookmarksFile(), bookmarks);
    }

    bool isBookmarked(const std::string& url) const {
        for (const auto& b : bookmarks)
            if (b["url"] == url) return true;
        return false;
    }
};

// ─── Contexto de la ventana ────────────────────────────────────────────────
// Usamos una struct con todos los widgets y estado porque gtkmm no está
// disponible en todos los entornos; esto usa la C API pura de GTK4.

struct BrowserWindow {
    GtkApplicationWindow* window = nullptr;
    AppData* app = nullptr;

    // Pestañas
    std::vector<TabData> tabs;
    int currentTab = -1;

    // Widgets
    GtkBox*       tabbarBox     = nullptr;
    GtkStack*     tabStack      = nullptr;
    GtkEntry*     urlEntry      = nullptr;
    GtkButton*    backBtn       = nullptr;
    GtkButton*    forwardBtn    = nullptr;
    GtkButton*    reloadBtn     = nullptr;
    GtkButton*    homeBtn       = nullptr;
    GtkButton*    bookmarkStar  = nullptr;
    GtkLabel*     badge         = nullptr;
    GtkLabel*     secBadge      = nullptr;
    GtkLabel*     statusbar     = nullptr;
    GtkProgressBar* dlProgress  = nullptr;
    GtkBox*       contentArea   = nullptr;
    GtkWidget*    sidebarWidget = nullptr;

    // Terminal
    GtkTextBuffer* terminalBuf  = nullptr;
    GtkTextView*   terminalTv   = nullptr;
    GtkScrolledWindow* termScroll = nullptr;
    GtkTextMark*   promptEndMark = nullptr;
    GtkTextTag*    termReadonlyTag = nullptr; // historial no editable
    bool terminalVisible = false;

    // Inspector
    GtkTextBuffer* inspectorBuf = nullptr;
    GtkTextView*   inspectorTv  = nullptr;
    GtkWidget*     inspPanel    = nullptr;
    bool inspectorMode = false;

    // Findbar
    GtkBox*   findbarBox   = nullptr;
    GtkEntry* findEntry    = nullptr;
    GtkLabel* findLabel    = nullptr;
    bool findbarVisible = false;

    // Sidebar
    std::string sidebarMode; // "" | "bookmarks" | "history"

    // Historial de comandos del terminal
    std::vector<std::string> termHistory;
    int termHistoryIdx = -1; // -1 = no navegando

    // Consola JavaScript
    GtkTextBuffer* jsBuf     = nullptr;
    GtkTextView*   jsTv      = nullptr;
    GtkScrolledWindow* jsScroll = nullptr;
    GtkWidget*     jsPanel   = nullptr;
    bool jsConsoleVisible    = false;
    std::vector<std::string> jsHistory;
    int jsHistoryIdx         = -1;
    GtkTextMark*   jsPromptMark = nullptr;

    // Menú sandwich
    GtkWidget*     menuPopover = nullptr;
    GtkButton*     menuBtn     = nullptr;

    // Drag-and-drop de pestañas
    int  dragSrcIdx = -1; // índice de la pestaña que se está arrastrando
};

// Puntero global para acceder desde callbacks C
static BrowserWindow* g_bw = nullptr;
static AppData g_app;

// ─── Helpers de botones ────────────────────────────────────────────────────

static GtkButton* makeNavBtn(const char* label, const char* tooltip, GCallback cb, gpointer data) {
    GtkButton* b = GTK_BUTTON(gtk_button_new_with_label(label));
    gtk_widget_add_css_class(GTK_WIDGET(b), "nav-button");
    gtk_widget_set_tooltip_text(GTK_WIDGET(b), tooltip);
    g_signal_connect(b, "clicked", cb, data);
    return b;
}

// ─── Ajustes persistentes ──────────────────────────────────────────────────

static void saveSettings(AppData* app) {
    json s;
    s["defaultSearchEngine"] = app->defaultSearchEngine;
    s["homeUri"]             = app->homeUri;
    s["torProxy"]            = app->torProxy;
    s["i2pProxy"]            = app->i2pProxy;
    s["searxngUrl"]          = app->searxngUrl;
    s["whoogleUrl"]          = app->whoogleUrl;
    s["maxHistory"]          = app->maxHistory;
    s["darkMode"]            = app->darkMode;
    s["httpsOnly"]           = app->httpsOnly;
    s["jsBlocked"]           = app->jsBlocked;
    // Guardar zoom por dominio
    json zoomJson = json::object();
    for (const auto& [k, v] : app->zoomPerDomain) zoomJson[k] = v;
    s["zoomPerDomain"]       = zoomJson;
    saveJson(settingsFile(), s);
}

static void loadSettings(AppData* app) {
    json s = loadJson(settingsFile(), json::object());
    auto str = [&](const std::string& k, const std::string& def) -> std::string {
        return (s.contains(k) && s[k].is_string()) ? s[k].get<std::string>() : def;
    };
    app->defaultSearchEngine = str("defaultSearchEngine", "duckduckgo");
    if (!findEngine(app->defaultSearchEngine)) app->defaultSearchEngine = "duckduckgo";
    app->homeUri    = str("homeUri",    "froez://newtab");
    app->torProxy   = str("torProxy",   "socks5://127.0.0.1:9050");
    app->i2pProxy   = str("i2pProxy",   "http://127.0.0.1:4444");
    app->searxngUrl = str("searxngUrl", "https://searx.bndkt.io");
    app->whoogleUrl = str("whoogleUrl", "https://search.sethforprivacy.com");
    if (s.contains("maxHistory") && s["maxHistory"].is_number_integer())
        app->maxHistory = s["maxHistory"].get<int>();
    if (s.contains("darkMode") && s["darkMode"].is_boolean())
        app->darkMode = s["darkMode"].get<bool>();
    if (s.contains("httpsOnly") && s["httpsOnly"].is_boolean())
        app->httpsOnly = s["httpsOnly"].get<bool>();
    if (s.contains("jsBlocked") && s["jsBlocked"].is_boolean())
        app->jsBlocked = s["jsBlocked"].get<bool>();
    if (s.contains("zoomPerDomain") && s["zoomPerDomain"].is_object()) {
        for (auto& [k, v] : s["zoomPerDomain"].items())
            if (v.is_number()) app->zoomPerDomain[k] = v.get<double>();
    }
}

// ─── Implementación de buildFroezSettings (requiere AppData completo) ─────

static std::string buildFroezSettings(AppData* app) {
    const std::string& defaultEngine = app->defaultSearchEngine;
    std::string html = htmlHead("Ajustes — I4 Froez");
    html += htmlNavLinks("settings");
    html += "<h1>Ajustes</h1>";

    // ── Motor de busqueda + opciones de red/privacidad ───────────────────────
    html += "<div class='card'><h2>Configuracion general</h2>"
            "<p class='section-info'>Guardados en <code>~/.local/share/i4froez/settings.json</code> (cifrado).</p>"
            "<form id='cf'>"
            "<table style='width:100%;border-collapse:collapse'>"
            "<thead><tr><th>Opcion</th><th>Valor</th><th>Descripcion</th></tr></thead>"
            "<tbody>";

    // Motor de búsqueda (select)
    html += "<tr><td><span class='config-key'>Motor de busqueda</span></td><td>";
    html += "<select name='engine' style='font-size:12px;padding:4px 8px;width:100%;max-width:320px'>";
    for (const auto& e : SEARCH_ENGINES) {
        std::string sel = (e.id == defaultEngine) ? " selected" : "";
        html += "<option value='" + e.id + "'" + sel + ">" + e.name + "</option>";
    }
    html += "</select></td>"
            "<td><span class='config-desc'>Motor de busqueda por defecto</span></td></tr>";

    // Proxy Tor
    html += "<tr>"
            "<td><span class='config-key'>Proxy Tor</span></td>"
            "<td><input type='text' name='tor' value='" + app->torProxy + "'"
            " placeholder='socks5://127.0.0.1:9050'"
            " style='width:100%;max-width:320px;font-size:12px;padding:4px 8px'></td>"
            "<td><span class='config-desc'>Proxy para tormode</span></td>"
            "</tr>";

    // Proxy I2P
    html += "<tr>"
            "<td><span class='config-key'>Proxy I2P</span></td>"
            "<td><input type='text' name='i2p' value='" + app->i2pProxy + "'"
            " placeholder='http://127.0.0.1:4444'"
            " style='width:100%;max-width:320px;font-size:12px;padding:4px 8px'></td>"
            "<td><span class='config-desc'>Proxy para i2pmode</span></td>"
            "</tr>";

    // SearXNG URL
    html += "<tr>"
            "<td><span class='config-key'>Instancia SearXNG</span></td>"
            "<td><input type='text' name='searxng' value='" + htmlEscape(app->searxngUrl) + "'"
            " placeholder='https://searxng.example.com'"
            " style='width:100%;max-width:320px;font-size:12px;padding:4px 8px'></td>"
            "<td><span class='config-desc'>URL base de tu instancia SearXNG (sin /search)</span></td>"
            "</tr>";

    // Whoogle URL
    html += "<tr>"
            "<td><span class='config-key'>Instancia Whoogle</span></td>"
            "<td><input type='text' name='whoogle' value='" + htmlEscape(app->whoogleUrl) + "'"
            " placeholder='https://whoogle.example.com'"
            " style='width:100%;max-width:320px;font-size:12px;padding:4px 8px'></td>"
            "<td><span class='config-desc'>URL base de tu instancia Whoogle (sin /search)</span></td>"
            "</tr>";

    // Max historial
    html += "<tr>"
            "<td><span class='config-key'>Max entradas en historial</span></td>"
            "<td><input type='number' name='maxhistory' value='" + std::to_string(app->maxHistory) + "'"
            " min='10' max='50000'"
            " style='width:120px;font-size:12px;padding:4px 8px'></td>"
            "<td><span class='config-desc'>Max entradas en historial (10-50000)</span></td>"
            "</tr>";

    // Helper checkboxes
    auto editRowBool = [](const std::string& label, const std::string& name,
                          bool val, const std::string& desc) -> std::string {
        std::string chk = val ? " checked" : "";
        return "<tr>"
               "<td><span class='config-key'>" + label + "</span></td>"
               "<td><label style='display:flex;align-items:center;gap:8px;cursor:pointer'>"
               "<input type='checkbox' name='" + name + "' value='1'" + chk +
               " style='width:auto;accent-color:#89b4fa;width:16px;height:16px'>"
               "<span style='color:#a6adc8;font-size:12px'>" + (val ? "Activo" : "Inactivo") + "</span>"
               "</label></td>"
               "<td><span class='config-desc'>" + desc + "</span></td>"
               "</tr>";
    };
    html += editRowBool("Forzar HTTPS", "httpsonly", app->httpsOnly,
                        "Forzar HTTPS en todas las paginas (bloquea HTTP excepto .onion/.i2p/localhost)");
    html += editRowBool("Bloquear JavaScript", "jsblocked", app->jsBlocked,
                        "Bloquear JavaScript globalmente en todas las pestañas nuevas");

    html += "</tbody></table><br>"
            "<button type='button' class='primary' onclick='saveConfig()'>Guardar cambios</button>"
            "</form>"
            "<script>"
            "function saveConfig(){"
            "  var f=document.getElementById('cf');"
            "  var params=[];"
            "  var inputs=f.querySelectorAll('input,select');"
            "  for(var i=0;i<inputs.length;i++){"
            "    var el=inputs[i];"
            "    if(el.type==='checkbox'){"
            "      params.push(encodeURIComponent(el.name)+'='+(el.checked?'1':'0'));"
            "    } else {"
            "      params.push(encodeURIComponent(el.name)+'='+encodeURIComponent(el.value));"
            "    }"
            "  }"
            "  window.location.href='froez://set-config?'+params.join('&');"
            "}"
            "</script>"
            "</div>";

    // ── Pagina de inicio ─────────────────────────────────────────────────────
    html += "<div class='card'><h2>Pagina de inicio</h2>"
            "<p class='section-info'>La URL que se carga al abrir una nueva pestaña (comando: home).</p>"
            "<div style='display:flex;gap:8px;align-items:center;flex-wrap:wrap'>"
            "<input type='text' id='homeurl' placeholder='froez://newtab' value='" + htmlEscape(app->homeUri) + "'"
            " style='flex:1;min-width:200px;max-width:400px;font-size:12px;padding:4px 8px'>"
            "<button type='button' class='primary' onclick='saveHome()'>Guardar</button>"
            "</div>"
            "<script>"
            "function saveHome(){"
            "  var v=document.getElementById('homeurl').value.trim();"
            "  if(!v)v='froez://newtab';"
            "  window.location.href='froez://set-home?url='+encodeURIComponent(v);"
            "}"
            "</script></div>";

    html += "</body></html>";
    return html;
}

// ─── Helper: parsear query string ─────────────────────────────────────────

static std::string queryParam(const std::string& query, const std::string& key) {
    // query es lo que viene después de '?' en la URI
    std::string search = key + "=";
    size_t pos = query.find(search);
    if (pos == std::string::npos) return "";
    pos += search.size();
    size_t end = query.find('&', pos);
    std::string raw = (end == std::string::npos) ? query.substr(pos) : query.substr(pos, end - pos);
    // URL decode via GLib
    gchar* dec = g_uri_unescape_string(raw.c_str(), nullptr);
    std::string result = dec ? dec : raw;
    g_free(dec);
    return result;
}

// ─── Páginas de error personalizadas ──────────────────────────────────────

static std::string buildErrorPage(const std::string& title,
                                  const std::string& heading,
                                  const std::string& emoji,
                                  const std::string& desc,
                                  const std::string& hint,
                                  const std::string& badUrl = "") {
    std::string html = htmlHead(title + " — I4 Froez");
    html += R"(
<style>
.error-wrap{display:flex;flex-direction:column;align-items:center;justify-content:center;
  min-height:80vh;text-align:center;gap:16px}
.error-icon{font-size:72px;line-height:1;margin-bottom:8px}
.error-title{color:#f38ba8;font-size:28px;font-weight:700;margin:0}
.error-desc{color:#a6adc8;font-size:15px;max-width:520px;line-height:1.6}
.error-url{background:#181825;border:1px solid #313244;border-radius:6px;
  padding:8px 14px;font-family:monospace;font-size:12px;color:#6c7086;
  max-width:520px;word-break:break-all;margin-top:4px}
.error-hint{color:#585b70;font-size:13px;max-width:480px;line-height:1.5}
.error-actions{display:flex;gap:10px;margin-top:8px}
</style>
<div class='error-wrap'>
  <div class='error-icon'>)" + emoji + R"(</div>
  <h1 class='error-title'>)" + heading + R"(</h1>
)";
    if (!badUrl.empty())
        html += "  <div class='error-url'>" + htmlEscape(badUrl) + "</div>\n";
    html += "  <p class='error-desc'>" + desc + "</p>\n";
    html += "  <p class='error-hint'>" + hint + "</p>\n";
    html += R"HTML(  <div class='error-actions'>
    <button class='primary' onclick='history.back()'>Volver</button>
    <button onclick="window.location.reload()">Reintentar</button>
    <button onclick="window.location.href='froez://newtab'">Inicio</button>
  </div>
</div>
</body></html>)HTML";
    return html;
}

static std::string buildNotFoundPage(const std::string& url) {
    return buildErrorPage(
        "Pagina no encontrada",
        "404 — No encontrado",
        ":/",
        "El servidor respondio que la pagina no existe. Puede que el enlace "
        "este roto, la URL haya cambiado, o el recurso haya sido eliminado.",
        "Verifica que la URL este escrita correctamente. Si llegaste aqui "
        "desde un enlace externo, es posible que el sitio lo haya movido.",
        url
    );
}

static std::string buildConnectionRefusedPage(const std::string& url) {
    return buildErrorPage(
        "Conexion rechazada",
        "Conexion rechazada",
        ">:(",
        "El servidor en esa direccion rechazo la conexion activamente. "
        "Puede que no haya ningun servicio escuchando en ese puerto, "
        "o que un firewall este bloqueando el acceso.",
        "Si intentas acceder a un servidor local (Tor, I2P, etc.), "
        "asegurate de que el servicio este corriendo. Para sitios normales, "
        "el servidor puede estar temporalmente fuera de linea.",
        url
    );
}

static std::string buildConnectionTerminatedPage(const std::string& url) {
    return buildErrorPage(
        "Conexion interrumpida",
        "Conexion interrumpida",
        "<:0",
        "La conexion con el servidor se cerro de manera inesperada "
        "antes de que la pagina terminara de cargar. "
        "Esto puede ocurrir por problemas de red, tiempos de espera agotados, "
        "o que el servidor haya reiniciado.",
        "Intenta recargar la pagina. Si el problema persiste, "
        "revisa tu conexion a internet o la estabilidad del servidor destino.",
        url
    );
}

static std::string buildDnsFailedPage(const std::string& url) {
    return buildErrorPage(
        "Error de DNS",
        "No se pudo resolver el dominio",
        ":(",
        "El navegador no pudo traducir el nombre de dominio a una direccion IP. "
        "El dominio puede no existir, tu DNS puede estar mal configurado, "
        "o tu conexion a internet puede estar caida.",
        "Verifica tu conexion a internet. Si usas modo Tor o I2P, "
        "asegurate de que el proxy este activo. Para dominios .onion "
        "necesitas tormode activado.",
        url
    );
}

static std::string buildTlsErrorPage(const std::string& url) {
    return buildErrorPage(
        "Error de certificado",
        "Advertencia de seguridad",
        "! :0",
        "No se puede verificar la identidad del servidor de forma segura. "
        "El certificado TLS es invalido, esta vencido, o no corresponde "
        "al dominio solicitado. Proceder podria exponer tus datos.",
        "Si confias en este servidor (por ejemplo, es un servidor local tuyo), "
        "puedes intentar proceder con cuidado. De lo contrario, "
        "no introduzcas datos personales en este sitio.",
        url
    );
}

static std::string buildGenericErrorPage(const std::string& url, const std::string& detail) {
    return buildErrorPage(
        "Error de carga",
        "No se pudo cargar la pagina",
        "⚠ :(",
        "Ocurrio un error inesperado al cargar la pagina: " + htmlEscape(detail),
        "Intenta recargar o navega a otro sitio.",
        url
    );
}

// ─── Página secreta: froez://theCreation ──────────────────────────────────

static std::string buildTheCreation() {
    std::string html = htmlHead("theCreation — I4 Froez");
    html += R"(
<style>
.creation-hero{
  text-align:center;padding:48px 24px 32px;
}
.creation-hero h1{
  font-size:32px;color:#cba6f7;font-weight:800;margin-bottom:8px;
  letter-spacing:-0.5px;
}
.creation-hero .version{
  display:inline-block;background:#181825;border:1px solid #cba6f7;
  color:#cba6f7;border-radius:20px;padding:3px 14px;font-size:13px;
  font-family:monospace;margin-bottom:18px;
}
.creation-hero .tagline{
  color:#a6adc8;font-size:16px;max-width:540px;margin:0 auto 32px;
  line-height:1.65;
}
.creation-hero .hardware{
  display:inline-flex;align-items:center;gap:8px;
  background:#181825;border:1px solid #313244;border-radius:8px;
  padding:8px 18px;font-size:13px;color:#6c7086;
  font-family:monospace;margin-bottom:8px;
}
.creation-hero .hardware span{color:#f38ba8}
.from-mex{
  color:#a6e3a1;font-size:14px;margin-top:14px;font-style:italic;
}
.manifesto{
  background:#181825;border:1px solid #313244;border-radius:12px;
  padding:28px 32px;margin:0 auto 24px;max-width:680px;
}
.manifesto h2{color:#89b4fa;font-size:16px;font-weight:700;margin-bottom:14px}
.manifesto p{color:#a6adc8;font-size:14px;line-height:1.75;margin-bottom:10px}
.manifesto p:last-child{margin-bottom:0}
.goals{
  display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));
  gap:14px;max-width:680px;margin:0 auto 24px;
}
.goal-card{
  background:#181825;border:1px solid #313244;border-radius:10px;
  padding:18px 16px;
}
.goal-card .goal-icon{font-size:26px;margin-bottom:8px}
.goal-card h3{color:#cdd6f4;font-size:13px;font-weight:700;margin-bottom:6px}
.goal-card p{color:#6c7086;font-size:12px;line-height:1.5}
.tech-stack{
  background:#181825;border:1px solid #313244;border-radius:12px;
  padding:22px 28px;max-width:680px;margin:0 auto 24px;
}
.tech-stack h2{color:#89b4fa;font-size:16px;font-weight:700;margin-bottom:14px}
.tech-row{display:flex;align-items:center;gap:12px;padding:7px 0;
  border-bottom:1px solid #1e1e2e;font-size:13px}
.tech-row:last-child{border-bottom:none}
.tech-name{color:#cba6f7;font-family:monospace;min-width:150px}
.tech-desc{color:#6c7086}
.secret-footer{
  text-align:center;padding:20px;color:#45475a;font-size:11px;
  font-family:monospace;
}
.secret-footer span{color:#313244}
</style>

<div class='creation-hero'>
  <h1>I4 Froez</h1>
  <div class='version'>v0.8 Beta</div>
  <p class='tagline'>
    Mi objetivo es crear el <strong style='color:#cdd6f4'>Ultimate Freedom Browser</strong><br>
    desde una laptop Lenovo IdeaPad 330-14AST.
  </p>
  <div class='hardware'>
    Hardware: <span>Lenovo IdeaPad 330-14AST minimo, obvio</span>
  </div>
  <p class='from-mex'>
    De un mexicano que quiere ser peruano,<br>
    para la comunidad de internet!
  </p>
</div>

<div class='manifesto'>
  <h2>El Manifiesto</h2>
  <p>
    La internet fue construida para ser libre, libre de rastreo, libre de censura,
    libre de horrible vigilancia corporativa. Con el paso del tiempo, los navegadores 
    se convirtieron en herramientas de sacarte datos, disfrazadas como un navegador.
  </p>
  <p>
    I4 Froez nace del puro aburrimiento, de la curiosidad de entrar a la Deep Web
    y de la paranoia de estar siendo brutalmente vigilado por el gobierno cuando
    entras a internet, y claro, de un tipo random que solo le alcanza una laptop
    que salio hace 8 años.
  </p>
  <p>
    No necesitas hardware caro, no necesitas financiamiento, solo necesitas
    querer que la internet vuelva a ser un lugar donde puedas existir
    sin que alguien te este observando innecesariamente :( .
  </p>
</div>

<div class='goals'>
  <div class='goal-card'>
    <div class='goal-icon'>⊘</div>
    <h3>Privacidad real</h3>
    <p>Anti-fingerprinting, cifrado local AES-256-GCM, y lo ultimo pero no menos importante, sin ninguna telemetria metida de por medio.</p>
  </div>
  <div class='goal-card'>
    <div class='goal-icon'>☼</div>
    <h3>Redes libres</h3>
    <p>Soporte nativo para Tor e I2P, acceso a la <strong>Dark Web</strong> solo instalndo paquetes.</p>
  </div>
  <div class='goal-card'>
    <div class='goal-icon'>≫</div>
    <h3>Ligero</h3>
    <p>Diseñado para correr bien en hardware malo, una Lenovo IdeaPad 330 es suficiente para desarrollarlo y usarlo; eso es raro.</p>
  </div>
  <div class='goal-card'>
    <div class='goal-icon'>⌬</div>
    <h3>Variado</h3>
    <p>Shell personalizado, consola JS, inspector, herramientas para usuarios que las quieran.</p>
  </div>
  <div class='goal-card'>
    <div class='goal-icon'>✥</div>
    <h3>Para todos</h3>
    <p>Hecho con esperanza de vencer la vigilancia, para cualquier persona en cualquier lugar que quiera navegar con libertad.</p>
  </div>
  <div class='goal-card'>
    <div class='goal-icon'>⑀</div>
    <h3>Codigo abierto</h3>
    <p>Siempre libre, siempre auditable. Si no puedes ver el codigo, no puedes confiar en el programa.</p>
  </div>
</div>

<div class='tech-stack'>
  <h2>Stack tecnologico</h2>
  <div class='tech-row'><span class='tech-name'>GTK4 + WebKitGTK 6</span><span class='tech-desc'>UI nativa en Linux, motor de renderizado web</span></div>
  <div class='tech-row'><span class='tech-name'>C++20</span><span class='tech-desc'>Rendimiento y control total sobre la memoria</span></div>
  <div class='tech-row'><span class='tech-name'>OpenSSL (AES-256-GCM)</span><span class='tech-desc'>Cifrado de historial, marcadores y ajustes</span></div>
  <div class='tech-row'><span class='tech-name'>nlohmann/json</span><span class='tech-desc'>Serializacion de datos persistentes</span></div>
  <div class='tech-row'><span class='tech-name'>Tor / I2P </span><span class='tech-desc'>Capas de anonimato y redes alternativas</span></div>
  <div class='tech-row'><span class='tech-name'>PBKDF2-HMAC-SHA256</span><span class='tech-desc'>Derivacion de clave (200 000 iteraciones)</span></div>
</div>

<div class='secret-footer'>
  <span>/// </span>Esta pagina es secreta. Si llegaste aqui, sabes como funciona.<span> ///</span><br>
  froez://theCreation &nbsp;·&nbsp; I4 Froez v0.8 Beta &nbsp;·&nbsp; hecho de jugo de cebolla con lupa.
</div>

</body></html>
)";
    return html;
}

// ─── Página froez://peru — Datos de la República del Perú ───────────────────

static std::string buildFroezPeru() {
    std::string html = htmlHead("República del Perú — I4 Froez");
    html += htmlNavLinks("peru");
    html += R"HTML(
<style>
.data-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-bottom: 20px; }
.data-card { background: #181825; border: 1px solid #313244; border-radius: 10px; padding: 18px 20px; }
.data-card h3 { color: #89b4fa; font-size: 13px; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.08em; margin-bottom: 14px; border-bottom: 1px solid #313244; padding-bottom: 8px; }
.data-row { display: flex; justify-content: space-between; align-items: baseline;
    padding: 5px 0; border-bottom: 1px solid #1e1e2e; font-size: 13px; gap: 12px; }
.data-row:last-child { border-bottom: none; }
.data-key { color: #6c7086; flex-shrink: 0; }
.data-val { color: #cdd6f4; text-align: right; font-family: monospace; font-size: 12px; }
.data-val.hl { color: #a6e3a1; }
.data-val.warn { color: #f38ba8; }
.data-val.accent { color: #cba6f7; }
.hero { background: linear-gradient(135deg, #1e1e2e 0%, #181825 100%);
    border: 1px solid #313244; border-radius: 12px; padding: 28px 28px 20px;
    margin-bottom: 20px; position: relative; overflow: hidden; }
.hero::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 4px;
    background: linear-gradient(90deg, #D91023, #FFFFFF, #D91023); }
.hero-flag { font-size: 13px; color: #6c7086; margin-bottom: 6px; font-family: monospace; }
.hero h2 { color: #cdd6f4; font-size: 22px; font-weight: 700; margin-bottom: 4px; }
.hero-sub { color: #89b4fa; font-size: 14px; margin-bottom: 16px; font-style: italic; }
.hero-desc { color: #a6adc8; font-size: 13px; line-height: 1.75; max-width: 700px; }
.phrase-table td:nth-child(2) { font-size: 15px; color: #cba6f7; }
.phrase-table td:nth-child(3) { font-size: 11px; color: #6c7086; font-family: monospace; }
.tag { display: inline-block; background: #313244; border-radius: 4px;
    padding: 2px 8px; font-size: 11px; font-family: monospace; margin: 2px; color: #cdd6f4; }
.timeline-row { display: flex; gap: 14px; padding: 8px 0; border-bottom: 1px solid #1e1e2e; font-size: 13px; }
.timeline-row:last-child { border-bottom: none; }
.tl-year { color: #89b4fa; font-family: monospace; font-size: 12px; min-width: 48px; flex-shrink: 0; }
.tl-event { color: #a6adc8; line-height: 1.5; }
</style>

<div class="hero">
  <div class="hero-flag">&#9646; Rojo &nbsp;&#9646; Blanco &nbsp;&#9646; Rojo — bicolor vertical con escudo al centro</div>
  <h2>República del Perú</h2>
  <div class="hero-sub">Piruw Suyu &nbsp;·&nbsp; Perú Ripuwllaqta &nbsp;·&nbsp; República del Perú</div>
  <p class="hero-desc">
    País soberano ubicado en la costa occidental de América del Sur. Sede del Imperio inca
    (Tawantinsuyu), una de las civilizaciones más grandes de la historia. Su capital, Lima,
    es una metrópolis de más de 10 millones de habitantes y centro político, cultural y
    económico del país.
  </p>
</div>

)HTML";

    // Datos geograficos y demograficos
    html += "<div class='data-grid'>";

    // Tarjeta: Datos generales
    html += "<div class='data-card'><h3>Datos generales</h3>"
            "<div class='data-row'><span class='data-key'>Capital</span><span class='data-val hl'>Lima</span></div>"
            "<div class='data-row'><span class='data-key'>Superficie</span><span class='data-val'>1 285 216 km²</span></div>"
            "<div class='data-row'><span class='data-key'>Población</span><span class='data-val'>~33 000 000 hab.</span></div>"
            "<div class='data-row'><span class='data-key'>Densidad</span><span class='data-val'>~26 hab/km²</span></div>"
            "<div class='data-row'><span class='data-key'>Estatus</span><span class='data-val accent'>República soberana</span></div>"
            "<div class='data-row'><span class='data-key'>Idiomas oficiales</span><span class='data-val'>Español, quechua, aimara</span></div>"
            "<div class='data-row'><span class='data-key'>Religión predominante</span><span class='data-val'>Catolicismo (~75 %)</span></div>"
            "</div>";

    // Tarjeta: Geografía
    html += "<div class='data-card'><h3>Geografía</h3>"
            "<div class='data-row'><span class='data-key'>Región</span><span class='data-val'>América del Sur occidental</span></div>"
            "<div class='data-row'><span class='data-key'>Punto más alto</span><span class='data-val'>Huascarán — 6 768 m</span></div>"
            "<div class='data-row'><span class='data-key'>Río principal</span><span class='data-val'>Amazonas (nace en Perú)</span></div>"
            "<div class='data-row'><span class='data-key'>Lago destacado</span><span class='data-val'>Titicaca — lago navegable más alto del mundo</span></div>"
            "<div class='data-row'><span class='data-key'>Regiones naturales</span><span class='data-val'>Costa, Sierra, Selva (Amazonía)</span></div>"
            "<div class='data-row'><span class='data-key'>Países vecinos</span><span class='data-val'>Ecuador, Colombia, Brasil, Bolivia, Chile</span></div>"
            "</div>";

    // Tarjeta: Economía
    html += "<div class='data-card'><h3>Economía</h3>"
            "<div class='data-row'><span class='data-key'>PIB (aprox.)</span><span class='data-val'>~260 000 M USD/año</span></div>"
            "<div class='data-row'><span class='data-key'>Sectores clave</span><span class='data-val'>Minería, agricultura, turismo, pesca</span></div>"
            "<div class='data-row'><span class='data-key'>Desempleo (est.)</span><span class='data-val warn'>~7 % (urbano)</span></div>"
            "<div class='data-row'><span class='data-key'>Moneda</span><span class='data-val'>Sol (PEN)</span></div>"
            "<div class='data-row'><span class='data-key'>Exportación principal</span><span class='data-val'>Cobre, oro, zinc, harina de pescado</span></div>"
            "</div>";

    // Tarjeta: Idioma quechua
    html += "<div class='data-card'><h3>El idioma quechua</h3>"
            "<div class='data-row'><span class='data-key'>Nombre propio</span><span class='data-val accent'>Runasimi</span></div>"
            "<div class='data-row'><span class='data-key'>Familia</span><span class='data-val'>Quechua (aislada)</span></div>"
            "<div class='data-row'><span class='data-key'>Hablantes</span><span class='data-val'>~8 000 000 (mundo)</span></div>"
            "<div class='data-row'><span class='data-key'>Escritura</span><span class='data-val'>Latino (adaptado)</span></div>"
            "<div class='data-row'><span class='data-key'>Consonantes</span><span class='data-val hl'>~30 fonemas (aspiradas, glotalizadas)</span></div>"
            "<div class='data-row'><span class='data-key'>Vocales</span><span class='data-val'>3 (a, i, u)</span></div>"
            "<div class='data-row'><span class='data-key'>Tipología</span><span class='data-val'>Aglutinante, sufijante</span></div>"
            "<div class='data-row'><span class='data-key'>Orden básico</span><span class='data-val'>SOV (Sujeto-Objeto-Verbo)</span></div>"
            "<div class='data-row'><span class='data-key'>Cooficial</span><span class='data-val'>Español (dominante nacional)</span></div>"
            "</div>";

    html += "</div>"; // end data-grid

    // Seccion: Historia resumida
    html += "<div class='card'><h2>Historia clave</h2>";
    auto tlRow = [&](const std::string& year, const std::string& event) {
        html += "<div class='timeline-row'><span class='tl-year'>" + year +
                "</span><span class='tl-event'>" + event + "</span></div>";
    };
    tlRow("~900 d.C.", "Florecen culturas pre-incas: Wari, Tiwanaku, Chimú.");
    tlRow("1438",      "Pachacútec expande el Tawantinsuyu (Imperio inca) convirtiéndolo en el mayor estado de América precolombina.");
    tlRow("1532",      "Francisco Pizarro llega a Cajamarca. Captura y ejecuta al inca Atahualpa. Inicio de la conquista española.");
    tlRow("1542",      "Creación del Virreinato del Perú, el más importante de América del Sur.");
    tlRow("1780–81",   "Gran rebelión de Túpac Amaru II, precursora de la independencia.");
    tlRow("1821",      "José de San Martín proclama la independencia del Perú en Lima (28 de julio).");
    tlRow("1824",      "Batalla de Ayacucho. Última gran derrota española. Consolidación de la independencia.");
    tlRow("1879–84",   "Guerra del Pacífico contra Chile y Bolivia. Perú pierde Tarapacá y Arica.");
    tlRow("1990s",     "Gobierno de Fujimori. Derrota de Sendero Luminoso. Reformas económicas y autoritarismo.");
    tlRow("2021",      "Pedro Castillo, maestro rural, gana la presidencia. Primer mandatario de origen campesino.");
    html += "</div>";

    // Seccion: Frases en quechua
    html += "<div class='card'><h2>Frases en Runasimi (quechua)</h2>"
            "<table class='phrase-table' style='width:100%;border-collapse:collapse;font-size:13px'>"
            "<thead><tr><th>Español</th><th>Quechua</th><th>Pronunciación</th></tr></thead><tbody>";
    auto ph = [&](const std::string& es, const std::string& qu, const std::string& tr) {
        html += "<tr><td style='padding:7px 8px;border-bottom:1px solid #1e1e2e'>" + es +
                "</td><td style='padding:7px 8px;border-bottom:1px solid #1e1e2e;font-size:15px;color:#cba6f7'>" + qu +
                "</td><td style='padding:7px 8px;border-bottom:1px solid #1e1e2e;font-size:11px;color:#6c7086;font-family:monospace'>" + tr + "</td></tr>";
    };
    ph("Hola",               "Rimaykullayki",         "ri-may-ku-llai-ki");
    ph("Gracias",            "Sulpayki",               "sul-pai-ki");
    ph("Sí",                 "Arí",                   "a-rí");
    ph("No",                 "Mana",                  "ma-na");
    ph("Por favor",          "Ama hina kaspa",         "a-ma hi-na kas-pa");
    ph("Lo siento",          "Pampachaykuway",         "pam-pa-chay-ku-way");
    ph("¿Cómo estás?",       "Imaynallan kashanki?",   "i-may-na-llan ka-shan-ki");
    ph("Me llamo...",        "Sutiymi...",             "su-tiy-mi...");
    ph("No entiendo",        "Mana entiendiниchu",     "ma-na en-tien-di-ni-chu");
    ph("Agua",               "Yaku",                  "ya-ku");
    ph("Sol",                "Inti",                  "in-ti");
    ph("Tierra / mundo",     "Pachamama",             "pa-cha-ma-ma");
    ph("Hermano",            "Wawqi",                 "wauk-i");
    ph("Adiós",              "Tupananchiskama",        "tu-pa-nan-chis-ka-ma");
    ph("Bonito / bueno",     "Sumaq",                 "su-mak");
    ph("Persona / gente",    "Runa",                  "ru-na");
    html += "</tbody></table>"
            "<p style='color:#6c7086;font-size:11px;margin-top:10px'>"
            "El quechua tiene consonantes aspiradas (ph, th, kh) y glotalizadas (p', t', k') "
            "sin equivalente directo en español. Es un idioma aglutinante: añade sufijos para expresar "
            "tiempo, modo, evidencialidad y relaciones gramaticales."
            "</p></div>";

    // Seccion: Datos culturales
    html += "<div class='card'><h2>Cultura y datos curiosos</h2>"
            "<div class='data-row'><span class='data-key'>Danza tradicional</span><span class='data-val accent'>Marinera norteña (danza nacional)</span></div>"
            "<div class='data-row'><span class='data-key'>Instrumento típico</span><span class='data-val'>Charango (laúd andino) y quena (flauta)</span></div>"
            "<div class='data-row'><span class='data-key'>Comida emblemática</span><span class='data-val'>Ceviche (Patrimonio Cultural de la Nación)</span></div>"
            "<div class='data-row'><span class='data-key'>Sitio arqueológico</span><span class='data-val hl'>Machu Picchu — Maravilla del Mundo Moderno</span></div>"
            "<div class='data-row'><span class='data-key'>Concepto andino central</span><span class='data-val accent'>Pachamama — Madre Tierra</span></div>"
            "<div class='data-row'><span class='data-key'>Líneas de Nazca</span><span class='data-val'>Geoglifos gigantes en el desierto, ~500 a.C.–500 d.C.</span></div>"
            "<div class='data-row'><span class='data-key'>Biodiversidad</span><span class='data-val'>Uno de los 17 países megadiversos del mundo</span></div>"
            "</div>";

    html += "</body></html>";
    return html;
}

// ─── Página froez://downloads ─────────────────────────────────────────────

static std::string buildFroezDownloads() {
    std::string html = htmlHead("Descargas — I4 Froez");
    html += htmlNavLinks("downloads");
    html += "<h1>Descargas</h1>";
    html += "<div class='card'><p class='section-info'>El panel de descargas se muestra en la barra lateral de la ventana."
            " Usa el menu ☰ → Descargas o el atajo <kbd>Ctrl+Alt+D</kbd> para abrirlo.</p></div>";
    html += "</body></html>";
    return html;
}

// ─── Handler del esquema froez:// ─────────────────────────────────────────
// Llamado por WebKitGTK cuando cualquier WebView intenta cargar froez://...

static void froezSchemeHandler(WebKitURISchemeRequest* request, gpointer) {
    const char* uriRaw = webkit_uri_scheme_request_get_uri(request);
    if (!uriRaw) {
        webkit_uri_scheme_request_finish_error(request,
            g_error_new(G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "URI nula"));
        return;
    }

    std::string uri(uriRaw);
    // Separar "froez://page?query" → page y query
    std::string rest = uri.substr(8); // quitar "froez://"
    size_t qmark = rest.find('?');
    std::string page  = qmark != std::string::npos ? rest.substr(0, qmark) : rest;
    std::string query = qmark != std::string::npos ? rest.substr(qmark + 1) : "";

    // Quitar slash final de page si existe
    while (!page.empty() && page.back() == '/') page.pop_back();

    AppData* app = &g_app;
    std::string html;
    std::string redirectUri;

    // ── Tabla de páginas HTML simples (sin lógica extra) ──────────────────
    // Usamos una función que devuelve string vacío para indicar "no match"
    // Las páginas con lógica propia se manejan por separado abajo.
    static const std::unordered_map<std::string,
        std::function<std::string(AppData*)>> htmlPages = {
        { "newtab",      [](AppData* a){ return buildFroezNewtab(a->defaultSearchEngine); } },
        { "",            [](AppData* a){ return buildFroezNewtab(a->defaultSearchEngine); } },
        { "settings",    [](AppData* a){ return buildFroezSettings(a); } },
        { "bookmarks",   [](AppData* a){ return buildFroezBookmarks(a->bookmarks); } },
        { "history",     [](AppData* a){ return buildFroezHistory(a->history); } },
        { "theCreation", [](AppData* )  { return buildTheCreation(); } },
        { "peru",        [](AppData* )  { return buildFroezPeru(); } },
        { "downloads",   [](AppData* )  { return buildFroezDownloads(); } },
        { "i2p-blocked", [](AppData* )  {
            return buildErrorPage(
                "Bloqueado en perfil I2P",
                "Destino no permitido en I2P",
                ":I",
                "En el perfil I2P solo se permite navegar a sitios <strong>.i2p</strong>. "
                "Intentar cargar sitios clearnet desde este perfil podria mezclar trafico "
                "I2P con Internet normal y comprometer el anonimato.",
                "Para navegar a sitios clearnet, cambia al perfil Clearnet con el comando "
                "<code>clearnet</code> en el terminal. Esto hara un restart limpio del perfil.",
                ""
            );
        }},
    };

    // ── Acciones (redirigen sin respuesta HTML) ───────────────────────────
    if (page == "set-engine") {
        std::string id = queryParam(query, "id");
        if (findEngine(id)) {
            app->defaultSearchEngine = id;
            saveSettings(app);
        }
        redirectUri = "froez://settings";

    } else if (page == "set-home") {
        std::string url = queryParam(query, "url");
        if (!url.empty()) {
            app->homeUri = url;
            saveSettings(app);
        }
        redirectUri = "froez://settings?saved=1";

    } else if (page == "set-config") {
        // froez://set-config?engine=...&tor=...&i2p=...&searxng=...&whoogle=...&maxhistory=...&httpsonly=...&jsblocked=...
        auto qp = [&](const std::string& k){ return queryParam(query, k); };
        if (auto v = qp("engine"); !v.empty() && findEngine(v)) app->defaultSearchEngine = v;
        if (auto v = qp("tor");      !v.empty()) app->torProxy   = v;
        if (auto v = qp("i2p");      !v.empty()) app->i2pProxy   = v;
        if (auto v = qp("searxng");  !v.empty()) app->searxngUrl = v;
        if (auto v = qp("whoogle");  !v.empty()) app->whoogleUrl = v;
        if (auto v = qp("maxhistory"); !v.empty()) {
            try { int n = std::stoi(v); if (n >= 10 && n <= 50000) app->maxHistory = n; } catch(...) {}
        }
        auto boolParam = [](const std::string& v){ return v == "1" || v == "true" || v == "on"; };
        app->httpsOnly = boolParam(qp("httpsonly"));
        app->jsBlocked = boolParam(qp("jsblocked"));
        saveSettings(app);
        redirectUri = "froez://settings?saved=1";

    } else if (page == "remove-bookmark") {
        std::string url = queryParam(query, "url");
        if (!url.empty()) app->removeBookmark(url);
        redirectUri = "froez://bookmarks";

    } else if (page == "clear-history") {
        app->history = json::array();
        saveJson(historyFile(), app->history);
        redirectUri = "froez://history";

    } else if (page == "remove-history") {
        std::string url   = queryParam(query, "url");
        std::string ts    = queryParam(query, "ts");
        if (!url.empty()) {
            json newHist = json::array();
            bool removed = false;
            for (const auto& entry : app->history) {
                // Si coincide url Y ts (si se proporciono ts), eliminar solo esa entrada
                bool matchUrl = (entry.value("url","") == url);
                bool matchTs  = ts.empty() || (entry.value("ts","") == ts);
                if (matchUrl && matchTs && !removed) {
                    removed = true; // eliminar solo la primera coincidencia
                } else {
                    newHist.push_back(entry);
                }
            }
            if (removed) {
                app->history = newHist;
                saveJson(historyFile(), app->history);
            }
        }
        redirectUri = "froez://history";

    } else if (page == "search") {
        // froez://search?q=... → redirigir al motor por defecto
        redirectUri = searchWithDefault(queryParam(query, "q"),
            app->defaultSearchEngine, app->searxngUrl, app->whoogleUrl);

    // ── Tabla de páginas HTML simples ─────────────────────────────────────
    } else if (auto it = htmlPages.find(page); it != htmlPages.end()) {
        html = it->second(app);
        // Toast de guardado para settings
        if (page == "settings" && queryParam(query, "saved") == "1") {
            std::string notice =
                "<div id='saved-notice' style='position:fixed;top:16px;right:16px;"
                "background:#a6e3a1;color:#1e1e2e;padding:10px 18px;border-radius:8px;"
                "font-weight:600;font-size:13px;z-index:999'>Configuracion guardada</div>"
                "<script>setTimeout(function(){var n=document.getElementById('saved-notice');"
                "if(n)n.style.display='none';},2500);</script>";
            size_t pos2 = html.rfind("</body>");
            if (pos2 != std::string::npos) html.insert(pos2, notice);
        }

    } else {
        html = buildNotFoundPage("froez://" + page);
    }

    // Si hay redirección: mini-HTML con meta-refresh
    if (!redirectUri.empty()) {
        html = "<!DOCTYPE html><html><head><meta charset='utf-8'>"
               "<meta http-equiv='refresh' content='0;url=" + redirectUri + "'>"
               "</head><body></body></html>";
    }

    GBytes* bytes = g_bytes_new(html.c_str(), html.size());
    GInputStream* stream = g_memory_input_stream_new_from_bytes(bytes);
    webkit_uri_scheme_request_finish(request, stream,
        (gint64)html.size(), "text/html; charset=utf-8");
    g_object_unref(stream);
    g_bytes_unref(bytes);
}

// ─── Creación de WebView ────────────────────────────────────────────────────

static WebKitWebView* makeWebview(BrowserWindow* bw, const std::string& mode);

// Callbacks de señales del WebView (declaraciones adelantadas)
static void onUriChanged(GObject* obj, GParamSpec*, gpointer data);
static void onTitleChanged(GObject* obj, GParamSpec*, gpointer data);
static void onLoadChanged(WebKitWebView* wv, WebKitLoadEvent event, gpointer data);
static gboolean onLoadFailed(WebKitWebView* wv, WebKitLoadEvent event, const char* failingUri, GError* error, gpointer data);
static void onProgress(GObject* obj, GParamSpec*, gpointer data);

static WebKitWebView* makeWebview(BrowserWindow* bw, const std::string& mode) {
    WebKitWebView* wv = nullptr;

    // El proxy depende del perfil activo de la sesión, no del parámetro mode.
    // mode sigue usándose para el badge visual y para compatibilidad con
    // enableNetworkMode, pero la red real la determina g_activeProfile.
    bool useTor = (g_activeProfile == BrowserProfile::TOR);
    bool useI2P = (g_activeProfile == BrowserProfile::I2P);

    if (useTor) {
        WebKitNetworkSession* ns = webkit_network_session_new_ephemeral();
        // IMPORTANTE: webkit_network_proxy_settings_new NO soporta credenciales
        // embebidas en la URI (user:pass@host) — las ignora silenciosamente y
        // el proxy no se aplica. Usar la URI limpia sin credenciales.
        // El circuit isolation se logra con sesiones efímeras separadas por pestaña:
        // cada WebKitNetworkSession efímera abre sus propias conexiones TCP a Tor,
        // y Tor asigna circuitos distintos a streams con cookies de aislamiento distintas.
        const std::string& proxyStr = bw->app->torProxy; // "socks5://127.0.0.1:9050"
        g_message("[i4froez] Tor proxy: %s", proxyStr.c_str());
        WebKitNetworkProxySettings* ps = webkit_network_proxy_settings_new(
            proxyStr.c_str(), nullptr);
        webkit_network_session_set_proxy_settings(ns,
            WEBKIT_NETWORK_PROXY_MODE_CUSTOM, ps);
        webkit_network_proxy_settings_free(ps);
        wv = WEBKIT_WEB_VIEW(g_object_new(WEBKIT_TYPE_WEB_VIEW,
            "network-session", ns, nullptr));
        g_object_unref(ns);
    } else if (useI2P) {
        WebKitNetworkSession* ns = webkit_network_session_new_ephemeral();
        const std::string& proxyStr = bw->app->i2pProxy; // "http://127.0.0.1:4444"
        g_message("[i4froez] I2P proxy: %s", proxyStr.c_str());
        WebKitNetworkProxySettings* ps = webkit_network_proxy_settings_new(
            proxyStr.c_str(), nullptr);
        webkit_network_session_set_proxy_settings(ns,
            WEBKIT_NETWORK_PROXY_MODE_CUSTOM, ps);
        webkit_network_proxy_settings_free(ps);
        wv = WEBKIT_WEB_VIEW(g_object_new(WEBKIT_TYPE_WEB_VIEW,
            "network-session", ns, nullptr));
        g_object_unref(ns);
    } else {
        wv = WEBKIT_WEB_VIEW(webkit_web_view_new());
    }

    // Fingerprinting coherente con el perfil activo de la sesión
    BrowserProfile fpProfile = g_activeProfile;

    // User-Agent coherente con el perfil
    std::string ua;
    switch (fpProfile) {
        case BrowserProfile::TOR:
            ua = "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0";
            break;
        case BrowserProfile::I2P:
            ua = "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0";
            break;
        default:
            ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
            break;
    }

    // Configuración de seguridad
    WebKitSettings* s = webkit_settings_new();
    webkit_settings_set_enable_developer_extras(s, FALSE);
    webkit_settings_set_javascript_can_access_clipboard(s, FALSE);
    webkit_settings_set_enable_webrtc(s, FALSE);
    webkit_settings_set_enable_mediasource(s, FALSE);
    webkit_settings_set_enable_encrypted_media(s, FALSE);
    webkit_settings_set_enable_back_forward_navigation_gestures(s, FALSE);
    webkit_settings_set_media_playback_requires_user_gesture(s, TRUE);
    webkit_settings_set_javascript_can_open_windows_automatically(s, FALSE);
    webkit_settings_set_allow_modal_dialogs(s, FALSE);
    webkit_settings_set_enable_page_cache(s, FALSE);
    webkit_settings_set_user_agent(s, ua.c_str());
    webkit_settings_set_enable_javascript(s, !bw->app->jsBlocked);
    webkit_web_view_set_settings(wv, s);
    g_object_unref(s);

    gtk_widget_set_vexpand(GTK_WIDGET(wv), TRUE);
    gtk_widget_set_hexpand(GTK_WIDGET(wv), TRUE);

    // Señales
    g_signal_connect(wv, "notify::uri",   G_CALLBACK(onUriChanged),   bw);
    g_signal_connect(wv, "notify::title", G_CALLBACK(onTitleChanged), bw);
    g_signal_connect(wv, "load-changed",  G_CALLBACK(onLoadChanged),  bw);
    g_signal_connect(wv, "load-failed",   G_CALLBACK(onLoadFailed),   bw);
    g_signal_connect(wv, "notify::estimated-load-progress", G_CALLBACK(onProgress), bw);

    // Anti-fingerprinting — script coherente con el perfil de red
    std::string fpJs = buildFpJs(fpProfile);
    WebKitUserContentManager* ucm = webkit_web_view_get_user_content_manager(wv);
    WebKitUserScript* fpScript = webkit_user_script_new(
        fpJs.c_str(),
        WEBKIT_USER_CONTENT_INJECT_TOP_FRAME,
        WEBKIT_USER_SCRIPT_INJECT_AT_DOCUMENT_START,
        nullptr, nullptr
    );
    webkit_user_content_manager_add_script(ucm, fpScript);
    webkit_user_script_unref(fpScript);

    return wv;
}

// ─── Funciones de gestión de pestañas ──────────────────────────────────────

static WebKitWebView* currentWv(BrowserWindow* bw) {
    return bw->tabs[bw->currentTab].webview;
}

static TabData& currentTd(BrowserWindow* bw) {
    return bw->tabs[bw->currentTab];
}

static void updateBadge(BrowserWindow* bw, const std::string& mode);
static void updateNavButtons(BrowserWindow* bw);
static void updateBookmarkStar(BrowserWindow* bw);
static void updateSecurityBadge(BrowserWindow* bw, const std::string& uri);
static void setupDownloadHandler(BrowserWindow* bw, WebKitWebView* wv);
static void switchTab(BrowserWindow* bw, int idx);
static void clearTabData(BrowserWindow* bw, TabData& td);
static void rebuildTabbar(BrowserWindow* bw);
static void openTab(BrowserWindow* bw, const char* uri = nullptr, const std::string& mode = "normal");
static void onCloseTab(BrowserWindow* bw, int idx);

// Callbacks de pestaña
struct TabCallbackData { BrowserWindow* bw; int idx; };

static void onTabTitleBtnClicked(GtkButton*, gpointer data) {
    auto* d = static_cast<TabCallbackData*>(data);
    switchTab(d->bw, d->idx);
}
static void onCloseTabBtnClicked(GtkButton*, gpointer data) {
    auto* d = static_cast<TabCallbackData*>(data);
    onCloseTab(d->bw, d->idx);
}

// ─── Mover pestaña (reordenar) ────────────────────────────────────────────
// Mueve la pestaña en posición srcIdx a destIdx, actualiza el vector de tabs
// y el GtkStack, y reconstruye la tabbar.
static void moveTab(BrowserWindow* bw, int srcIdx, int destIdx) {
    if (srcIdx == destIdx) return;
    if (srcIdx < 0 || srcIdx >= (int)bw->tabs.size()) return;
    if (destIdx < 0 || destIdx >= (int)bw->tabs.size()) return;

    // Proteger todos los WebViews con una referencia extra antes de tocar el stack.
    // gtk_stack_remove libera la referencia que el stack tiene; sin g_object_ref
    // el widget se destruiría inmediatamente.
    for (auto& td : bw->tabs)
        g_object_ref(td.webview);

    // Reordenar el vector
    TabData moved = bw->tabs[srcIdx];
    bw->tabs.erase(bw->tabs.begin() + srcIdx);
    bw->tabs.insert(bw->tabs.begin() + destIdx, moved);

    // Remover todos del stack (no los destruye porque tenemos la ref extra)
    for (auto& td : bw->tabs)
        gtk_stack_remove(bw->tabStack, GTK_WIDGET(td.webview));

    // Re-añadir con nombres correctos y soltar la ref extra
    for (int i = 0; i < (int)bw->tabs.size(); i++) {
        std::string name = "tab" + std::to_string(i);
        gtk_stack_add_named(bw->tabStack, GTK_WIDGET(bw->tabs[i].webview), name.c_str());
        g_object_unref(bw->tabs[i].webview);
    }

    // Ajustar currentTab
    if (bw->currentTab == srcIdx)
        bw->currentTab = destIdx;
    else if (srcIdx < destIdx) {
        if (bw->currentTab > srcIdx && bw->currentTab <= destIdx)
            bw->currentTab--;
    } else {
        if (bw->currentTab >= destIdx && bw->currentTab < srcIdx)
            bw->currentTab++;
    }

    rebuildTabbar(bw);
    switchTab(bw, bw->currentTab);
}

// Contexto para el idle callback que dispara moveTab fuera del ciclo de drag
struct MoveTabIdleCtx { BrowserWindow* bw; int src; int dst; };

static gboolean moveTabIdle(gpointer p) {
    auto* ctx = static_cast<MoveTabIdleCtx*>(p);
    moveTab(ctx->bw, ctx->src, ctx->dst);
    delete ctx;
    return G_SOURCE_REMOVE;
}

static GtkBox* makeTabWidget(BrowserWindow* bw, int idx) {
    GtkBox* box = GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0));
    gtk_widget_add_css_class(GTK_WIDGET(box), "tab-btn");

    std::string tabLabel = "Tab " + std::to_string(idx + 1);
    GtkButton* titleBtn = GTK_BUTTON(gtk_button_new_with_label(tabLabel.c_str()));
    gtk_widget_add_css_class(GTK_WIDGET(titleBtn), "tab-title-btn");
    gtk_widget_set_hexpand(GTK_WIDGET(titleBtn), TRUE);

    auto* td = new TabCallbackData{bw, idx};
    g_signal_connect_data(titleBtn, "clicked", G_CALLBACK(onTabTitleBtnClicked),
        td, [](gpointer p, GClosure*) { delete static_cast<TabCallbackData*>(p); }, GConnectFlags(0));

    GtkButton* closeBtn = GTK_BUTTON(gtk_button_new_with_label("x"));
    gtk_widget_add_css_class(GTK_WIDGET(closeBtn), "close-tab-btn");

    auto* cd = new TabCallbackData{bw, idx};
    g_signal_connect_data(closeBtn, "clicked", G_CALLBACK(onCloseTabBtnClicked),
        cd, [](gpointer p, GClosure*) { delete static_cast<TabCallbackData*>(p); }, GConnectFlags(0));

    // Guardar referencia al botón de título en qdata
    g_object_set_data(G_OBJECT(box), "title-btn", titleBtn);

    // Guardar el índice directamente en el widget para recuperarlo en los callbacks
    // de drag sin depender de closures con punteros heap que pueden invalidarse.
    g_object_set_data(G_OBJECT(box), "tab-idx", GINT_TO_POINTER(idx));
    g_object_set_data(G_OBJECT(box), "bw",      bw);

    gtk_box_append(box, GTK_WIDGET(titleBtn));
    gtk_box_append(box, GTK_WIDGET(closeBtn));

    // ── Drag-and-drop para reordenar pestañas ─────────────────────────────
    // Fuente: al iniciar el drag seteamos dragSrcIdx en bw (accedido via qdata)
    GtkDragSource* dragSrc = gtk_drag_source_new();
    gtk_drag_source_set_actions(dragSrc, GDK_ACTION_MOVE);

    {
        auto prepareCb = +[](GtkDragSource* ds, gdouble, gdouble) -> GdkContentProvider* {
            GtkWidget* w = gtk_event_controller_get_widget(GTK_EVENT_CONTROLLER(ds));
            if (!w) return nullptr;
            BrowserWindow* b = static_cast<BrowserWindow*>(g_object_get_data(G_OBJECT(w), "bw"));
            int i = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(w), "tab-idx"));
            if (b) b->dragSrcIdx = i;
            GValue v = G_VALUE_INIT;
            g_value_init(&v, G_TYPE_INT);
            g_value_set_int(&v, i);
            GdkContentProvider* cp = gdk_content_provider_new_for_value(&v);
            g_value_unset(&v);
            return cp;
        };
        g_signal_connect(dragSrc, "prepare", G_CALLBACK(prepareCb), nullptr);
    }

    gtk_widget_add_controller(GTK_WIDGET(box), GTK_EVENT_CONTROLLER(dragSrc));

    // Destino: al soltar disparamos moveTab en un idle para no interrumpir el drag
    GtkDropTarget* dropTgt = gtk_drop_target_new(G_TYPE_INT, GDK_ACTION_MOVE);

    {
        auto dropCb = +[](GtkDropTarget* dt, const GValue*, gdouble, gdouble) -> gboolean {
            GtkWidget* w = gtk_event_controller_get_widget(GTK_EVENT_CONTROLLER(dt));
            if (!w) return FALSE;
            BrowserWindow* b = static_cast<BrowserWindow*>(g_object_get_data(G_OBJECT(w), "bw"));
            int dst = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(w), "tab-idx"));
            if (!b || b->dragSrcIdx < 0 || b->dragSrcIdx == dst) {
                if (b) b->dragSrcIdx = -1;
                return FALSE;
            }
            // Diferir la reconstrucción de la UI al siguiente ciclo del event loop.
            // Si llamamos moveTab/rebuildTabbar aquí mismo, destruimos los widgets
            // del drag mientras GTK aún los necesita → Segfault.
            auto* ctx = new MoveTabIdleCtx{b, b->dragSrcIdx, dst};
            b->dragSrcIdx = -1;
            g_idle_add(moveTabIdle, ctx);
            return TRUE;
        };
        g_signal_connect(dropTgt, "drop", G_CALLBACK(dropCb), nullptr);
    }

    {
        auto enterCb = +[](GtkDropTarget* dt, gdouble, gdouble) -> GdkDragAction {
            GtkWidget* w = gtk_event_controller_get_widget(GTK_EVENT_CONTROLLER(dt));
            if (w) gtk_widget_add_css_class(w, "tab-drag-over");
            return GDK_ACTION_MOVE;
        };
        g_signal_connect(dropTgt, "enter", G_CALLBACK(enterCb), nullptr);
    }

    g_signal_connect(dropTgt, "leave",
        G_CALLBACK(+[](GtkDropTarget* dt) {
            GtkWidget* w = gtk_event_controller_get_widget(GTK_EVENT_CONTROLLER(dt));
            if (w) gtk_widget_remove_css_class(w, "tab-drag-over");
        }), nullptr);

    gtk_widget_add_controller(GTK_WIDGET(box), GTK_EVENT_CONTROLLER(dropTgt));

    return box;
}

static void openTab(BrowserWindow* bw, const char* uri, const std::string& mode) {
    // El modo efectivo de la pestaña refleja el perfil activo de la sesión.
    // El parámetro mode se respeta solo si el perfil activo es Clearnet
    // (para que enableNetworkMode pueda seguir alternando dentro de Clearnet si se usa).
    // En perfiles Tor/I2P todas las pestañas usan el perfil de la sesión.
    std::string effectiveMode = mode;
    if (g_activeProfile == BrowserProfile::TOR)      effectiveMode = "tor";
    else if (g_activeProfile == BrowserProfile::I2P) effectiveMode = "i2p";

    WebKitWebView* wv = makeWebview(bw, effectiveMode);
    TabData td; td.webview = wv; td.mode = effectiveMode;
    bw->tabs.push_back(td);
    int idx = (int)bw->tabs.size() - 1;

    std::string name = "tab" + std::to_string(idx);
    gtk_stack_add_named(bw->tabStack, GTK_WIDGET(wv), name.c_str());

    GtkBox* tabWidget = makeTabWidget(bw, idx);
    gtk_box_append(bw->tabbarBox, GTK_WIDGET(tabWidget));

    setupDownloadHandler(bw, wv);
    switchTab(bw, idx);

    std::string loadUri = uri ? std::string(uri) : bw->app->homeUri;
    webkit_web_view_load_uri(wv, loadUri.c_str());
}

static void clearTabData(BrowserWindow*, TabData& td) {
    // Solo limpiar datos en sesiones efímeras (Tor/I2P); la sesión por defecto
    // es compartida entre todas las pestañas normales y no debe borrarse aquí.
    WebKitNetworkSession* ns = webkit_web_view_get_network_session(td.webview);
    if (!ns) return;
    if (!webkit_network_session_is_ephemeral(ns)) return;
    WebKitWebsiteDataManager* wdm = webkit_network_session_get_website_data_manager(ns);
    if (!wdm) return;
    webkit_website_data_manager_clear(wdm,
        (WebKitWebsiteDataTypes)(
            WEBKIT_WEBSITE_DATA_COOKIES |
            WEBKIT_WEBSITE_DATA_DISK_CACHE |
            WEBKIT_WEBSITE_DATA_MEMORY_CACHE |
            WEBKIT_WEBSITE_DATA_SESSION_STORAGE |
            WEBKIT_WEBSITE_DATA_LOCAL_STORAGE |
            WEBKIT_WEBSITE_DATA_INDEXEDDB_DATABASES |
            WEBKIT_WEBSITE_DATA_OFFLINE_APPLICATION_CACHE
        ),
        0, nullptr, nullptr, nullptr);
}

static void rebuildTabbar(BrowserWindow* bw) {
    GtkWidget* child = gtk_widget_get_first_child(GTK_WIDGET(bw->tabbarBox));
    while (child) {
        GtkWidget* next = gtk_widget_get_next_sibling(child);
        gtk_box_remove(bw->tabbarBox, child);
        child = next;
    }
    for (int i = 0; i < (int)bw->tabs.size(); i++) {
        GtkBox* tw = makeTabWidget(bw, i);
        const char* title = webkit_web_view_get_title(bw->tabs[i].webview);
        if (title) {
            GtkButton* titleBtn = GTK_BUTTON(g_object_get_data(G_OBJECT(tw), "title-btn"));
            std::string t(title);
            if ((int)t.size() > 20) t = t.substr(0, 20) + "...";
            gtk_button_set_label(titleBtn, t.c_str());
        }
        gtk_box_append(bw->tabbarBox, GTK_WIDGET(tw));
    }
}

static void onCloseTab(BrowserWindow* bw, int idx) {
    if ((int)bw->tabs.size() == 1) {
        webkit_web_view_load_uri(bw->tabs[0].webview, bw->app->homeUri.c_str());
        return;
    }
    clearTabData(bw, bw->tabs[idx]);
    GtkWidget* child = gtk_stack_get_child_by_name(bw->tabStack,
        ("tab" + std::to_string(idx)).c_str());
    if (child) gtk_stack_remove(bw->tabStack, child);
    bw->tabs.erase(bw->tabs.begin() + idx);
    rebuildTabbar(bw);
    switchTab(bw, std::min(idx, (int)bw->tabs.size() - 1));
}

static void switchTab(BrowserWindow* bw, int idx) {
    if (idx < 0 || idx >= (int)bw->tabs.size()) return;

    // Actualizar estilos de pestañas
    GtkWidget* child = gtk_widget_get_first_child(GTK_WIDGET(bw->tabbarBox));
    int i = 0;
    while (child) {
        gtk_widget_remove_css_class(child, "tab-active");
        if (i == idx) gtk_widget_add_css_class(child, "tab-active");
        child = gtk_widget_get_next_sibling(child);
        i++;
    }

    bw->currentTab = idx;
    std::string name = "tab" + std::to_string(idx);
    gtk_stack_set_visible_child_name(bw->tabStack, name.c_str());

    const char* uri = webkit_web_view_get_uri(bw->tabs[idx].webview);
    gtk_editable_set_text(GTK_EDITABLE(bw->urlEntry), (uri && std::string(uri) != "about:blank") ? uri : "");
    updateBadge(bw, bw->tabs[idx].mode);
    updateNavButtons(bw);
    updateBookmarkStar(bw);
    updateSecurityBadge(bw, uri ? uri : "");
}

// ─── Señales del WebView ────────────────────────────────────────────────────

static void onUriChanged(GObject* obj, GParamSpec*, gpointer data) {
    auto* bw = static_cast<BrowserWindow*>(data);
    auto* wv = WEBKIT_WEB_VIEW(obj);
    if (bw->tabs.empty()) return;
    const char* uri = webkit_web_view_get_uri(wv);
    if (!uri || std::string(uri) == "about:blank") return;
    if (wv == currentWv(bw)) {
        gtk_editable_set_text(GTK_EDITABLE(bw->urlEntry), uri);
        updateBookmarkStar(bw);
        updateNavButtons(bw);
        updateSecurityBadge(bw, uri);

        // Aplicar zoom guardado para este dominio
        GUri* gu = g_uri_parse(uri, G_URI_FLAGS_NONE, nullptr);
        if (gu) {
            std::string host = g_uri_get_host(gu) ? g_uri_get_host(gu) : "";
            g_uri_unref(gu);
            auto it = bw->app->zoomPerDomain.find(host);
            if (it != bw->app->zoomPerDomain.end())
                webkit_web_view_set_zoom_level(wv, it->second);
        }
    }
    const char* title = webkit_web_view_get_title(wv);
    bw->app->addHistory(uri, title ? title : uri);
}

static void onTitleChanged(GObject* obj, GParamSpec*, gpointer data) {
    auto* bw = static_cast<BrowserWindow*>(data);
    auto* wv = WEBKIT_WEB_VIEW(obj);
    if (bw->tabs.empty()) return;
    const char* titleRaw = webkit_web_view_get_title(wv);
    std::string title = titleRaw ? titleRaw : "";

    GtkWidget* child = gtk_widget_get_first_child(GTK_WIDGET(bw->tabbarBox));
    int i = 0;
    while (child) {
        if (i < (int)bw->tabs.size() && bw->tabs[i].webview == wv) {
            GtkButton* btn = GTK_BUTTON(g_object_get_data(G_OBJECT(child), "title-btn"));
            if (btn) {
                std::string short_ = title.empty() ? ("Tab " + std::to_string(i + 1)) :
                    (title.size() > 20 ? title.substr(0, 20) + "..." : title);
                gtk_button_set_label(btn, short_.c_str());
            }
            break;
        }
        child = gtk_widget_get_next_sibling(child);
        i++;
    }
    if (wv == currentWv(bw)) {
        std::string winTitle = title.empty() ? "I4 Froez" : "I4 Froez — " + title;
        gtk_window_set_title(GTK_WINDOW(bw->window), winTitle.c_str());
    }
}

static void applyDarkCss(BrowserWindow* bw); // definida más adelante

static void onLoadChanged(WebKitWebView* wv, WebKitLoadEvent event, gpointer data) {
    auto* bw = static_cast<BrowserWindow*>(data);
    switch (event) {
        case WEBKIT_LOAD_STARTED:
            gtk_button_set_label(bw->reloadBtn, "■");
            gtk_widget_set_tooltip_text(GTK_WIDGET(bw->reloadBtn), "Detener carga");
            break;
        case WEBKIT_LOAD_FINISHED:
            gtk_button_set_label(bw->reloadBtn, "↺");
            gtk_widget_set_tooltip_text(GTK_WIDGET(bw->reloadBtn), "Recargar (Ctrl+R)");
            gtk_label_set_text(bw->statusbar, "");
            // Reaplicar modo oscuro si está activado
            if (bw->app->darkMode && wv == currentWv(bw))
                applyDarkCss(bw);
            break;
        default:
            break;
    }
}

// Mapa de errores de red de GIO a páginas de error personalizadas
static gboolean onLoadFailed(WebKitWebView* wv,
                              WebKitLoadEvent /*event*/,
                              const char* failingUri,
                              GError* error,
                              gpointer /*data*/) {
    std::string url = failingUri ? failingUri : "";
    std::string html;

    // No interceptar cancelaciones de usuario ni errores de froez://
    if (url.rfind("froez://", 0) == 0) return FALSE;
    if (error && error->domain == WEBKIT_NETWORK_ERROR &&
        error->code == WEBKIT_NETWORK_ERROR_CANCELLED) return FALSE;

    if (error) {
        int code = error->code;
        std::string msg = error->message ? error->message : "";

        // GIO/GLib network errors → switch sobre código
        if (error->domain == G_IO_ERROR) {
            // G_IO_ERROR_BROKEN_PIPE y G_IO_ERROR_CONNECTION_CLOSED pueden
            // tener el mismo valor en algunas versiones de GLib, así que
            // usamos if/else en lugar de switch para evitar casos duplicados.
            if (code == G_IO_ERROR_CONNECTION_REFUSED)
                html = buildConnectionRefusedPage(url);
            else if (code == G_IO_ERROR_TIMED_OUT
                  || code == G_IO_ERROR_BROKEN_PIPE
                  || code == G_IO_ERROR_CONNECTION_CLOSED)
                html = buildConnectionTerminatedPage(url);
            else
                html = buildGenericErrorPage(url, msg.empty() ? "Error desconocido" : msg);
        } else if (error->domain == WEBKIT_NETWORK_ERROR) {
            switch (code) {
                case WEBKIT_NETWORK_ERROR_UNKNOWN_PROTOCOL:
                case WEBKIT_NETWORK_ERROR_FILE_DOES_NOT_EXIST:
                    html = buildNotFoundPage(url); break;
                case WEBKIT_NETWORK_ERROR_TRANSPORT:
                    html = buildConnectionTerminatedPage(url); break;
                default:
                    html = buildGenericErrorPage(url, msg.empty() ? "Error de red" : msg); break;
            }
        } else if (error->domain == WEBKIT_POLICY_ERROR) {
            html = buildTlsErrorPage(url);
        } else {
            // Detectar por mensaje cuando el dominio de error no es conocido
            struct { std::string_view needle; std::string (*build)(const std::string&); } msgMap[] = {
                { "Could not resolve host",    buildDnsFailedPage },
                { "Name or service not known", buildDnsFailedPage },
                { "Failed to resolve",         buildDnsFailedPage },
                { "Connection refused",        buildConnectionRefusedPage },
                { "Connection reset",          buildConnectionTerminatedPage },
                { "Broken pipe",               buildConnectionTerminatedPage },
                { "Connection closed",         buildConnectionTerminatedPage },
                { "certificate",               buildTlsErrorPage },
                { "TLS",                       buildTlsErrorPage },
                { "SSL",                       buildTlsErrorPage },
            };
            html = buildGenericErrorPage(url, msg.empty() ? "Error desconocido" : msg);
            for (const auto& [needle, builder] : msgMap) {
                if (msg.find(needle) != std::string::npos) { html = builder(url); break; }
            }
        }
    } else {
        html = buildGenericErrorPage(url, "Error desconocido");
    }

    webkit_web_view_load_html(wv, html.c_str(), failingUri);
    return TRUE; // indicamos que manejamos el error
}

static void onProgress(GObject* obj, GParamSpec*, gpointer data) {
    auto* bw = static_cast<BrowserWindow*>(data);
    auto* wv = WEBKIT_WEB_VIEW(obj);
    if (wv != currentWv(bw)) return;
    double p = webkit_web_view_get_estimated_load_progress(wv);
    if (p > 0 && p < 1) {
        int pct = (int)(p * 100);
        std::string msg = "Cargando... " + std::to_string(pct) + "%";
        gtk_label_set_text(bw->statusbar, msg.c_str());
        // Mostrar progreso en la barra de URL
        gtk_widget_add_css_class(GTK_WIDGET(bw->urlEntry), "url-entry-loading");
    } else {
        gtk_label_set_text(bw->statusbar, "");
        gtk_widget_remove_css_class(GTK_WIDGET(bw->urlEntry), "url-entry-loading");
    }
}

// ─── Navegación ────────────────────────────────────────────────────────────

static std::string resolveInput(BrowserWindow* bw, const std::string& text) {
    std::string lower = strLower(text);
    for (const char* scheme : {"javascript:", "data:", "vbscript:", "blob:"}) {
        if (startsWith(lower, scheme)) {
            std::string msg = std::string("Esquema bloqueado: ") + scheme;
            gtk_label_set_text(bw->statusbar, msg.c_str());
            return "about:blank";
        }
    }

    // Modo I2P: bloquear cualquier destino que no sea .i2p, froez://, o localhost
    // Evita mezclar trafico I2P con clearnet por error del usuario
    if (g_activeProfile == BrowserProfile::I2P) {
        bool isI2p      = lower.find(".i2p") != std::string::npos;
        bool isFroez    = startsWith(lower, "froez://");
        bool isAbout    = startsWith(lower, "about:");
        bool isLocal    = startsWith(lower, "127.") || lower.find("localhost") != std::string::npos;
        bool isRelative = lower.find("://") == std::string::npos && lower.find('.') == std::string::npos;
        if (!isI2p && !isFroez && !isAbout && !isLocal && !isRelative) {
            gtk_label_set_text(bw->statusbar, "I2P: solo sitios .i2p permitidos en este perfil");
            // Mostrar página de error explicativa
            return "froez://i2p-blocked";
        }
    }
    // Modo HTTPS-Only: bloquear http:// excepto redes locales/especiales
    if (bw->app->httpsOnly && startsWith(lower, "http://")) {
        // Permitir .onion, .i2p, localhost y redes privadas
        GUri* gu = g_uri_parse(text.c_str(), G_URI_FLAGS_NONE, nullptr);
        std::string host;
        if (gu) { host = g_uri_get_host(gu) ? g_uri_get_host(gu) : ""; g_uri_unref(gu); }
        bool exempt = endsWith(host, ".onion") || endsWith(host, ".i2p") ||
                      host == "localhost" ||
                      startsWith(host, "127.") || startsWith(host, "192.168.") ||
                      startsWith(host, "10.")  || startsWith(host, "172.");
        if (!exempt) {
            // Upgrade a HTTPS
            std::string upgraded = "https://" + text.substr(7);
            gtk_label_set_text(bw->statusbar, "HTTPS-Only: redirigido a HTTPS");
            g_timeout_add(2500, [](gpointer p) -> gboolean { gtk_label_set_text(GTK_LABEL(p), ""); return FALSE; }, bw->statusbar);
            return upgraded;
        }
    }
    if (startsWith(text, "froez://"))  return text;
    if (startsWith(text, "http://")  || startsWith(text, "https://") ||
        startsWith(text, "about:")   || startsWith(text, "file://"))
        return text;

    // Dominios especiales — no añadir https:// automáticamente a .onion/.i2p
    // ya que normalmente van por HTTP a través del proxy
    if (text.find(' ') == std::string::npos) {
        std::string host = text;
        // Quitar puerto si existe
        size_t colonPos = host.rfind(':');
        std::string hostOnly = (colonPos != std::string::npos) ? host.substr(0, colonPos) : host;
        if (endsWith(hostOnly, ".onion") || endsWith(hostOnly, ".i2p"))
            return "http://" + text;
        // localhost y direcciones IP
        if (hostOnly == "localhost" || startsWith(hostOnly, "127.") ||
            startsWith(hostOnly, "192.168.") || startsWith(hostOnly, "10."))
            return "http://" + text;
        // Tiene punto y no tiene espacio → probablemente dominio
        if (text.find('.') != std::string::npos)
            return "https://" + text;
    }
    return searchWithDefault(text, bw->app->defaultSearchEngine, bw->app->searxngUrl, bw->app->whoogleUrl);
}

static void updateNavButtons(BrowserWindow* bw) {
    if (bw->tabs.empty()) return;
    auto* wv = currentWv(bw);
    gtk_widget_set_sensitive(GTK_WIDGET(bw->backBtn),    webkit_web_view_can_go_back(wv));
    gtk_widget_set_sensitive(GTK_WIDGET(bw->forwardBtn), webkit_web_view_can_go_forward(wv));
}

// ─── Badge de red ──────────────────────────────────────────────────────────

static void updateBadge(BrowserWindow* bw, const std::string& mode) {
    GtkWidget* w = GTK_WIDGET(bw->badge);
    for (const char* cls : {"badge-normal","badge-tor","badge-i2p","badge-clear"})
        gtk_widget_remove_css_class(w, cls);

    // Tabla: { modo, etiqueta, clase-css }
    static const struct { const char* mode; const char* label; const char* cls; const char* tooltip; } BADGE_MAP[] = {
        { "tor", "TOR",   "badge-tor",   "Modo Tor — tráfico enrutado por la red Tor" },
        { "i2p", "I2P",   "badge-i2p",   "Modo I2P — tráfico enrutado por la red I2P" },
        { "",    "Clear", "badge-clear", "Modo clearnet — conexión directa a Internet" },
    };
    const char* label   = "Clear";
    const char* cls     = "badge-clear";
    const char* tooltip = "Modo clearnet — conexión directa a Internet";
    for (const auto& b : BADGE_MAP) {
        if (mode == b.mode || b.mode[0] == '\0') { label = b.label; cls = b.cls; tooltip = b.tooltip; break; }
    }
    gtk_label_set_text(bw->badge, label);
    gtk_widget_add_css_class(w, cls);
    gtk_widget_set_tooltip_text(w, tooltip);
    gtk_widget_set_visible(w, TRUE);
}

// ─── Badge de seguridad ────────────────────────────────────────────────────

static void updateSecurityBadge(BrowserWindow* bw, const std::string& uri) {
    GtkWidget* w = GTK_WIDGET(bw->secBadge);
    if (uri.empty() || startsWith(uri, "about:")) { gtk_widget_set_visible(w, FALSE); return; }

    static const char* ALL_SEC_CLASSES[] = {
        "badge-secure","badge-insecure","badge-onion","badge-onion-s","badge-eepsite","badge-file","badge-clear"
    };

    // Páginas internas froez:// — ocultar badge de seguridad
    if (startsWith(uri, "froez://")) {
        gtk_widget_set_visible(w, FALSE);
        return;
    }

    GUri* guri = g_uri_parse(uri.c_str(), G_URI_FLAGS_NONE, nullptr);
    if (!guri) { gtk_widget_set_visible(w, FALSE); return; }
    std::string scheme = g_uri_get_scheme(guri) ? g_uri_get_scheme(guri) : "";
    std::string host   = g_uri_get_host(guri)   ? g_uri_get_host(guri)   : "";
    g_uri_unref(guri);

    for (const char* cls : ALL_SEC_CLASSES) gtk_widget_remove_css_class(w, cls);

    // Tabla: { predicado → label, clase, tooltip }
    struct SecRule {
        std::function<bool()> match;
        const char* label;
        const char* cls;
        const char* tooltip;
    };
    const SecRule rules[] = {
        { [&]{ return scheme == "file"; },
          "F", "badge-file",     "Archivo local" },
        { [&]{ return endsWith(host, ".onion") && scheme == "https"; },
          ":0", "badge-onion-s",  "Onion HTTPS — servicio oculto Tor con cifrado adicional" },
        { [&]{ return endsWith(host, ".onion"); },
          ":S", "badge-onion",    "Onion — servicio oculto Tor" },
        { [&]{ return endsWith(host, ".i2p"); },
          ":P", "badge-eepsite",  "Eepsite — servicio I2P" },
        { [&]{ return scheme == "https"; },
          ":D", "badge-secure",   "Seguro — conexión HTTPS" },
        { [&]{ return true; }, // fallback
          ":(", "badge-insecure", "Inseguro — conexión HTTP sin cifrar" },
    };
    for (const auto& r : rules) {
        if (r.match()) {
            gtk_label_set_text(bw->secBadge, r.label);
            gtk_widget_add_css_class(w, r.cls);
            gtk_widget_set_tooltip_text(w, r.tooltip);
            break;
        }
    }
    gtk_widget_set_visible(w, TRUE);
}

// ─── Marcadores ────────────────────────────────────────────────────────────

static void updateBookmarkStar(BrowserWindow* bw) {
    if (bw->tabs.empty()) return;
    const char* uri = webkit_web_view_get_uri(currentWv(bw));
    bool bookmarked = uri && bw->app->isBookmarked(uri);
    gtk_button_set_label(bw->bookmarkStar, bookmarked ? "◆" : "◇");
}

// ─── Terminal ──────────────────────────────────────────────────────────────

// Aplica el tag readonly desde el inicio del buffer hasta promptEndMark.
// El TextView sigue siendo editable=TRUE globalmente; el tag solo bloquea
// la zona histórica. La zona del prompt (después del mark) queda libre.
static void termFreezeHistory(BrowserWindow* bw) {
    if (!bw->termReadonlyTag) return;
    GtkTextIter start, freezeEnd;
    gtk_text_buffer_get_start_iter(bw->terminalBuf, &start);
    if (bw->promptEndMark)
        gtk_text_buffer_get_iter_at_mark(bw->terminalBuf, &freezeEnd, bw->promptEndMark);
    else
        gtk_text_buffer_get_end_iter(bw->terminalBuf, &freezeEnd);
    gtk_text_buffer_apply_tag(bw->terminalBuf, bw->termReadonlyTag, &start, &freezeEnd);
}

static void termPrint(BrowserWindow* bw, const std::string& text, bool noNl = false) {
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(bw->terminalBuf, &end);
    std::string msg = noNl ? text : text + "\n";
    gtk_text_buffer_insert(bw->terminalBuf, &end, msg.c_str(), -1);
    // El texto insertado es output → congelarlo inmediatamente
    termFreezeHistory(bw);
    GtkTextIter end2;
    gtk_text_buffer_get_end_iter(bw->terminalBuf, &end2);
    gtk_text_view_scroll_to_iter(bw->terminalTv, &end2, 0.0, TRUE, 0.0, 1.0);
}

static void termPrompt(BrowserWindow* bw) {
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(bw->terminalBuf, &end);
    gtk_text_buffer_insert(bw->terminalBuf, &end, "froezshell -> ", -1);
    GtkTextIter end2;
    gtk_text_buffer_get_end_iter(bw->terminalBuf, &end2);
    // Recrear el mark con LEFT_GRAVITY=TRUE: el texto que el usuario escribe
    // queda a la DERECHA del mark → fuera de la zona congelada.
    if (bw->promptEndMark)
        gtk_text_buffer_delete_mark(bw->terminalBuf, bw->promptEndMark);
    bw->promptEndMark = gtk_text_buffer_create_mark(
        bw->terminalBuf, nullptr, &end2, TRUE /* left gravity */);
    // Congelar el " froezshell -> " recién insertado
    termFreezeHistory(bw);
    // Colocar el cursor al final (zona editable)
    gtk_text_buffer_get_end_iter(bw->terminalBuf, &end2);
    gtk_text_buffer_place_cursor(bw->terminalBuf, &end2);
    gtk_text_view_scroll_to_iter(bw->terminalTv, &end2, 0.0, TRUE, 0.0, 1.0);
}

// ─── Findbar ────────────────────────────────────────────────────────────────

static void closeFindbar(BrowserWindow* bw) {
    gtk_widget_set_visible(GTK_WIDGET(bw->findbarBox), FALSE);
    bw->findbarVisible = false;
    webkit_find_controller_search_finish(webkit_web_view_get_find_controller(currentWv(bw)));
    gtk_label_set_text(bw->findLabel, "");
}

static void findChanged(BrowserWindow* bw) {
    const char* text = gtk_editable_get_text(GTK_EDITABLE(bw->findEntry));
    WebKitFindController* fc = webkit_web_view_get_find_controller(currentWv(bw));
    if (text && text[0])
        webkit_find_controller_search(fc, text,
            (WebKitFindOptions)(WEBKIT_FIND_OPTIONS_CASE_INSENSITIVE | WEBKIT_FIND_OPTIONS_WRAP_AROUND), 1000);
    else {
        webkit_find_controller_search_finish(fc);
        gtk_label_set_text(bw->findLabel, "");
    }
}

// ─── Modo oscuro ────────────────────────────────────────────────────────────

static void applyDarkCss(BrowserWindow* bw) {
    const char* css = ":root{color-scheme:dark!important}"
                      "*{background-color:#111!important;color:#eee!important;border-color:#333!important}"
                      "a{color:#8ab4f8!important}img{filter:brightness(0.85)}";
    std::string js = R"((function(){let el=document.getElementById('i4froez-dark');)"
                     R"(if(!el){el=document.createElement('style');el.id='i4froez-dark';document.head.appendChild(el);})"
                     R"(el.textContent=`)" + std::string(css) + R"(`;})();)";
    webkit_web_view_evaluate_javascript(currentWv(bw), js.c_str(), -1,
        nullptr, nullptr, nullptr, nullptr, nullptr);
}

static void removeDarkCss(BrowserWindow* bw) {
    const char* js = "(function(){let el=document.getElementById('i4froez-dark');if(el)el.remove();})();";
    webkit_web_view_evaluate_javascript(currentWv(bw), js, -1,
        nullptr, nullptr, nullptr, nullptr, nullptr);
}

// ─── Sidebar (marcadores / historial) ─────────────────────────────────────

struct SidebarItemData { BrowserWindow* bw; std::string url; bool removable; };

static void closeSidebar(BrowserWindow* bw) {
    if (bw->sidebarWidget) {
        gtk_box_remove(bw->contentArea, bw->sidebarWidget);
        g_object_unref(bw->sidebarWidget); // soltar la ref extra que tomamos al crear
        bw->sidebarWidget = nullptr;
    }
    bw->sidebarMode = "";
}

static void showSidebar(BrowserWindow* bw, const std::string& mode);

static void sidebarItemClicked(GtkButton*, gpointer data) {
    auto* d = static_cast<SidebarItemData*>(data);
    webkit_web_view_load_uri(currentWv(d->bw), d->url.c_str());
}

static void sidebarItemRemoveClicked(GtkButton*, gpointer data) {
    auto* d = static_cast<SidebarItemData*>(data);
    d->bw->app->removeBookmark(d->url);
    showSidebar(d->bw, "bookmarks");
}

static void addSidebarItem(GtkBox* listBox, BrowserWindow* bw,
                           const std::string& label, const std::string& url,
                           bool removable) {
    GtkBox* row = GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 2));

    GtkButton* btn = GTK_BUTTON(gtk_button_new_with_label(label.c_str()));
    gtk_widget_add_css_class(GTK_WIDGET(btn), "sidebar-item");
    gtk_widget_set_hexpand(GTK_WIDGET(btn), TRUE);
    gtk_widget_set_halign(GTK_WIDGET(btn), GTK_ALIGN_FILL);

    auto* itemData = new SidebarItemData{bw, url, removable};
    g_signal_connect_data(btn, "clicked", G_CALLBACK(sidebarItemClicked),
        itemData, [](gpointer p, GClosure*) { delete static_cast<SidebarItemData*>(p); },
        GConnectFlags(0));
    gtk_box_append(row, GTK_WIDGET(btn));

    if (removable) {
        GtkButton* del = GTK_BUTTON(gtk_button_new_with_label("Quitar"));
        gtk_widget_add_css_class(GTK_WIDGET(del), "close-tab-btn");
        auto* delData = new SidebarItemData{bw, url, true};
        g_signal_connect_data(del, "clicked", G_CALLBACK(sidebarItemRemoveClicked),
            delData, [](gpointer p, GClosure*) { delete static_cast<SidebarItemData*>(p); },
            GConnectFlags(0));
        gtk_box_append(row, GTK_WIDGET(del));
    }

    gtk_box_append(listBox, GTK_WIDGET(row));
}

static void showSidebar(BrowserWindow* bw, const std::string& mode) {
    closeSidebar(bw);
    bw->sidebarMode = mode;

    GtkBox* outer = GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL, 0));
    gtk_widget_add_css_class(GTK_WIDGET(outer), "sidebar");

    // Cabecera
    GtkBox* titleBox = GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0));
    gtk_widget_add_css_class(GTK_WIDGET(titleBox), "sidebar-title");

    GtkLabel* lbl = GTK_LABEL(gtk_label_new(mode == "bookmarks" ? "Marcadores" : "Historial"));
    gtk_widget_set_hexpand(GTK_WIDGET(lbl), TRUE);
    gtk_label_set_xalign(lbl, 0.0f);

    GtkButton* closeBtn = GTK_BUTTON(gtk_button_new_with_label("Cerrar"));
    gtk_widget_add_css_class(GTK_WIDGET(closeBtn), "nav-button");
    g_signal_connect_data(closeBtn, "clicked",
        G_CALLBACK(+[](GtkButton*, gpointer p) { closeSidebar(static_cast<BrowserWindow*>(p)); }),
        bw, nullptr, GConnectFlags(0));

    gtk_box_append(titleBox, GTK_WIDGET(lbl));
    gtk_box_append(titleBox, GTK_WIDGET(closeBtn));

    // Lista con scroll
    GtkScrolledWindow* scroll = GTK_SCROLLED_WINDOW(gtk_scrolled_window_new());
    gtk_widget_set_vexpand(GTK_WIDGET(scroll), TRUE);
    gtk_scrolled_window_set_policy(scroll, GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);

    GtkBox* listBox = GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL, 1));
    gtk_widget_set_margin_top(GTK_WIDGET(listBox), 4);
    gtk_widget_set_margin_bottom(GTK_WIDGET(listBox), 4);
    gtk_widget_set_margin_start(GTK_WIDGET(listBox), 4);
    gtk_widget_set_margin_end(GTK_WIDGET(listBox), 4);

    if (mode == "bookmarks") {
        if (bw->app->bookmarks.empty()) {
            GtkLabel* empty = GTK_LABEL(gtk_label_new("Sin marcadores aún"));
            gtk_widget_set_margin_top(GTK_WIDGET(empty), 20);
            gtk_widget_add_css_class(GTK_WIDGET(empty), "sidebar-item");
            gtk_box_append(listBox, GTK_WIDGET(empty));
        } else {
            for (const auto& b : bw->app->bookmarks)
                addSidebarItem(listBox, bw,
                    b["title"].get<std::string>(),
                    b["url"].get<std::string>(), true);
        }
    } else {
        // Historial — últimas 200 entradas en orden inverso
        int total = (int)bw->app->history.size();
        int start = std::max(0, total - 200);
        if (total == 0) {
            GtkLabel* empty = GTK_LABEL(gtk_label_new("El historial está vacío"));
            gtk_widget_set_margin_top(GTK_WIDGET(empty), 20);
            gtk_widget_add_css_class(GTK_WIDGET(empty), "sidebar-item");
            gtk_box_append(listBox, GTK_WIDGET(empty));
        } else {
            for (int i = total - 1; i >= start; i--) {
                const auto& h = bw->app->history[i];
                std::string ts = h.value("ts", "").substr(0, 10);
                std::string label = "[" + ts + "] " + h.value("title", h.value("url", ""));
                addSidebarItem(listBox, bw, label, h.value("url", ""), false);
            }
        }
    }

    gtk_scrolled_window_set_child(scroll, GTK_WIDGET(listBox));
    gtk_box_append(outer, GTK_WIDGET(titleBox));
    gtk_box_append(outer, GTK_WIDGET(scroll));

    // Tomar ref extra para sobrevivir a futuros removes
    g_object_ref(outer);
    bw->sidebarWidget = GTK_WIDGET(outer);

    // Insertar ANTES del tab stack (prepend al contentArea)
    gtk_box_prepend(bw->contentArea, GTK_WIDGET(outer));
}

static void toggleSidebar(BrowserWindow* bw, const std::string& mode) {
    if (bw->sidebarMode == mode) closeSidebar(bw);
    else showSidebar(bw, mode);
}



// ─── Gestión de descargas completa ────────────────────────────────────────

enum class DlState { DOWNLOADING, PAUSED, FINISHED, FAILED, CANCELLED };

struct DownloadItem {
    WebKitDownload* dl      = nullptr;
    std::string     filename;
    std::string     destPath;
    DlState         state   = DlState::DOWNLOADING;
    double          progress = 0.0;
    guint64         totalBytes = 0;
    int             id = 0;

    // Widgets del panel
    GtkWidget* row        = nullptr;
    GtkLabel*  nameLbl    = nullptr;
    GtkLabel*  statusLbl  = nullptr;
    GtkProgressBar* bar   = nullptr;
    GtkButton* pauseBtn   = nullptr;
    GtkButton* cancelBtn  = nullptr;
    GtkButton* openBtn    = nullptr;
};

// Panel de descargas — se añade dinámicamente al contentArea
struct DlPanel {
    GtkWidget* widget   = nullptr; // GtkBox raíz
    GtkBox*    listBox  = nullptr;
    GtkLabel*  emptyLbl = nullptr;
    bool       visible  = false;
};

static DlPanel g_dlPanel;
static std::vector<DownloadItem*> g_downloads;
static int g_dlNextId = 1;

// Helper para formatear bytes en cadena legible
static std::string fmtBytes(guint64 b) {
    if (b < 1024) return std::to_string(b) + " B";
    if (b < 1024*1024) { char buf[32]; snprintf(buf,sizeof(buf),"%.1f KB",(double)b/1024); return buf; }
    if (b < 1024*1024*1024) { char buf[32]; snprintf(buf,sizeof(buf),"%.1f MB",(double)b/(1024*1024)); return buf; }
    char buf[32]; snprintf(buf,sizeof(buf),"%.2f GB",(double)b/(1024ull*1024*1024)); return buf;
}

static void updateDlRow(DownloadItem* item) {
    if (!item->nameLbl) return;
    gtk_label_set_text(item->nameLbl, item->filename.c_str());
    switch (item->state) {
        case DlState::DOWNLOADING: {
            guint64 recv = webkit_download_get_received_data_length(item->dl);
            std::string s = fmtBytes(recv);
            if (item->totalBytes > 0) s += " / " + fmtBytes(item->totalBytes);
            s += "  " + std::to_string((int)(item->progress * 100)) + "%";
            gtk_label_set_text(item->statusLbl, s.c_str());
            gtk_progress_bar_set_fraction(item->bar, item->progress);
            gtk_widget_set_visible(GTK_WIDGET(item->bar), TRUE);
            gtk_button_set_label(item->pauseBtn, "✕ Cancelar descarga");
            gtk_widget_set_sensitive(GTK_WIDGET(item->pauseBtn), TRUE);
            gtk_widget_set_visible(GTK_WIDGET(item->openBtn), FALSE);
            break;
        }
        case DlState::PAUSED:
            gtk_label_set_text(item->statusLbl, "Cancelado");
            gtk_button_set_label(item->pauseBtn, "✕ Cancelar descarga");
            gtk_widget_set_sensitive(GTK_WIDGET(item->pauseBtn), FALSE);
            gtk_widget_set_visible(GTK_WIDGET(item->openBtn), FALSE);
            break;
        case DlState::FINISHED:
            gtk_label_set_text(item->statusLbl, ("Completado — " + fmtBytes(item->totalBytes > 0 ? item->totalBytes : webkit_download_get_received_data_length(item->dl))).c_str());
            gtk_progress_bar_set_fraction(item->bar, 1.0);
            gtk_widget_set_sensitive(GTK_WIDGET(item->pauseBtn), FALSE);
            gtk_widget_set_sensitive(GTK_WIDGET(item->cancelBtn), FALSE);
            gtk_widget_set_visible(GTK_WIDGET(item->openBtn), TRUE);
            break;
        case DlState::FAILED:
            gtk_label_set_text(item->statusLbl, "Error en la descarga");
            gtk_widget_set_sensitive(GTK_WIDGET(item->pauseBtn), FALSE);
            gtk_widget_set_visible(GTK_WIDGET(item->openBtn), FALSE);
            break;
        case DlState::CANCELLED:
            gtk_label_set_text(item->statusLbl, "Cancelado");
            gtk_widget_set_sensitive(GTK_WIDGET(item->pauseBtn), FALSE);
            gtk_widget_set_sensitive(GTK_WIDGET(item->cancelBtn), FALSE);
            gtk_widget_set_visible(GTK_WIDGET(item->openBtn), FALSE);
            break;
    }
}

// Forward declaration
static void buildDlPanel(BrowserWindow* bw);
static void toggleDlPanel(BrowserWindow* bw);

static GtkWidget* makeDlRow(BrowserWindow* bw, DownloadItem* item) {
    GtkBox* row = GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL, 4));
    gtk_widget_set_margin_top(GTK_WIDGET(row), 6);
    gtk_widget_set_margin_bottom(GTK_WIDGET(row), 6);
    gtk_widget_set_margin_start(GTK_WIDGET(row), 8);
    gtk_widget_set_margin_end(GTK_WIDGET(row), 8);

    // Nombre del archivo
    GtkLabel* nameLbl = GTK_LABEL(gtk_label_new(item->filename.c_str()));
    gtk_label_set_xalign(nameLbl, 0.0f);
    gtk_label_set_ellipsize(nameLbl, PANGO_ELLIPSIZE_MIDDLE);
    gtk_widget_add_css_class(GTK_WIDGET(nameLbl), "sidebar-item");

    // Barra de progreso
    GtkProgressBar* bar = GTK_PROGRESS_BAR(gtk_progress_bar_new());
    gtk_widget_add_css_class(GTK_WIDGET(bar), "dl-progress");
    gtk_progress_bar_set_fraction(bar, 0.0);

    // Estado
    GtkLabel* statusLbl = GTK_LABEL(gtk_label_new("Iniciando..."));
    gtk_label_set_xalign(statusLbl, 0.0f);
    GtkCssProvider* sp = gtk_css_provider_new();
    gtk_css_provider_load_from_string(sp, "label { color: #6c7086; font-size: 11px; }");
    gtk_style_context_add_provider_for_display(gdk_display_get_default(),
        GTK_STYLE_PROVIDER(sp), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(sp);

    // Botones de control
    GtkBox* btnRow = GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6));
    GtkButton* pauseBtn  = GTK_BUTTON(gtk_button_new_with_label("✕ Cancelar descarga"));
    GtkButton* cancelBtn = GTK_BUTTON(gtk_button_new_with_label("✕ Cancelar"));
    GtkButton* openBtn   = GTK_BUTTON(gtk_button_new_with_label("Abrir carpeta"));
    gtk_widget_add_css_class(GTK_WIDGET(pauseBtn),  "nav-button");
    gtk_widget_add_css_class(GTK_WIDGET(cancelBtn), "nav-button");
    gtk_widget_add_css_class(GTK_WIDGET(openBtn),   "nav-button");
    gtk_widget_set_visible(GTK_WIDGET(openBtn), FALSE);

    gtk_box_append(btnRow, GTK_WIDGET(pauseBtn));
    gtk_box_append(btnRow, GTK_WIDGET(cancelBtn));
    gtk_box_append(btnRow, GTK_WIDGET(openBtn));

    gtk_box_append(row, GTK_WIDGET(nameLbl));
    gtk_box_append(row, GTK_WIDGET(bar));
    gtk_box_append(row, GTK_WIDGET(statusLbl));
    gtk_box_append(row, GTK_WIDGET(btnRow));

    // Guardar refs en el item
    item->row       = GTK_WIDGET(row);
    item->nameLbl   = nameLbl;
    item->statusLbl = statusLbl;
    item->bar       = bar;
    item->pauseBtn  = pauseBtn;
    item->cancelBtn = cancelBtn;
    item->openBtn   = openBtn;

    // Callbacks
    g_signal_connect_data(pauseBtn, "clicked",
        G_CALLBACK(+[](GtkButton*, gpointer p) {
            auto* itm = static_cast<DownloadItem*>(p);
            if (itm->state == DlState::DOWNLOADING) {
                // WebKitGTK no tiene pausa real — cancelamos y marcamos como cancelado
                webkit_download_cancel(itm->dl);
                itm->state = DlState::CANCELLED;
            } else if (itm->state == DlState::PAUSED) {
                // Estado PAUSED nunca se alcanza de forma real en esta implementación;
                // si alguna vez llegara aquí, también cancelar para no dejar estado inconsistente.
                webkit_download_cancel(itm->dl);
                itm->state = DlState::CANCELLED;
            }
            updateDlRow(itm);
        }), item, nullptr, GConnectFlags(0));

    g_signal_connect_data(cancelBtn, "clicked",
        G_CALLBACK(+[](GtkButton*, gpointer p) {
            auto* itm = static_cast<DownloadItem*>(p);
            if (itm->state == DlState::DOWNLOADING || itm->state == DlState::PAUSED) {
                webkit_download_cancel(itm->dl);
                itm->state = DlState::CANCELLED;
                updateDlRow(itm);
            }
        }), item, nullptr, GConnectFlags(0));

    g_signal_connect_data(openBtn, "clicked",
        G_CALLBACK(+[](GtkButton*, gpointer p) {
            auto* itm = static_cast<DownloadItem*>(p);
            if (!itm->destPath.empty()) {
                // Abrir el gestor de archivos en la carpeta de destino
                std::string dir = itm->destPath;
                size_t sl = dir.rfind('/');
                if (sl != std::string::npos) dir = dir.substr(0, sl);
                GFile* gf = g_file_new_for_path(dir.c_str());
                gchar* fileUri = g_file_get_uri(gf);
                g_app_info_launch_default_for_uri(fileUri, nullptr, nullptr);
                g_free(fileUri);
                g_object_unref(gf);
            }
        }), item, nullptr, GConnectFlags(0));

    // Separador visual
    GtkWidget* sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    GtkBox* wrapper = GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL, 0));
    gtk_box_append(wrapper, GTK_WIDGET(row));
    gtk_box_append(wrapper, sep);
    return GTK_WIDGET(wrapper);
}

static void buildDlPanel(BrowserWindow* bw) {
    if (g_dlPanel.widget) return;

    GtkBox* outer = GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL, 0));
    gtk_widget_set_size_request(GTK_WIDGET(outer), 300, -1);

    // Cabecera
    GtkBox* titleBox = GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8));
    gtk_widget_add_css_class(GTK_WIDGET(titleBox), "toolbar");
    GtkLabel* titleLbl = GTK_LABEL(gtk_label_new("  Descargas"));
    gtk_widget_add_css_class(GTK_WIDGET(titleLbl), "sidebar-title");
    gtk_widget_set_hexpand(GTK_WIDGET(titleLbl), TRUE);
    GtkButton* closeBtn = GTK_BUTTON(gtk_button_new_with_label("✕"));
    gtk_widget_add_css_class(GTK_WIDGET(closeBtn), "close-tab-btn");
    g_signal_connect(closeBtn, "clicked",
        G_CALLBACK(+[](GtkButton*, gpointer p) { toggleDlPanel(static_cast<BrowserWindow*>(p)); }), bw);
    gtk_box_append(titleBox, GTK_WIDGET(titleLbl));
    gtk_box_append(titleBox, GTK_WIDGET(closeBtn));

    // Botón limpiar completadas
    GtkButton* clearBtn = GTK_BUTTON(gtk_button_new_with_label("Limpiar completadas"));
    gtk_widget_add_css_class(GTK_WIDGET(clearBtn), "sidebar-item");
    gtk_widget_set_margin_start(GTK_WIDGET(clearBtn), 8);
    gtk_widget_set_margin_end(GTK_WIDGET(clearBtn), 8);
    gtk_widget_set_margin_top(GTK_WIDGET(clearBtn), 6);

    // Lista
    GtkScrolledWindow* scroll = GTK_SCROLLED_WINDOW(gtk_scrolled_window_new());
    gtk_widget_set_vexpand(GTK_WIDGET(scroll), TRUE);
    gtk_scrolled_window_set_policy(scroll, GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);

    GtkBox* listBox = GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL, 2));
    gtk_widget_set_margin_top(GTK_WIDGET(listBox), 4);
    GtkLabel* emptyLbl = GTK_LABEL(gtk_label_new("Sin descargas"));
    gtk_widget_set_margin_top(GTK_WIDGET(emptyLbl), 20);
    gtk_widget_add_css_class(GTK_WIDGET(emptyLbl), "sidebar-item");
    gtk_box_append(listBox, GTK_WIDGET(emptyLbl));

    gtk_scrolled_window_set_child(scroll, GTK_WIDGET(listBox));

    g_signal_connect_data(clearBtn, "clicked",
        G_CALLBACK(+[](GtkButton*, gpointer p) {
            auto* lb = static_cast<GtkBox*>(p);
            std::vector<DownloadItem*> toKeep;
            for (auto* itm : g_downloads) {
                if (itm->state == DlState::FINISHED ||
                    itm->state == DlState::CANCELLED ||
                    itm->state == DlState::FAILED) {
                    // El wrapper que devuelve makeDlRow es el padre directo del row,
                    // y a su vez es hijo directo de listBox.
                    if (itm->row) {
                        GtkWidget* wrapper = gtk_widget_get_parent(itm->row);
                        if (wrapper && gtk_widget_get_parent(wrapper) == GTK_WIDGET(lb))
                            gtk_box_remove(lb, wrapper);
                        else if (wrapper && gtk_widget_get_parent(wrapper) != nullptr) {
                            // intento mas robusto: subir un nivel mas
                            GtkWidget* grandparent = gtk_widget_get_parent(wrapper);
                            if (grandparent && gtk_widget_get_parent(grandparent) == GTK_WIDGET(lb))
                                gtk_box_remove(lb, grandparent);
                        }
                    }
                    delete itm;
                } else {
                    toKeep.push_back(itm);
                }
            }
            g_downloads = toKeep;
            // Mostrar etiqueta "sin descargas" si la lista quedo vacia
            if (toKeep.empty() && g_dlPanel.emptyLbl)
                gtk_widget_set_visible(GTK_WIDGET(g_dlPanel.emptyLbl), TRUE);
        }), listBox, nullptr, GConnectFlags(0));

    gtk_box_append(outer, GTK_WIDGET(titleBox));
    gtk_box_append(outer, GTK_WIDGET(clearBtn));
    gtk_box_append(outer, GTK_WIDGET(scroll));

    g_object_ref(outer);
    g_dlPanel.widget   = GTK_WIDGET(outer);
    g_dlPanel.listBox  = listBox;
    g_dlPanel.emptyLbl = emptyLbl;
}

static void toggleDlPanel(BrowserWindow* bw) {
    buildDlPanel(bw);
    if (g_dlPanel.visible) {
        gtk_box_remove(bw->contentArea, g_dlPanel.widget);
        g_dlPanel.visible = false;
    } else {
        gtk_box_prepend(bw->contentArea, g_dlPanel.widget);
        g_dlPanel.visible = true;
    }
}

// Callbacks de descarga
static void onDownloadProgress(GObject* obj, GParamSpec*, gpointer data) {
    auto* item = static_cast<DownloadItem*>(data);
    auto* dl   = WEBKIT_DOWNLOAD(obj);
    item->progress   = webkit_download_get_estimated_progress(dl);
    item->totalBytes = (guint64)(webkit_download_get_estimated_progress(dl) > 0
        ? webkit_download_get_received_data_length(dl) / webkit_download_get_estimated_progress(dl)
        : 0);
    updateDlRow(item);

    // También actualizar barra de statusbar
    if (g_bw) {
        std::string msg = "Descargando: " + item->filename + "  " +
                          std::to_string((int)(item->progress*100)) + "%";
        gtk_label_set_text(g_bw->statusbar, msg.c_str());
    }
}

static void onDownloadFinished(WebKitDownload*, gpointer data) {
    auto* item = static_cast<DownloadItem*>(data);
    item->state = DlState::FINISHED;
    updateDlRow(item);
    if (g_bw) {
        gtk_label_set_text(g_bw->statusbar, ("Descarga completa: " + item->filename).c_str());
        g_timeout_add(4000, [](gpointer p) -> gboolean {
            gtk_label_set_text(GTK_LABEL(p), ""); return FALSE;
        }, g_bw->statusbar);
    }
}

static void onDownloadFailed(WebKitDownload*, GError* error, gpointer data) {
    auto* item = static_cast<DownloadItem*>(data);
    item->state = DlState::FAILED;
    updateDlRow(item);
    if (g_bw) {
        std::string msg = "Error descarga: " + item->filename +
                          (error ? std::string(" — ") + error->message : "");
        gtk_label_set_text(g_bw->statusbar, msg.c_str());
    }
}

static void onSaveDialogDone(GObject* source, GAsyncResult* result, gpointer data) {
    GtkFileDialog* dialog = GTK_FILE_DIALOG(source);
    auto* pair = static_cast<std::pair<BrowserWindow*, DownloadItem*>*>(data);
    BrowserWindow* bw   = pair->first;
    DownloadItem*  item = pair->second;
    delete pair;

    GFile* gfile = gtk_file_dialog_save_finish(dialog, result, nullptr);
    if (!gfile) { webkit_download_cancel(item->dl); item->state = DlState::CANCELLED; updateDlRow(item); return; }

    char* path = g_file_get_path(gfile);
    g_object_unref(gfile);
    if (!path) { webkit_download_cancel(item->dl); item->state = DlState::CANCELLED; updateDlRow(item); return; }

    item->destPath = path;
    gchar* basenameRaw = g_path_get_basename(path);
    item->filename = basenameRaw ? basenameRaw : path;
    g_free(basenameRaw);
    g_free(path);

    webkit_download_set_destination(item->dl, item->destPath.c_str());

    // Actualizar nombre en la UI ahora que lo sabemos
    updateDlRow(item);

    // Actualizar statusbar
    gtk_label_set_text(bw->statusbar, ("Descargando: " + item->filename + "  0%").c_str());

    g_signal_connect(item->dl, "notify::estimated-progress", G_CALLBACK(onDownloadProgress), item);
    g_signal_connect(item->dl, "finished", G_CALLBACK(onDownloadFinished), item);
    g_signal_connect(item->dl, "failed",   G_CALLBACK(onDownloadFailed),   item);
}

static gboolean onDecideDestination(WebKitDownload* dl, const char* fname, gpointer data) {
    auto* bw = static_cast<BrowserWindow*>(data);
    std::string suggestedName = fname ? fname : "descarga";

    // Crear el item de descarga y añadirlo al panel
    buildDlPanel(bw);
    auto* item = new DownloadItem();
    item->dl       = dl;
    item->filename = suggestedName;
    item->id       = g_dlNextId++;
    item->state    = DlState::DOWNLOADING;
    g_downloads.push_back(item);

    // Añadir fila al panel
    if (g_dlPanel.listBox) {
        gtk_widget_set_visible(GTK_WIDGET(g_dlPanel.emptyLbl), FALSE);
        GtkWidget* rowWidget = makeDlRow(bw, item);
        gtk_box_append(g_dlPanel.listBox, rowWidget);
    }
    // Abrir panel automáticamente si está cerrado
    if (!g_dlPanel.visible) toggleDlPanel(bw);

    // Diálogo de guardar
    GtkFileDialog* dialog = gtk_file_dialog_new();
    gtk_file_dialog_set_title(dialog, "Guardar archivo");
    gtk_file_dialog_set_initial_name(dialog, suggestedName.c_str());

    auto* pair = new std::pair<BrowserWindow*, DownloadItem*>{bw, item};
    gtk_file_dialog_save(dialog, GTK_WINDOW(bw->window), nullptr, onSaveDialogDone, pair);
    g_object_unref(dialog);
    return TRUE;
}

static void onDownloadStarted(WebKitNetworkSession*, WebKitDownload* dl, gpointer data) {
    auto* bw = static_cast<BrowserWindow*>(data);
    g_signal_connect(dl, "decide-destination", G_CALLBACK(onDecideDestination), bw);
}

static void setupDownloadHandler(BrowserWindow* bw, WebKitWebView* wv) {
    WebKitNetworkSession* ns = webkit_web_view_get_network_session(wv);
    if (ns) g_signal_connect(ns, "download-started", G_CALLBACK(onDownloadStarted), bw);
}

// ─── Wipe de RAM de sesión sensible ────────────────────────────────────────
// Limpia claves criptográficas, historial y marcadores de la RAM.
// NO protege contra dumps activos del kernel, pero borra lo que queda en heap.

static void wipeSessionMemory(AppData* app) {
    // 1. Limpiar clave maestra
    if (!g_masterKey.empty()) {
        OPENSSL_cleanse(g_masterKey.data(), g_masterKey.size());
        g_masterKey.clear();
    }

    // 2. Zero-fill historial en RAM
    for (auto& entry : app->history) {
        try {
            if (entry.contains("url")) {
                std::string& u = entry["url"].get_ref<std::string&>();
                OPENSSL_cleanse(u.data(), u.size()); u.clear();
            }
            if (entry.contains("title")) {
                std::string& t = entry["title"].get_ref<std::string&>();
                OPENSSL_cleanse(t.data(), t.size()); t.clear();
            }
        } catch (...) {}
    }
    app->history = json::array();

    // 3. Zero-fill marcadores en RAM
    for (auto& bm : app->bookmarks) {
        try {
            if (bm.contains("url")) {
                std::string& u = bm["url"].get_ref<std::string&>();
                OPENSSL_cleanse(u.data(), u.size()); u.clear();
            }
            if (bm.contains("title")) {
                std::string& t = bm["title"].get_ref<std::string&>();
                OPENSSL_cleanse(t.data(), t.size()); t.clear();
            }
        } catch (...) {}
    }
    app->bookmarks = json::array();

    // 4. Limpiar ajustes sensibles en RAM
    OPENSSL_cleanse(app->torProxy.data(),   app->torProxy.size());
    OPENSSL_cleanse(app->i2pProxy.data(),   app->i2pProxy.size());
}

// ─── Cambio de perfil — wipe + restart de la ventana ──────────────────────
// Destruye la ventana GTK actual, limpia toda la RAM sensible, cambia el
// perfil activo y relanza una nueva ventana con el perfil destino.
// Es equivalente a cerrar y reabrir el navegador con otro perfil.

static void switchProfile(GtkApplication* app, BrowserProfile newProfile);

// ─── Modos de red ──────────────────────────────────────────────────────────

static void enableNetworkMode(BrowserWindow* bw, const std::string& mode) {
    BrowserProfile target = profileFromString(mode);
    if (target == g_activeProfile) {
        termPrint(bw, "Ya estás en el perfil " + mode + ".");
        termPrompt(bw);
        return;
    }

    // Confirmar con el usuario antes del cambio destructivo
    termPrint(bw, "Cambiando al perfil " + mode + "...");
    termPrint(bw, "Se cerrará esta ventana y se abrirá una nueva con el perfil " + mode + ".");
    termPrint(bw, "Los datos del perfil actual permanecen cifrados en disco.");

    GtkApplication* gapp = GTK_APPLICATION(g_application_get_default());

    // Wipe de RAM del perfil actual
    wipeSessionMemory(bw->app);

    // Cambiar perfil global y relanzar
    g_activeProfile = target;

    // Programar el switch para después del retorno del callback actual
    struct SwitchCtx { GtkApplication* app; };
    auto* ctx = new SwitchCtx{gapp};
    g_timeout_add(100, [](gpointer p) -> gboolean {
        auto* ctx2 = static_cast<SwitchCtx*>(p);
        switchProfile(ctx2->app, g_activeProfile);
        delete ctx2;
        return FALSE;
    }, ctx);
}

static void disableNetworkMode(BrowserWindow* bw) {
    if (g_activeProfile == BrowserProfile::CLEARNET) {
        termPrint(bw, "Ya estás en modo clearnet.");
        termPrompt(bw);
        return;
    }
    enableNetworkMode(bw, "clearnet");
}

// ─── Calculadora segura (evaluador aritmético sin popen/shell) ──────────────

// Gramática: expr = term (('+' | '-') term)*
//            term = factor (('*' | '/' | '%') factor)*
//            factor = ['-'] (number | '(' expr ')' | func '(' expr ')' | func '(' expr ',' expr ')')
// Funciones 1-arg: sqrt, abs, floor, ceil, round, sin, cos, tan, asin, acos, atan,
//                  log, log2, log10, exp, sign, trunc
// Funciones 2-arg: atan2, min, max, pow, hypot, fmod

struct CalcParser {
    const char* p;
    const char* end;
    bool error = false;

    void skipWs() { while (p < end && isspace(*p)) ++p; }

    double parseExpr();
    double parseTerm();
    double parseFactor();
    double parseNumber();

    double parse(const std::string& expr) {
        p = expr.c_str();
        end = p + expr.size();
        error = false;
        double val = parseExpr();
        skipWs();
        if (p != end) error = true;
        return val;
    }
};

double CalcParser::parseNumber() {
    skipWs();
    const char* start = p;
    if (p < end && *p == '.') ++p;
    while (p < end && isdigit(*p)) ++p;
    if (p < end && *p == '.') ++p;
    while (p < end && isdigit(*p)) ++p;
    // exponent
    if (p < end && (*p == 'e' || *p == 'E')) {
        ++p;
        if (p < end && (*p == '+' || *p == '-')) ++p;
        while (p < end && isdigit(*p)) ++p;
    }
    if (p == start) { error = true; return 0; }
    return std::stod(std::string(start, p));
}

double CalcParser::parseFactor() {
    skipWs();
    if (error) return 0;
    if (p < end && *p == '-') { ++p; return -parseFactor(); }
    if (p < end && *p == '+') { ++p; return parseFactor(); }
    if (p < end && *p == '(') {
        ++p;
        double val = parseExpr();
        skipWs();
        if (p < end && *p == ')') ++p; else error = true;
        return val;
    }
    if (p < end && isalpha(*p)) {
        const char* ns = p;
        while (p < end && (isalpha(*p) || *p == '_' || isdigit(*p))) ++p;
        std::string name(ns, p);
        skipWs();
        // constants
        if (name == "pi" || name == "PI")   return M_PI;
        if (name == "e"  || name == "E")    return M_E;
        if (name == "tau")                  return 2.0 * M_PI;
        if (name == "inf" || name == "Inf") return std::numeric_limits<double>::infinity();
        // functions
        if (p < end && *p == '(') {
            ++p;
            double a = parseExpr();
            skipWs();
            bool twoArg = (p < end && *p == ',');
            double b = 0;
            if (twoArg) { ++p; b = parseExpr(); skipWs(); }
            if (p < end && *p == ')') ++p; else error = true;
            // 2-argument
            if (twoArg) {
                if (name == "atan2") return std::atan2(a, b);
                if (name == "min")   return std::min(a, b);
                if (name == "max")   return std::max(a, b);
                if (name == "pow")   return std::pow(a, b);
                if (name == "hypot") return std::hypot(a, b);
                if (name == "fmod") { if (b==0){error=true;return 0;} return std::fmod(a,b); }
                error = true; return 0;
            }
            // 1-argument
            if (name == "sqrt")  return std::sqrt(a);
            if (name == "cbrt")  return std::cbrt(a);
            if (name == "abs")   return std::fabs(a);
            if (name == "floor") return std::floor(a);
            if (name == "ceil")  return std::ceil(a);
            if (name == "round") return std::round(a);
            if (name == "trunc") return std::trunc(a);
            if (name == "sign")  return (double)((a > 0) - (a < 0));
            if (name == "sin")   return std::sin(a);
            if (name == "cos")   return std::cos(a);
            if (name == "tan")   return std::tan(a);
            if (name == "asin")  return std::asin(a);
            if (name == "acos")  return std::acos(a);
            if (name == "atan")  return std::atan(a);
            if (name == "sinh")  return std::sinh(a);
            if (name == "cosh")  return std::cosh(a);
            if (name == "tanh")  return std::tanh(a);
            if (name == "log")   return std::log(a);
            if (name == "log2")  return std::log2(a);
            if (name == "log10") return std::log10(a);
            if (name == "exp")   return std::exp(a);
            if (name == "exp2")  return std::exp2(a);
            if (name == "deg")   return a * (180.0 / M_PI);
            if (name == "rad")   return a * (M_PI / 180.0);
            if (name == "fact") {
                if (a < 0 || a > 20 || a != std::floor(a)) { error = true; return 0; }
                double r = 1; for (int i = 2; i <= (int)a; i++) r *= i; return r;
            }
            error = true; return 0;
        }
        error = true; return 0;
    }
    return parseNumber();
}

double CalcParser::parseTerm() {
    double val = parseFactor();
    while (!error) {
        skipWs();
        if (p >= end) break;
        char op = *p;
        if (op == '*' || op == '/' || op == '%' || op == '^') {
            ++p;
            double rhs = parseFactor();
            if (op == '*') val *= rhs;
            else if (op == '/') {
                if (rhs == 0) { error = true; return 0; }
                val /= rhs;
            } else if (op == '%') {
                if (rhs == 0) { error = true; return 0; }
                val = std::fmod(val, rhs);
            } else { // '^'
                val = std::pow(val, rhs);
            }
        } else break;
    }
    return val;
}

double CalcParser::parseExpr() {
    double val = parseTerm();
    while (!error) {
        skipWs();
        if (p >= end) break;
        char op = *p;
        if (op == '+' || op == '-') {
            ++p;
            double rhs = parseTerm();
            if (op == '+') val += rhs;
            else           val -= rhs;
        } else break;
    }
    return val;
}

static double safeEval(const std::string& expr, bool& ok) {
    CalcParser parser;
    double result = parser.parse(expr);
    ok = !parser.error && std::isfinite(result);
    return result;
}

// ─── Comandos de terminal ───────────────────────────────────────────────────

// Declaraciones adelantadas necesarias dentro de runCommand
static void toggleFindbar(BrowserWindow* bw);
static void findChanged(BrowserWindow* bw);
static void toggleJsConsole(BrowserWindow* bw);

static void runCommand(BrowserWindow* bw, const std::string& raw) {
    size_t sp = raw.find(' ');
    std::string cmd  = strLower(sp != std::string::npos ? raw.substr(0, sp) : raw);
    std::string args = sp != std::string::npos ? raw.substr(sp + 1) : "";
    // Trim args
    while (!args.empty() && isspace(args.front())) args.erase(args.begin());
    while (!args.empty() && isspace(args.back())) args.pop_back();

    auto nav = [&](const std::string& url) {
        webkit_web_view_load_uri(currentWv(bw), url.c_str());
    };

    // ── Tabla de comandos triviales (una sola acción sin lógica) ─────────────
    // Se evalúan antes que el bloque if/else para mantener ese bloque más limpio.
    using CmdFn = std::function<void()>;
    const std::pair<const char*, CmdFn> SIMPLE_CMDS[] = {
        { "back",       [&]{ if (webkit_web_view_can_go_back(currentWv(bw)))    webkit_web_view_go_back(currentWv(bw));    } },
        { "forward",    [&]{ if (webkit_web_view_can_go_forward(currentWv(bw))) webkit_web_view_go_forward(currentWv(bw)); } },
        { "reload",     [&]{ webkit_web_view_reload(currentWv(bw)); } },
        { "reloadhard", [&]{ webkit_web_view_reload_bypass_cache(currentWv(bw)); } },
        { "home",       [&]{ nav(bw->app->homeUri); } },
        { "closetab",   [&]{ onCloseTab(bw, bw->currentTab); } },
    };
    for (const auto& [name, fn] : SIMPLE_CMDS) {
        if (cmd == name) { fn(); termPrint(bw, ""); termPrompt(bw); return; }
    }

    if (cmd == "help") {
        termPrint(bw,
            "─── Navegación ───────────────────────────────\n"
            "  open <url>            → abre URL en pestaña actual\n"
            "  newtab [url]          → abre nueva pestaña\n"
            "  closetab              → cierra pestaña actual\n"
            "  tab <n>               → cambia a pestaña n (1-based)\n"
            "  tabs                  → listar pestañas abiertas\n"
            "  back / forward        → historial del navegador\n"
            "  reload / reloadhard   → recarga (con/sin caché)\n"
            "  home                  → página de inicio\n"
            "  zoom [n]              → nivel de zoom (0.1–5.0)\n"
            "  fullscreen / fs       → alternar pantalla completa\n"
            "  viewsource / source   → ver código fuente de la página\n"
            "─── Atajos de teclado ────────────────────────\n"
            "  Ctrl+T                → nueva pestaña\n"
            "  Ctrl+W                → cerrar pestaña\n"
            "  Ctrl+Tab              → pestaña siguiente\n"
            "  Ctrl+Shift+Tab        → pestaña anterior\n"
            "  Ctrl+L                → enfocar barra de URL\n"
            "  Ctrl+R / Ctrl+Shift+R → recargar / forzar recarga\n"
            "  Ctrl+F                → buscar en página\n"
            "  Ctrl++ / Ctrl+-       → zoom entrada/salida\n"
            "  Ctrl+0                → restablecer zoom\n"
            "  Ctrl+Alt+T            → terminal\n"
            "  Ctrl+Alt+J            → consola JavaScript\n"
            "  Ctrl+Alt+D            → panel de descargas\n"
            "  F11                   → pantalla completa\n"
            "  Alt+←/→               → atrás/adelante\n"
            "  Alt+Home              → inicio\n"
            "  ^/v (en terminal)     → historial de comandos\n"
            "─── Búsqueda ─────────────────────────────────\n"
            "  search <consulta>     → buscar con motor por defecto\n"
            "  find [texto]          → buscar en la página actual\n"
            "  set-engine <id>       → cambiar motor por defecto\n"
            "  engines               → listar motores disponibles\n"
            "  ddg / google / yt / wiki / bing / brave\n"
            "  startpage / qwant / ecosia / yahoo / yandex\n"
            "  baidu / naver / searxng / whoogle <consulta>\n"
            "─── Redes alternativas ───────────────────────\n"
            "  tormode               → cambiar al perfil Tor (restart limpio + wipe)\n"
            "  i2pmode               → cambiar al perfil I2P (restart limpio + wipe)\n"
            "  clearnet              → cambiar al perfil Clearnet (restart limpio)\n"
            "  newnym                → rotar identidad Tor (SIGNAL NEWNYM, solo perfil Tor)\n"
            "─── Marcadores e historial ───────────────────\n"
            "  bookmark              → guardar/quitar marcador actual\n"
            "  bookmarks             → listar marcadores\n"
            "  history [n]           → últimas n entradas (def: 10)\n"
            "─── Utilidades ───────────────────────────────\n"
            "  dark                  → alternar modo oscuro (persiste)\n"
            "  httpsonly on|off      → modo HTTPS-Only (persiste)\n"
            "  noscript  on|off      → bloquear/habilitar JavaScript\n"
            "  jsconsole             → alternar consola JavaScript\n"
            "  downloads / dl        → panel de descargas (Ctrl+Alt+D)\n"
            "  peru / pe             → datos de la República del Perú\n"
            "  useragent [ua|reset]  → cambiar/ver User-Agent\n"
            "  copyurl               → copiar URL al portapapeles\n"
            "  zoom [n]              → nivel de zoom (0.1–5.0, se guarda por dominio)\n"
            "  zoomreset             → resetear zoom y borrar el guardado\n"
            "  calc <expr>           → calculadora (sqrt, sin, cos, atan2, min, max...)\n"
            "  time / date           → hora/fecha actuales\n"
            "  echo <texto>          → imprimir texto\n"
            "  clear                 → limpiar terminal\n"
            "  clearcookies          → limpiar cookies de la pestaña\n"
            "  clearall              → limpiar cookies de todo\n"
            "  about                 → información del navegador\n"
            "  resetall [confirm]    → borrar todos los datos y contraseña (requiere confirm)\n"
            "  quit                  → salir\n"
        );
    } else if (cmd == "open" || cmd == "new") {
        if (!args.empty()) nav(resolveInput(bw, args));
        else termPrint(bw, "Uso: open <url>");
    } else if (cmd == "newtab") {
        openTab(bw, args.empty() ? nullptr : resolveInput(bw, args).c_str(), "normal");
    } else if (cmd == "tab") {
        try { int n = std::stoi(args) - 1; switchTab(bw, n); }
        catch (...) { termPrint(bw, "Uso: tab <número>"); }
    } else if (cmd == "froez") {
        // Navegar a página interna: froez newtab, froez settings, etc.
        std::string page = args.empty() ? "newtab" : strLower(args);
        nav("froez://" + page);
    } else if (cmd == "zoom") {
        if (!args.empty()) {
            try {
                double level = std::stod(args);
                if (level >= 0.1 && level <= 5.0) {
                    webkit_web_view_set_zoom_level(currentWv(bw), level);
                    // Guardar zoom por dominio
                    const char* uri = webkit_web_view_get_uri(currentWv(bw));
                    if (uri) {
                        GUri* gu = g_uri_parse(uri, G_URI_FLAGS_NONE, nullptr);
                        if (gu) {
                            std::string host = g_uri_get_host(gu) ? g_uri_get_host(gu) : "";
                            g_uri_unref(gu);
                            if (!host.empty()) {
                                bw->app->zoomPerDomain[host] = level;
                                saveSettings(bw->app);
                                char buf[64]; snprintf(buf, sizeof(buf), "Zoom %.2fx guardado para %s", level, host.c_str());
                                termPrint(bw, buf); termPrint(bw, ""); termPrompt(bw); return;
                            }
                        }
                    }
                    char buf[32]; snprintf(buf, sizeof(buf), "%.2fx", level);
                    termPrint(bw, std::string("Zoom: ") + buf);
                } else termPrint(bw, "Zoom válido: 0.1 – 5.0 (1.0 = normal)");
            } catch (...) { termPrint(bw, "Uso: zoom <número>"); }
        } else {
            double lv = webkit_web_view_get_zoom_level(currentWv(bw));
            char buf[32]; snprintf(buf, sizeof(buf), "%.2fx", lv);
            termPrint(bw, std::string("Zoom actual: ") + buf);
        }
    // ─── Búsqueda con motor por defecto ─────────────────────────────────────
    } else if (cmd == "search") {
        if (!args.empty())
            nav(searchWithDefault(args, bw->app->defaultSearchEngine, bw->app->searxngUrl, bw->app->whoogleUrl));
        else {
            const SearchEngine* eng = findEngine(bw->app->defaultSearchEngine);
            nav(eng ? eng->homeUrl : "https://duckduckgo.com");
        }
    // ─── Cambiar motor por defecto ───────────────────────────────────────────
    } else if (cmd == "set-engine") {
        if (args.empty()) {
            termPrint(bw, "Uso: set-engine <id>  (usa 'engines' para ver la lista)");
        } else {
            std::string id = strLower(args);
            const SearchEngine* eng = findEngine(id);
            if (eng) {
                bw->app->defaultSearchEngine = id;
                saveSettings(bw->app);
                termPrint(bw, "Motor por defecto: " + eng->name);
            } else {
                termPrint(bw, "Motor desconocido: '" + id + "'  —  usa 'engines' para ver la lista");
            }
        }
    // ─── Listar motores disponibles ──────────────────────────────────────────
    } else if (cmd == "engines") {
        termPrint(bw, "Motores de búsqueda disponibles:");
        for (const auto& e : SEARCH_ENGINES) {
            std::string cur = (e.id == bw->app->defaultSearchEngine) ? " [activo]" : "";
            termPrint(bw, "  " + e.id + cur + "\n       " + e.name);
        }
    // ─── Aliases de motores de búsqueda ─────────────────────────────────────
    // Tabla: { cmd, url_home, template_busqueda }  (%s = query URL-encoded)
    } else if ([&]() -> bool {
        static const struct { const char* cmd; const char* home; const char* tmpl; } ALIASES[] = {
            { "ddg",       "https://duckduckgo.com",    "https://duckduckgo.com/?q=%s"                    },
            { "google",    "https://www.google.com",    "https://www.google.com/search?q=%s"              },
            { "yt",        "https://www.youtube.com",   "https://www.youtube.com/results?search_query=%s" },
            { "wiki",      "https://es.wikipedia.org",  "https://es.wikipedia.org/wiki/%s"                },
            { "bing",      "https://www.bing.com",      "https://www.bing.com/search?q=%s"                },
            { "brave",     "https://search.brave.com",  "https://search.brave.com/search?q=%s"            },
            { "startpage", "https://www.startpage.com", "https://www.startpage.com/search?q=%s"           },
            { "qwant",     "https://www.qwant.com",     "https://www.qwant.com/?q=%s"                     },
            { "ecosia",    "https://www.ecosia.org",    "https://www.ecosia.org/search?q=%s"              },
            { "yahoo",     "https://search.yahoo.com",  "https://search.yahoo.com/search?p=%s"            },
            { "yandex",    "https://yandex.com",        "https://yandex.com/search/?text=%s"              },
            { "baidu",     "https://www.baidu.com",     "https://www.baidu.com/s?wd=%s"                   },
            { "naver",     "https://www.naver.com",     "https://search.naver.com/search.naver?query=%s"  },
        };
        for (const auto& a : ALIASES) {
            if (cmd != a.cmd) continue;
            if (args.empty()) { nav(a.home); }
            else { std::string u = a.tmpl; size_t p = u.find("%s"); if (p != std::string::npos) u.replace(p, 2, urlEncode(args)); nav(u); }
            return true;
        }
        return false;
    }()) {
        // (manejado por la tabla de aliases)
    } else if (cmd == "searxng") {
        nav(args.empty() ? bw->app->searxngUrl : bw->app->searxngUrl + "/search?q=" + urlEncode(args));
    } else if (cmd == "whoogle") {
        nav(args.empty() ? bw->app->whoogleUrl : bw->app->whoogleUrl + "/search?q=" + urlEncode(args));
    } else if (cmd == "tormode") {
        enableNetworkMode(bw, "tor"); return;
    } else if (cmd == "i2pmode") {
        enableNetworkMode(bw, "i2p"); return;
    } else if (cmd == "clearnet") {
        disableNetworkMode(bw); return;
    } else if (cmd == "newnym") {
        // Rotar identidad Tor via socket de control (puerto 9051 por defecto)
        // Envia: AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\n
        if (g_activeProfile != BrowserProfile::TOR) {
            termPrint(bw, "newnym solo esta disponible en el perfil Tor.");
            termPrompt(bw);
            return;
        }
        termPrint(bw, "Solicitando nueva identidad Tor (NEWNYM)...");
        // Usar GLib spawn para no bloquear el hilo principal
        char* argv[] = {
            (char*)"sh", (char*)"-c",
            (char*)"echo -e 'AUTHENTICATE \"\"\\r\\nSIGNAL NEWNYM\\r\\nQUIT\\r\\n' | nc -q1 127.0.0.1 9051 2>&1",
            nullptr
        };
        GPid pid; gint out_fd;
        GError* nerr = nullptr;
        if (g_spawn_async_with_pipes(nullptr, argv, nullptr,
                G_SPAWN_SEARCH_PATH, nullptr, nullptr,
                &pid, nullptr, &out_fd, nullptr, &nerr)) {
            GIOChannel* ch = g_io_channel_unix_new(out_fd);
            g_io_add_watch(ch, G_IO_IN, [](GIOChannel* c, GIOCondition, gpointer p) -> gboolean {
                auto* bw2 = static_cast<BrowserWindow*>(p);
                gchar* line = nullptr; gsize len = 0;
                g_io_channel_read_line(c, &line, &len, nullptr, nullptr);
                if (line) {
                    std::string resp(line, len);
                    while (!resp.empty() && isspace(resp.back())) resp.pop_back();
                    if (resp.find("250") != std::string::npos)
                        termPrint(bw2, "Nueva identidad Tor obtenida. Los proximos circuitos seran nuevos.");
                    else if (!resp.empty())
                        termPrint(bw2, "Respuesta Tor: " + resp);
                    g_free(line);
                }
                termPrint(bw2, ""); termPrompt(bw2);
                return FALSE;
            }, bw);
            g_io_channel_unref(ch);
        } else {
            termPrint(bw, "Error al contactar el socket de control Tor.");
            termPrint(bw, "Asegurate de que tor este corriendo con ControlPort 9051.");
            if (nerr) { g_warning("[i4froez] newnym: %s", nerr->message); g_error_free(nerr); }
            termPrompt(bw);
        }
        return;
    } else if (cmd == "whoami" || cmd == "serverip") {
        bool isServerIp = (cmd == "serverip");
        termPrint(bw, isServerIp ? "Consultando IP del servidor..." : "Consultando IP pública...");
        // Usamos GLib spawn para no bloquear
        char* argv[] = { (char*)"curl", (char*)"-s", (char*)"--max-time", (char*)"7", (char*)"https://api.ipify.org", nullptr };
        GPid pid; gint out_fd;
        GError* err = nullptr;
        if (g_spawn_async_with_pipes(nullptr, argv, nullptr,
                G_SPAWN_SEARCH_PATH, nullptr, nullptr,
                &pid, nullptr, &out_fd, nullptr, &err)) {
            GIOChannel* ch = g_io_channel_unix_new(out_fd);
            g_io_add_watch(ch, G_IO_IN, [](GIOChannel* c, GIOCondition, gpointer p) -> gboolean {
                auto* bw2 = static_cast<BrowserWindow*>(p);
                gchar* line = nullptr;
                gsize len = 0;
                g_io_channel_read_line(c, &line, &len, nullptr, nullptr);
                if (line) {
                    std::string ip(line, len);
                    while (!ip.empty() && isspace(ip.back())) ip.pop_back();
                    termPrint(bw2, "IP pública: " + ip);
                    g_free(line);
                }
                termPrint(bw2, ""); termPrompt(bw2);
                return FALSE;
            }, bw);
            g_io_channel_unref(ch);
        } else {
            termPrint(bw, "Error ejecutando curl. ¿Está instalado?");
            if (err) { g_warning("[i4froez] curl: %s", err->message); g_error_free(err); }
            termPrint(bw, ""); termPrompt(bw);
        }
        return;
    } else if (cmd == "bookmark") {
        const char* uri = webkit_web_view_get_uri(currentWv(bw));
        if (!uri || std::string(uri) == "about:blank") {
            termPrint(bw, "Sin página activa.");
        } else {
            const char* titleRaw = webkit_web_view_get_title(currentWv(bw));
            std::string title = titleRaw ? titleRaw : uri;
            if (bw->app->isBookmarked(uri)) {
                bw->app->removeBookmark(uri);
                termPrint(bw, "Marcador eliminado: " + std::string(uri));
                gtk_button_set_label(bw->bookmarkStar, "◇");
            } else {
                bw->app->addBookmark(uri, title);
                termPrint(bw, "Marcador guardado: " + title);
                gtk_button_set_label(bw->bookmarkStar, "◆");
            }
        }
    } else if (cmd == "bookmarks") {
        if (bw->app->bookmarks.empty()) { termPrint(bw, "Sin marcadores guardados."); }
        else {
            termPrint(bw, "Marcadores guardados:");
            int i = 1;
            for (const auto& b : bw->app->bookmarks)
                termPrint(bw, "  " + std::to_string(i++) + ". " +
                    b["title"].get<std::string>() + "\n       " + b["url"].get<std::string>());
        }
    } else if (cmd == "history") {
        int n = 10;
        try { if (!args.empty()) n = std::stoi(args); } catch (...) {}
        if (bw->app->history.empty()) { termPrint(bw, "El historial está vacío."); }
        else {
            termPrint(bw, "Últimas " + std::to_string(n) + " páginas:");
            int total = (int)bw->app->history.size();
            int start = std::max(0, total - n);
            int i = 1;
            for (int j = total - 1; j >= start; j--) {
                const auto& h = bw->app->history[j];
                std::string ts = h["ts"].get<std::string>().substr(0, 19);
                std::replace(ts.begin(), ts.end(), 'T', ' ');
                termPrint(bw, "  " + std::to_string(i++) + ". [" + ts + "] " +
                    h["title"].get<std::string>() + "\n       " + h["url"].get<std::string>());
            }
        }
    } else if (cmd == "dark") {
        bw->app->darkMode = !bw->app->darkMode;
        saveSettings(bw->app);
        termPrint(bw, std::string("Modo oscuro ") + (bw->app->darkMode ? "activado" : "desactivado") + ".");
        if (bw->app->darkMode) applyDarkCss(bw);
        else removeDarkCss(bw);
    } else if (cmd == "httpsonly" || cmd == "noscript") {
        // Patrón on/off compartido para ambos comandos
        bool isHttpsOnly = (cmd == "httpsonly");
        bool& flag       = isHttpsOnly ? bw->app->httpsOnly : bw->app->jsBlocked;

        if (args == "on" || args == "1") {
            flag = true;
            saveSettings(bw->app);
            if (isHttpsOnly) {
                termPrint(bw, "HTTPS-Only: activado. Las URLs http:// serán redirigidas a https://");
            } else {
                bw->app->jsBlocked = true;
                WebKitSettings* s = webkit_web_view_get_settings(currentWv(bw));
                webkit_settings_set_enable_javascript(s, FALSE);
                termPrint(bw, "JavaScript: bloqueado en esta y nuevas pestañas.");
            }
        } else if (args == "off" || args == "0") {
            flag = false;
            saveSettings(bw->app);
            if (isHttpsOnly) {
                termPrint(bw, "HTTPS-Only: desactivado.");
            } else {
                WebKitSettings* s = webkit_web_view_get_settings(currentWv(bw));
                webkit_settings_set_enable_javascript(s, TRUE);
                termPrint(bw, "JavaScript: habilitado.");
            }
        } else {
            if (isHttpsOnly)
                termPrint(bw, std::string("HTTPS-Only: ") + (flag ? "activado" : "desactivado")
                    + "\n  Uso: httpsonly on|off");
            else
                termPrint(bw, std::string("JavaScript: ") + (flag ? "bloqueado" : "habilitado")
                    + "\n  Uso: noscript on|off");
        }
    } else if (cmd == "jsconsole") {
        toggleJsConsole(bw); termPrint(bw, bw->jsConsoleVisible ? "Consola JS abierta." : "Consola JS cerrada."); termPrint(bw, ""); termPrompt(bw); return;
    } else if (cmd == "downloads" || cmd == "dl") {
        toggleDlPanel(bw); termPrint(bw, g_dlPanel.visible ? "Panel de descargas abierto." : "Panel de descargas cerrado."); termPrint(bw, ""); termPrompt(bw); return;
    } else if (cmd == "peru" || cmd == "pe") {
        nav("froez://peru");
    } else if (cmd == "zoomreset") {
        webkit_web_view_set_zoom_level(currentWv(bw), 1.0);
        const char* uri = webkit_web_view_get_uri(currentWv(bw));
        if (uri) {
            GUri* gu = g_uri_parse(uri, G_URI_FLAGS_NONE, nullptr);
            if (gu) {
                std::string host = g_uri_get_host(gu) ? g_uri_get_host(gu) : "";
                g_uri_unref(gu);
                if (!host.empty()) { bw->app->zoomPerDomain.erase(host); saveSettings(bw->app); termPrint(bw, "Zoom reseteado y eliminado para " + host); termPrint(bw, ""); termPrompt(bw); return; }
            }
        }
        termPrint(bw, "Zoom reseteado a 1.0x.");
    } else if (cmd == "calc") {
        if (!args.empty()) {
            bool ok;
            double result = safeEval(args, ok);
            if (ok) {
                // Formatear: si es entero exacto mostrar sin decimales
                std::string res;
                if (result == std::floor(result) && std::fabs(result) < 1e15) {
                    res = std::to_string((long long)result);
                } else {
                    char buf[64];
                    snprintf(buf, sizeof(buf), "%.10g", result);
                    res = buf;
                }
                termPrint(bw, args + " = " + res);
            } else {
                termPrint(bw, "Error en expresión.\n"
                    "  1-arg: sqrt cbrt abs floor ceil round trunc sign\n"
                    "         sin cos tan asin acos atan sinh cosh tanh\n"
                    "         log log2 log10 exp exp2 deg rad fact\n"
                    "  2-arg: atan2(y,x) min(a,b) max(a,b) pow(b,e) hypot(x,y) fmod(a,b)\n"
                    "  Const: pi  e  tau  inf");
            }
        } else termPrint(bw, "Uso: calc <expr> , Las funciones trigonometricas son radianes y van sin el simbolo de grados.");
    } else if (cmd == "time") {
        time_t t = time(nullptr); struct tm* tm = localtime(&t); char buf[16];
        strftime(buf, sizeof(buf), "%H:%M:%S", tm); termPrint(bw, buf);
    } else if (cmd == "date") {
        time_t t = time(nullptr); struct tm* tm = localtime(&t); char buf[16];
        strftime(buf, sizeof(buf), "%Y-%m-%d", tm); termPrint(bw, buf);
    } else if (cmd == "echo") {
        if (!args.empty()) termPrint(bw, args);
    } else if (cmd == "clear" || cmd == "clean") {
        gtk_text_buffer_set_text(bw->terminalBuf, "", -1);
    } else if (cmd == "about") {
        const SearchEngine* eng = findEngine(bw->app->defaultSearchEngine);
        std::string engName = eng ? eng->name : bw->app->defaultSearchEngine;
        std::string profName = profileDisplayName(g_activeProfile);
        termPrint(bw,
            "I4 Froez v0.8 (BETA)\n"
            "WebKitGTK 6 + GTK 4 + C++20\n"
            "Perfil activo: " + profName + " (" + profileDir() + ")\n"
            "Redes: Tor (" + bw->app->torProxy + "), I2P (" + bw->app->i2pProxy + ")\n"
            "Motor de busqueda: " + engName + " (" + bw->app->defaultSearchEngine + ")\n"
            "─── Perfiles aislados ─────────────────────────\n"
            "  [*] Clearnet / Tor / I2P tienen almacenamiento separado\n"
            "  [*] Cada perfil con sal, verificador y clave propios\n"
            "  [*] Cambio de perfil hace wipe de RAM (Tor/I2P al salir)\n"
            "  [*] Circuit isolation por pestaña en Tor (SOCKS5 user:pass)\n"
            "  [*] I2P bloquea trafico clearnet automaticamente\n"
            "─── Fingerprint por perfil ─────────────────────\n"
            "  [*] Clearnet: Chrome/Windows (UA coherente)\n"
            "  [*] Tor: Firefox/128 Windows (identico a Tor Browser)\n"
            "  [*] I2P: Firefox/115 Windows (perfil generico)\n"
            "  [*] Timezone UTC fija en todos los perfiles\n"
            "─── Protecciones activas ──────────────────────\n"
            "  [*] WebRTC, popups, autoplay bloqueados\n"
            "  [*] Letterboxing, timing, canvas, audio\n"
            "  [*] Navigator, Screen, WebGL normalizados\n"
            "  [*] Historial/marcadores: AES-256-GCM (PBKDF2)\n"
            "  [*] Geolocalización y MediaDevices bloqueados\n"
            "  [*] Battery API, Speech API bloqueados\n"
            "  [*] Connection API, Clipboard.read bloqueados\n"
            "  [*] Storage estimate normalizado\n"
            "  [*] Esquemas javascript:/data:/vbscript: bloqueados\n"
            "─── Comandos de red ──────────────────────────\n"
            "  [+] tormode/i2pmode/clearnet — cambio de perfil con wipe\n"
            "  [+] newnym — rotar circuito Tor (requiere ControlPort 9051)\n"
        );
    } else if (cmd == "clearcookies") {
        // Limpiar datos de la sesión actual independientemente del modo
        TabData& td = currentTd(bw);
        WebKitNetworkSession* ns = webkit_web_view_get_network_session(td.webview);
        if (ns) {
            WebKitWebsiteDataManager* wdm = webkit_network_session_get_website_data_manager(ns);
            if (wdm) {
                webkit_website_data_manager_clear(wdm,
                    (WebKitWebsiteDataTypes)(
                        WEBKIT_WEBSITE_DATA_COOKIES |
                        WEBKIT_WEBSITE_DATA_DISK_CACHE |
                        WEBKIT_WEBSITE_DATA_MEMORY_CACHE |
                        WEBKIT_WEBSITE_DATA_SESSION_STORAGE |
                        WEBKIT_WEBSITE_DATA_LOCAL_STORAGE |
                        WEBKIT_WEBSITE_DATA_INDEXEDDB_DATABASES |
                        WEBKIT_WEBSITE_DATA_OFFLINE_APPLICATION_CACHE
                    ),
                    0, nullptr, nullptr, nullptr);
            }
        }
        termPrint(bw, "Cookies y datos de sesión de la pestaña actual eliminados.");
    } else if (cmd == "clearall") {
        // Limpiar todas las sesiones (incluida la por defecto)
        auto clearSession = [](WebKitNetworkSession* ns) {
            if (!ns) return;
            WebKitWebsiteDataManager* wdm = webkit_network_session_get_website_data_manager(ns);
            if (!wdm) return;
            webkit_website_data_manager_clear(wdm,
                (WebKitWebsiteDataTypes)(
                    WEBKIT_WEBSITE_DATA_COOKIES |
                    WEBKIT_WEBSITE_DATA_DISK_CACHE |
                    WEBKIT_WEBSITE_DATA_MEMORY_CACHE |
                    WEBKIT_WEBSITE_DATA_SESSION_STORAGE |
                    WEBKIT_WEBSITE_DATA_LOCAL_STORAGE |
                    WEBKIT_WEBSITE_DATA_INDEXEDDB_DATABASES |
                    WEBKIT_WEBSITE_DATA_OFFLINE_APPLICATION_CACHE
                ),
                0, nullptr, nullptr, nullptr);
        };
        for (auto& td : bw->tabs)
            clearSession(webkit_web_view_get_network_session(td.webview));
        termPrint(bw, "Datos de todas las pestañas eliminados.");
    } else if (cmd == "quit" || cmd == "exit") {
        // Wipe de RAM al salir si estamos en perfil Tor o I2P
        if (g_activeProfile == BrowserProfile::TOR ||
            g_activeProfile == BrowserProfile::I2P) {
            wipeSessionMemory(bw->app);
        } else {
            if (!g_masterKey.empty()) {
                OPENSSL_cleanse(g_masterKey.data(), g_masterKey.size());
                g_masterKey.clear();
            }
        }
        g_application_quit(g_application_get_default());
        return;
    // ─── Nuevo: listar pestañas ──────────────────────────────────────────────
    } else if (cmd == "tabs") {
        termPrint(bw, "Pestañas abiertas:");
        for (int i = 0; i < (int)bw->tabs.size(); i++) {
            const char* uri   = webkit_web_view_get_uri(bw->tabs[i].webview);
            const char* title = webkit_web_view_get_title(bw->tabs[i].webview);
            std::string cur   = (i == bw->currentTab) ? " [activa]" : "";
            std::string mode  = bw->tabs[i].mode != "normal" ? " [" + bw->tabs[i].mode + "]" : "";
            termPrint(bw, "  " + std::to_string(i+1) + "." + cur + mode +
                " " + (title ? std::string(title) : "(sin título)") +
                "\n       " + (uri ? std::string(uri) : ""));
        }
    // ─── Nuevo: buscar en página desde terminal ──────────────────────────────
    } else if (cmd == "find") {
        if (!args.empty()) {
            gtk_widget_set_visible(GTK_WIDGET(bw->findbarBox), TRUE);
            bw->findbarVisible = true;
            gtk_editable_set_text(GTK_EDITABLE(bw->findEntry), args.c_str());
            findChanged(bw);
            gtk_widget_grab_focus(GTK_WIDGET(bw->findEntry));
            termPrint(bw, "Buscando: " + args);
        } else {
            toggleFindbar(bw);
        }
    // ─── Nuevo: cambiar User-Agent temporalmente ─────────────────────────────
    } else if (cmd == "useragent") {
        if (args.empty() || args == "reset") {
            // Restaurar UA del perfil activo
            std::string defaultUa;
            switch (g_activeProfile) {
                case BrowserProfile::TOR:
                    defaultUa = "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0";
                    break;
                case BrowserProfile::I2P:
                    defaultUa = "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0";
                    break;
                default:
                    defaultUa = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
                    break;
            }
            WebKitSettings* s = webkit_web_view_get_settings(currentWv(bw));
            webkit_settings_set_user_agent(s, defaultUa.c_str());
            termPrint(bw, "User-Agent restaurado al valor del perfil activo.");
        } else {
            WebKitSettings* s = webkit_web_view_get_settings(currentWv(bw));
            webkit_settings_set_user_agent(s, args.c_str());
            termPrint(bw, "User-Agent cambiado a: " + args);
        }
    // ─── Nuevo: copiar URL actual al portapapeles ────────────────────────────
    } else if (cmd == "copyurl") {
        const char* uri = webkit_web_view_get_uri(currentWv(bw));
        if (uri && uri[0]) {
            GdkDisplay* disp = gdk_display_get_default();
            GdkClipboard* clip = gdk_display_get_clipboard(disp);
            gdk_clipboard_set_text(clip, uri);
            termPrint(bw, "URL copiada: " + std::string(uri));
        } else {
            termPrint(bw, "No hay URL activa.");
        }
    // ─── Nuevo: ver código fuente de la página ───────────────────────────────
    } else if (cmd == "viewsource" || cmd == "source") {
        const char* uri = webkit_web_view_get_uri(currentWv(bw));
        if (uri && startsWith(std::string(uri), "http")) {
            openTab(bw, (std::string("view-source:") + uri).c_str(), currentTd(bw).mode);
        } else {
            termPrint(bw, "Solo se puede ver la fuente de páginas http/https.");
        }
    // ─── Nuevo: pantalla completa ────────────────────────────────────────────
    } else if (cmd == "fullscreen" || cmd == "fs") {
        if (gtk_window_is_fullscreen(GTK_WINDOW(bw->window))) {
            gtk_window_unfullscreen(GTK_WINDOW(bw->window));
            termPrint(bw, "Saliendo de pantalla completa.");
        } else {
            gtk_window_fullscreen(GTK_WINDOW(bw->window));
            termPrint(bw, "Pantalla completa. Presiona F11 o escribe 'fullscreen' para salir.");
        }
    // ─── Resetear todos los datos del navegador ─────────────────────────────
    } else if (cmd == "resetall") {
        std::string profName = profileDisplayName(g_activeProfile);
        termPrint(bw, "ADVERTENCIA: esto borrara historial, marcadores, ajustes,");
        termPrint(bw, "sal de cifrado y contraseña del perfil " + profName + ".");
        termPrint(bw, "El navegador cerrara y al reabrirlo pedira una contraseña nueva para este perfil.");
        termPrint(bw, "Los demas perfiles NO se ven afectados.");
        termPrint(bw, "Escribe 'resetall confirm' para continuar.");
        if (args == "confirm") {
            namespace fs = std::filesystem;
            int removed = 0;
            for (const auto& p : {historyFile(), bookmarksFile(),
                                   saltFile(), settingsFile(), verifierFile()}) {
                std::error_code ec;
                if (fs::remove(p, ec)) removed++;
            }
            if (!g_masterKey.empty())
                OPENSSL_cleanse(g_masterKey.data(), g_masterKey.size());
            char buf[64];
            snprintf(buf, sizeof(buf), "Borrados %d archivos del perfil %s. Cerrando...",
                     removed, profName.c_str());
            termPrint(bw, buf);
            termPrint(bw, "");
            g_timeout_add(800, [](gpointer) -> gboolean {
                g_application_quit(g_application_get_default());
                return FALSE;
            }, nullptr);
            return;
        }
    // ─── 77airwaves ──────────────────────────────────────────────────────────
    } else if (cmd == "77airwaves") {
        nav("https://www.youtube.com/watch?v=jsXXKQ_nl30");
    } else {
        termPrint(bw, "Comando desconocido: '" + cmd + "'  —  escribe 'help'");
    }

    termPrint(bw, "");
    termPrompt(bw);
}

// ─── Manejo de teclado en terminal ─────────────────────────────────────────

static gboolean onTerminalKey(GtkEventControllerKey* ctrl, guint keyval,
                              guint, GdkModifierType, gpointer data) {
    auto* bw = static_cast<BrowserWindow*>(data);
    if (keyval == GDK_KEY_Return || keyval == GDK_KEY_KP_Enter) {
        // Leer el comando directamente desde promptEndMark hasta el fin del buffer.
        // Esto es independiente del texto del prompt y nunca se rompe.
        std::string cmd;
        if (bw->promptEndMark) {
            GtkTextIter promptEnd, bufEnd;
            gtk_text_buffer_get_iter_at_mark(bw->terminalBuf, &promptEnd, bw->promptEndMark);
            gtk_text_buffer_get_end_iter(bw->terminalBuf, &bufEnd);
            gchar* raw = gtk_text_buffer_get_text(bw->terminalBuf, &promptEnd, &bufEnd, FALSE);
            cmd = raw ? raw : "";
            g_free(raw);
        }
        // Trim
        while (!cmd.empty() && isspace((unsigned char)cmd.front())) cmd.erase(cmd.begin());
        while (!cmd.empty() && isspace((unsigned char)cmd.back()))  cmd.pop_back();

        if (!cmd.empty()) {
            // Añadir al historial de comandos (evitar duplicados consecutivos)
            if (bw->termHistory.empty() || bw->termHistory.back() != cmd)
                bw->termHistory.push_back(cmd);
            if (bw->termHistory.size() > 200) bw->termHistory.erase(bw->termHistory.begin());
            bw->termHistoryIdx = -1;
            termPrint(bw, "");
            runCommand(bw, cmd);
            return TRUE;
        }
        bw->termHistoryIdx = -1;
        termPrint(bw, ""); termPrompt(bw);
        return TRUE;
    }

    // Navegación por historial con flechas
    if ((keyval == GDK_KEY_Up || keyval == GDK_KEY_KP_Up) && !bw->termHistory.empty()) {
        int newIdx = (bw->termHistoryIdx < 0)
            ? (int)bw->termHistory.size() - 1
            : std::max(0, bw->termHistoryIdx - 1);
        bw->termHistoryIdx = newIdx;
        const std::string& histCmd = bw->termHistory[newIdx];
        // Reemplazar desde el mark de prompt hasta el fin del buffer
        if (bw->promptEndMark) {
            GtkTextIter promptEnd, bufEnd;
            gtk_text_buffer_get_iter_at_mark(bw->terminalBuf, &promptEnd, bw->promptEndMark);
            gtk_text_buffer_get_end_iter(bw->terminalBuf, &bufEnd);
            gtk_text_buffer_delete(bw->terminalBuf, &promptEnd, &bufEnd);
            GtkTextIter insertPos;
            gtk_text_buffer_get_end_iter(bw->terminalBuf, &insertPos);
            gtk_text_buffer_insert(bw->terminalBuf, &insertPos, histCmd.c_str(), -1);
            GtkTextIter newEnd;
            gtk_text_buffer_get_end_iter(bw->terminalBuf, &newEnd);
            gtk_text_buffer_place_cursor(bw->terminalBuf, &newEnd);
            gtk_text_view_scroll_to_iter(bw->terminalTv, &newEnd, 0.0, TRUE, 0.0, 1.0);
        }
        return TRUE;
    }
    if ((keyval == GDK_KEY_Down || keyval == GDK_KEY_KP_Down) && bw->termHistoryIdx >= 0) {
        if (bw->promptEndMark) {
            GtkTextIter promptEnd, bufEnd;
            gtk_text_buffer_get_iter_at_mark(bw->terminalBuf, &promptEnd, bw->promptEndMark);
            gtk_text_buffer_get_end_iter(bw->terminalBuf, &bufEnd);
            gtk_text_buffer_delete(bw->terminalBuf, &promptEnd, &bufEnd);
            int newIdx = bw->termHistoryIdx + 1;
            if (newIdx < (int)bw->termHistory.size()) {
                bw->termHistoryIdx = newIdx;
                GtkTextIter insertPos;
                gtk_text_buffer_get_end_iter(bw->terminalBuf, &insertPos);
                gtk_text_buffer_insert(bw->terminalBuf, &insertPos, bw->termHistory[newIdx].c_str(), -1);
            } else {
                bw->termHistoryIdx = -1;
            }
            GtkTextIter newEnd;
            gtk_text_buffer_get_end_iter(bw->terminalBuf, &newEnd);
            gtk_text_buffer_place_cursor(bw->terminalBuf, &newEnd);
            gtk_text_view_scroll_to_iter(bw->terminalTv, &newEnd, 0.0, TRUE, 0.0, 1.0);
        }
        return TRUE;
    }

    // Proteger prompt
    static const guint protectedKeys[] = {
        GDK_KEY_BackSpace, GDK_KEY_Delete, GDK_KEY_Left, GDK_KEY_Home,
        GDK_KEY_KP_Left,   GDK_KEY_KP_Home, 0
    };
    for (int i = 0; protectedKeys[i]; i++) {
        if (keyval == protectedKeys[i] && bw->promptEndMark) {
            GtkTextMark* insertMark = gtk_text_buffer_get_insert(bw->terminalBuf);
            GtkTextIter cursor, limit;
            gtk_text_buffer_get_iter_at_mark(bw->terminalBuf, &cursor, insertMark);
            gtk_text_buffer_get_iter_at_mark(bw->terminalBuf, &limit,  bw->promptEndMark);
            if (gtk_text_iter_compare(&cursor, &limit) <= 0) return TRUE;
        }
    }
    return FALSE;
}

// ─── Manejo de teclado en inspector ────────────────────────────────────────

static void closeInspector(BrowserWindow* bw);
static void inspectorApply(BrowserWindow* bw);

static gboolean onInspectorKey(GtkEventControllerKey*, guint keyval, guint,
                                GdkModifierType state, gpointer data) {
    auto* bw = static_cast<BrowserWindow*>(data);
    bool ctrl = !!(state & GDK_CONTROL_MASK);
    if (ctrl && keyval == GDK_KEY_Return) { inspectorApply(bw); return TRUE; }
    if (keyval == GDK_KEY_Escape)          { closeInspector(bw); return TRUE; }
    return FALSE;
}

// ─── Inspector ──────────────────────────────────────────────────────────────

static void inspectorLoad(BrowserWindow* bw);

static void openInspector(BrowserWindow* bw) {
    if (bw->inspectorMode) return;
    if (bw->terminalVisible) {
        gtk_label_set_text(bw->statusbar, "Cierra la terminal primero (Ctrl+Alt+T)");
        g_timeout_add(2000, [](gpointer p) -> gboolean { gtk_label_set_text(GTK_LABEL(p), ""); return FALSE; }, bw->statusbar);
        return;
    }
    bw->inspectorMode = true;
    // Añadir el panel al tabStack si aun no esta, y mostrarlo a pantalla completa
    if (!gtk_stack_get_child_by_name(bw->tabStack, "inspector")) {
        gtk_widget_set_vexpand(bw->inspPanel, TRUE);
        gtk_widget_set_hexpand(bw->inspPanel, TRUE);
        gtk_stack_add_named(bw->tabStack, bw->inspPanel, "inspector");
    }
    gtk_stack_set_visible_child_name(bw->tabStack, "inspector");
    inspectorLoad(bw);
}

static void closeInspector(BrowserWindow* bw) {
    if (!bw->inspectorMode) return;
    bw->inspectorMode = false;
    // Volver a la pestaña activa
    std::string name = "tab" + std::to_string(bw->currentTab);
    gtk_stack_set_visible_child_name(bw->tabStack, name.c_str());
}

static void inspectorApply(BrowserWindow* bw) {
    GtkTextIter start, end;
    gtk_text_buffer_get_start_iter(bw->inspectorBuf, &start);
    gtk_text_buffer_get_end_iter(bw->inspectorBuf,   &end);
    gchar* html = gtk_text_buffer_get_text(bw->inspectorBuf, &start, &end, FALSE);
    // Encode to base64 to avoid JS injection via backticks/backslashes in HTML
    std::string htmlStr(html);
    g_free(html);
    gchar* b64 = g_base64_encode(reinterpret_cast<const guchar*>(htmlStr.c_str()), htmlStr.size());
    std::string js = std::string(
        "(function(){"
        "var b=atob('") + b64 + "');"
        "document.open();"
        "document.write(b);"
        "document.close();"
        "})();";
    g_free(b64);
    webkit_web_view_evaluate_javascript(currentWv(bw), js.c_str(), -1,
        nullptr, nullptr, nullptr, nullptr, nullptr);
}

static void inspectorLoad(BrowserWindow* bw) {
    gtk_text_buffer_set_text(bw->inspectorBuf, "Cargando HTML...", -1);
    WebKitWebView* wv = currentWv(bw);
    struct Ctx { GtkTextBuffer* buf; };
    auto* ctx = new Ctx{bw->inspectorBuf};
    webkit_web_view_evaluate_javascript(wv, "document.documentElement.outerHTML", -1,
        nullptr, nullptr, nullptr,
        [](GObject* src, GAsyncResult* res, gpointer p) {
            auto* ctx2 = static_cast<Ctx*>(p);
            GError* err = nullptr;
            // En WebKit6 evaluate_javascript_finish devuelve JSCValue* directamente
            JSCValue* val = webkit_web_view_evaluate_javascript_finish(
                WEBKIT_WEB_VIEW(src), res, &err);
            if (val) {
                char* str = jsc_value_to_string(val);
                gtk_text_buffer_set_text(ctx2->buf, str ? str : "[vacío]", -1);
                g_free(str);
                g_object_unref(val);
            } else {
                std::string msg = err ? std::string("[Error: ") + err->message + "]" : "[vacío]";
                gtk_text_buffer_set_text(ctx2->buf, msg.c_str(), -1);
                if (err) g_error_free(err);
            }
            delete ctx2;
        }, ctx);
}

// ─── Atajo de teclado global ────────────────────────────────────────────────

static void toggleFindbar(BrowserWindow* bw);
static void toggleTerminal(BrowserWindow* bw);
static void toggleInspector(BrowserWindow* bw);
static void toggleJsConsole(BrowserWindow* bw);

static gboolean onGlobalKey(GtkEventControllerKey*, guint keyval, guint,
                             GdkModifierType state, gpointer data) {
    auto* bw = static_cast<BrowserWindow*>(data);
    bool ctrlHeld  = !!(state & GDK_CONTROL_MASK);
    bool altHeld   = !!(state & GDK_ALT_MASK);
    bool shiftHeld = !!(state & GDK_SHIFT_MASK);

    if (ctrlHeld && !altHeld) {
        if (keyval == GDK_KEY_t) { openTab(bw); return TRUE; }
        if (keyval == GDK_KEY_w) { onCloseTab(bw, bw->currentTab); return TRUE; }
        if (keyval == GDK_KEY_l) { gtk_widget_grab_focus(GTK_WIDGET(bw->urlEntry)); gtk_editable_select_region(GTK_EDITABLE(bw->urlEntry), 0, -1); return TRUE; }
        if (keyval == GDK_KEY_r && !shiftHeld) { webkit_web_view_reload(currentWv(bw)); return TRUE; }
        if (keyval == GDK_KEY_r &&  shiftHeld) { webkit_web_view_reload_bypass_cache(currentWv(bw)); return TRUE; }
        if (keyval == GDK_KEY_f) { toggleFindbar(bw); return TRUE; }
        // Ctrl+Tab / Ctrl+Shift+Tab para navegar entre pestañas
        if (keyval == GDK_KEY_Tab && !shiftHeld) {
            int next = (bw->currentTab + 1) % (int)bw->tabs.size();
            switchTab(bw, next); return TRUE;
        }
        if ((keyval == GDK_KEY_Tab && shiftHeld) || keyval == GDK_KEY_ISO_Left_Tab) {
            int prev = (bw->currentTab - 1 + (int)bw->tabs.size()) % (int)bw->tabs.size();
            switchTab(bw, prev); return TRUE;
        }
        if (keyval == GDK_KEY_plus || keyval == GDK_KEY_equal) {
            double z = std::min(webkit_web_view_get_zoom_level(currentWv(bw)) + 0.1, 5.0);
            webkit_web_view_set_zoom_level(currentWv(bw), z);
            char buf[32]; snprintf(buf, sizeof(buf), "Zoom: %.0f%%", z * 100);
            gtk_label_set_text(bw->statusbar, buf);
            g_timeout_add(1500, [](gpointer p)->gboolean{ gtk_label_set_text(GTK_LABEL(p),""); return FALSE; }, bw->statusbar);
            const char* uri = webkit_web_view_get_uri(currentWv(bw));
            if (uri) { GUri* gu = g_uri_parse(uri, G_URI_FLAGS_NONE, nullptr); if (gu) { std::string h = g_uri_get_host(gu) ? g_uri_get_host(gu) : ""; g_uri_unref(gu); if (!h.empty()) { bw->app->zoomPerDomain[h] = z; saveSettings(bw->app); } } }
            return TRUE;
        }
        if (keyval == GDK_KEY_minus) {
            double z = std::max(webkit_web_view_get_zoom_level(currentWv(bw)) - 0.1, 0.1);
            webkit_web_view_set_zoom_level(currentWv(bw), z);
            char buf[32]; snprintf(buf, sizeof(buf), "Zoom: %.0f%%", z * 100);
            gtk_label_set_text(bw->statusbar, buf);
            g_timeout_add(1500, [](gpointer p)->gboolean{ gtk_label_set_text(GTK_LABEL(p),""); return FALSE; }, bw->statusbar);
            const char* uri = webkit_web_view_get_uri(currentWv(bw));
            if (uri) { GUri* gu = g_uri_parse(uri, G_URI_FLAGS_NONE, nullptr); if (gu) { std::string h = g_uri_get_host(gu) ? g_uri_get_host(gu) : ""; g_uri_unref(gu); if (!h.empty()) { bw->app->zoomPerDomain[h] = z; saveSettings(bw->app); } } }
            return TRUE;
        }
        if (keyval == GDK_KEY_0) {
            webkit_web_view_set_zoom_level(currentWv(bw), 1.0);
            gtk_label_set_text(bw->statusbar, "Zoom: 100%");
            g_timeout_add(1500, [](gpointer p)->gboolean{ gtk_label_set_text(GTK_LABEL(p),""); return FALSE; }, bw->statusbar);
            // Borrar zoom guardado para este dominio
            const char* uri = webkit_web_view_get_uri(currentWv(bw));
            if (uri) { GUri* gu = g_uri_parse(uri, G_URI_FLAGS_NONE, nullptr); if (gu) { std::string h = g_uri_get_host(gu) ? g_uri_get_host(gu) : ""; g_uri_unref(gu); if (!h.empty()) { bw->app->zoomPerDomain.erase(h); saveSettings(bw->app); } } }
            return TRUE;
        }
    }
    if (ctrlHeld && altHeld) {
        if (keyval == GDK_KEY_t || keyval == GDK_KEY_Return) { toggleTerminal(bw); return TRUE; }
        if (keyval == GDK_KEY_j) { toggleJsConsole(bw); return TRUE; }
        if (keyval == GDK_KEY_d) { toggleDlPanel(bw); return TRUE; }
    }
    if (!ctrlHeld && !altHeld) {
        if (keyval == GDK_KEY_Escape) {
            if (bw->findbarVisible) { closeFindbar(bw); return TRUE; }
            if (bw->inspectorMode)  { closeInspector(bw); return TRUE; }
            // Salir de pantalla completa con Escape
            if (gtk_window_is_fullscreen(GTK_WINDOW(bw->window))) {
                gtk_window_unfullscreen(GTK_WINDOW(bw->window));
                return TRUE;
            }
        }
        if (keyval == GDK_KEY_F11) {
            if (gtk_window_is_fullscreen(GTK_WINDOW(bw->window)))
                gtk_window_unfullscreen(GTK_WINDOW(bw->window));
            else
                gtk_window_fullscreen(GTK_WINDOW(bw->window));
            return TRUE;
        }
    }
    if (altHeld && !ctrlHeld) {
        if (keyval == GDK_KEY_Left  && webkit_web_view_can_go_back(currentWv(bw)))    { webkit_web_view_go_back(currentWv(bw));    return TRUE; }
        if (keyval == GDK_KEY_Right && webkit_web_view_can_go_forward(currentWv(bw))) { webkit_web_view_go_forward(currentWv(bw)); return TRUE; }
        if (keyval == GDK_KEY_Home) { webkit_web_view_load_uri(currentWv(bw), bw->app->homeUri.c_str()); return TRUE; }
    }
    return FALSE;
}

static void toggleFindbar(BrowserWindow* bw) {
    if (bw->findbarVisible) closeFindbar(bw);
    else { gtk_widget_set_visible(GTK_WIDGET(bw->findbarBox), TRUE); bw->findbarVisible = true; gtk_widget_grab_focus(GTK_WIDGET(bw->findEntry)); }
}

static void toggleTerminal(BrowserWindow* bw) {
    if (bw->inspectorMode) {
        gtk_label_set_text(bw->statusbar, "Cierra el inspector primero (Esc)");
        g_timeout_add(2000, [](gpointer p) -> gboolean { gtk_label_set_text(GTK_LABEL(p), ""); return FALSE; }, bw->statusbar);
        return;
    }
    if (bw->terminalVisible) {
        gtk_box_remove(bw->contentArea, GTK_WIDGET(bw->termScroll));
        bw->terminalVisible = false;
    } else {
        gtk_box_append(bw->contentArea, GTK_WIDGET(bw->termScroll));
        bw->terminalVisible = true;
        gtk_widget_grab_focus(GTK_WIDGET(bw->terminalTv));
    }
}

static void toggleInspector(BrowserWindow* bw) {
    if (bw->inspectorMode) closeInspector(bw);
    else openInspector(bw);
}

// ─── Consola JavaScript ────────────────────────────────────────────────────

// Imprime en la consola JS
static void jsPrint(BrowserWindow* bw, const std::string& text) {
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(bw->jsBuf, &end);
    gtk_text_buffer_insert(bw->jsBuf, &end, (text + "\n").c_str(), -1);
    GtkTextIter newEnd;
    gtk_text_buffer_get_end_iter(bw->jsBuf, &newEnd);
    gtk_text_view_scroll_to_iter(bw->jsTv, &newEnd, 0.0, TRUE, 0.0, 1.0);
}

static void jsPrompt(BrowserWindow* bw) {
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(bw->jsBuf, &end);
    gtk_text_buffer_insert(bw->jsBuf, &end, "js> ", -1);
    gtk_text_buffer_get_end_iter(bw->jsBuf, &end);
    if (bw->jsPromptMark)
        gtk_text_buffer_move_mark(bw->jsBuf, bw->jsPromptMark, &end);
    else
        bw->jsPromptMark = gtk_text_buffer_create_mark(bw->jsBuf, "jsprompt", &end, TRUE);
    gtk_text_view_scroll_to_iter(bw->jsTv, &end, 0.0, TRUE, 0.0, 1.0);
}

static void runJsCommand(BrowserWindow* bw, const std::string& code) {
    struct JsCtx { BrowserWindow* bw; std::string code; };
    auto* ctx = new JsCtx{bw, code};
    webkit_web_view_evaluate_javascript(currentWv(bw), code.c_str(), -1,
        nullptr, nullptr, nullptr,
        [](GObject* src, GAsyncResult* res, gpointer p) {
            auto* ctx2 = static_cast<JsCtx*>(p);
            GError* err = nullptr;
            JSCValue* val = webkit_web_view_evaluate_javascript_finish(
                WEBKIT_WEB_VIEW(src), res, &err);
            if (val) {
                char* str = jsc_value_to_string(val);
                jsPrint(ctx2->bw, std::string("<- ") + (str ? str : "undefined"));
                g_free(str);
                g_object_unref(val);
            } else {
                std::string msg = err ? std::string("[!] ") + err->message : "[!] Error desconocido";
                jsPrint(ctx2->bw, msg);
                if (err) g_error_free(err);
            }
            jsPrompt(ctx2->bw);
            delete ctx2;
        }, ctx);
}

static gboolean onJsConsoleKey(GtkEventControllerKey*, guint keyval,
                                guint, GdkModifierType state, gpointer data) {
    auto* bw = static_cast<BrowserWindow*>(data);
    if (keyval == GDK_KEY_Return || keyval == GDK_KEY_KP_Enter) {
        GtkTextIter start, end;
        gtk_text_buffer_get_start_iter(bw->jsBuf, &start);
        gtk_text_buffer_get_end_iter(bw->jsBuf, &end);
        gchar* full = gtk_text_buffer_get_text(bw->jsBuf, &start, &end, FALSE);
        std::string text(full); g_free(full);
        while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) text.pop_back();
        size_t nl = text.rfind('\n');
        std::string last = nl != std::string::npos ? text.substr(nl + 1) : text;
        while (!last.empty() && isspace(last.front())) last.erase(last.begin());
        if (startsWith(last, "js> ")) {
            std::string code = last.substr(4);
            while (!code.empty() && isspace(code.front())) code.erase(code.begin());
            while (!code.empty() && isspace(code.back())) code.pop_back();
            if (!code.empty()) {
                if (bw->jsHistory.empty() || bw->jsHistory.back() != code)
                    bw->jsHistory.push_back(code);
                if (bw->jsHistory.size() > 200) bw->jsHistory.erase(bw->jsHistory.begin());
                bw->jsHistoryIdx = -1;
                jsPrint(bw, "");
                runJsCommand(bw, code);
                return TRUE;
            }
        }
        bw->jsHistoryIdx = -1;
        jsPrint(bw, ""); jsPrompt(bw);
        return TRUE;
    }
    bool ctrl = !!(state & GDK_CONTROL_MASK);
    if (ctrl && (keyval == GDK_KEY_l || keyval == GDK_KEY_L)) {
        gtk_text_buffer_set_text(bw->jsBuf, "", -1);
        jsPrompt(bw);
        return TRUE;
    }
    // Historial con flechas
    if ((keyval == GDK_KEY_Up || keyval == GDK_KEY_KP_Up) && !bw->jsHistory.empty()) {
        int newIdx = (bw->jsHistoryIdx < 0)
            ? (int)bw->jsHistory.size() - 1
            : std::max(0, bw->jsHistoryIdx - 1);
        bw->jsHistoryIdx = newIdx;
        if (bw->jsPromptMark) {
            GtkTextIter promptEnd, bufEnd;
            gtk_text_buffer_get_iter_at_mark(bw->jsBuf, &promptEnd, bw->jsPromptMark);
            gtk_text_buffer_get_end_iter(bw->jsBuf, &bufEnd);
            gtk_text_buffer_delete(bw->jsBuf, &promptEnd, &bufEnd);
            GtkTextIter ins; gtk_text_buffer_get_end_iter(bw->jsBuf, &ins);
            gtk_text_buffer_insert(bw->jsBuf, &ins, bw->jsHistory[newIdx].c_str(), -1);
            gtk_text_buffer_get_end_iter(bw->jsBuf, &ins);
            gtk_text_buffer_place_cursor(bw->jsBuf, &ins);
            gtk_text_view_scroll_to_iter(bw->jsTv, &ins, 0.0, TRUE, 0.0, 1.0);
        }
        return TRUE;
    }
    if ((keyval == GDK_KEY_Down || keyval == GDK_KEY_KP_Down) && bw->jsHistoryIdx >= 0) {
        if (bw->jsPromptMark) {
            GtkTextIter promptEnd, bufEnd;
            gtk_text_buffer_get_iter_at_mark(bw->jsBuf, &promptEnd, bw->jsPromptMark);
            gtk_text_buffer_get_end_iter(bw->jsBuf, &bufEnd);
            gtk_text_buffer_delete(bw->jsBuf, &promptEnd, &bufEnd);
            int newIdx = bw->jsHistoryIdx + 1;
            if (newIdx < (int)bw->jsHistory.size()) {
                bw->jsHistoryIdx = newIdx;
                GtkTextIter ins; gtk_text_buffer_get_end_iter(bw->jsBuf, &ins);
                gtk_text_buffer_insert(bw->jsBuf, &ins, bw->jsHistory[newIdx].c_str(), -1);
            } else { bw->jsHistoryIdx = -1; }
            GtkTextIter ins; gtk_text_buffer_get_end_iter(bw->jsBuf, &ins);
            gtk_text_buffer_place_cursor(bw->jsBuf, &ins);
            gtk_text_view_scroll_to_iter(bw->jsTv, &ins, 0.0, TRUE, 0.0, 1.0);
        }
        return TRUE;
    }
    // Proteger prompt
    static const guint pkeys[] = { GDK_KEY_BackSpace, GDK_KEY_Delete, GDK_KEY_Left,
                                    GDK_KEY_Home, GDK_KEY_KP_Left, GDK_KEY_KP_Home, 0 };
    for (int i = 0; pkeys[i]; i++) {
        if (keyval == pkeys[i] && bw->jsPromptMark) {
            GtkTextMark* im = gtk_text_buffer_get_insert(bw->jsBuf);
            GtkTextIter cursor, limit;
            gtk_text_buffer_get_iter_at_mark(bw->jsBuf, &cursor, im);
            gtk_text_buffer_get_iter_at_mark(bw->jsBuf, &limit, bw->jsPromptMark);
            if (gtk_text_iter_compare(&cursor, &limit) <= 0) return TRUE;
        }
    }
    return FALSE;
}

static void toggleJsConsole(BrowserWindow* bw) {
    if (bw->jsConsoleVisible) {
        gtk_box_remove(bw->contentArea, bw->jsPanel);
        bw->jsConsoleVisible = false;
    } else {
        gtk_box_append(bw->contentArea, bw->jsPanel);
        bw->jsConsoleVisible = true;
        gtk_widget_grab_focus(GTK_WIDGET(bw->jsTv));
    }
}

// Cuando el usuario hace clic en zona protegida del terminal, redirigir el
// cursor al final del buffer (zona del prompt). Declarado como función estática
// nombrada para no pasar lambdas con comas a G_CALLBACK() (el preprocesador
// las confundiría con separadores de argumentos del macro).
static void onTerminalClick(GtkGestureClick*, gint, gdouble, gdouble, gpointer p) {
    auto* bw = static_cast<BrowserWindow*>(p);
    if (!bw->promptEndMark) return;
    GtkTextMark* im = gtk_text_buffer_get_insert(bw->terminalBuf);
    GtkTextIter cursor, limit;
    gtk_text_buffer_get_iter_at_mark(bw->terminalBuf, &cursor, im);
    gtk_text_buffer_get_iter_at_mark(bw->terminalBuf, &limit,  bw->promptEndMark);
    if (gtk_text_iter_compare(&cursor, &limit) < 0) {
        GtkTextIter end;
        gtk_text_buffer_get_end_iter(bw->terminalBuf, &end);
        gtk_text_buffer_place_cursor(bw->terminalBuf, &end);
    }
}

// ─── Construcción de la ventana ─────────────────────────────────────────────

static BrowserWindow* buildWindow(GtkApplication* gapp, AppData* app) {
    auto* bw = new BrowserWindow();
    bw->app = app;
    g_bw = bw;

    bw->window = GTK_APPLICATION_WINDOW(gtk_application_window_new(gapp));
    gtk_window_set_title(GTK_WINDOW(bw->window), "I4 Froez");
    gtk_window_set_default_size(GTK_WINDOW(bw->window), 1280, 800);

    GtkBox* root = GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL, 0));

    // Barra de pestañas
    bw->tabbarBox = GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 2));
    gtk_widget_add_css_class(GTK_WIDGET(bw->tabbarBox), "tabbar");

    GtkButton* newTabBtn = GTK_BUTTON(gtk_button_new_with_label("+"));
    gtk_widget_add_css_class(GTK_WIDGET(newTabBtn), "new-tab-btn");
    gtk_widget_set_tooltip_text(GTK_WIDGET(newTabBtn), "Nueva pestaña");
    g_signal_connect(newTabBtn, "clicked", G_CALLBACK(+[](GtkButton*, gpointer p) { openTab(static_cast<BrowserWindow*>(p)); }), bw);

    GtkScrolledWindow* tabbarScroll = GTK_SCROLLED_WINDOW(gtk_scrolled_window_new());
    gtk_scrolled_window_set_policy(tabbarScroll, GTK_POLICY_AUTOMATIC, GTK_POLICY_NEVER);
    gtk_widget_set_hexpand(GTK_WIDGET(tabbarScroll), TRUE);
    gtk_scrolled_window_set_child(tabbarScroll, GTK_WIDGET(bw->tabbarBox));
    gtk_scrolled_window_set_min_content_height(tabbarScroll, 38);

    GtkBox* tabbarRow = GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0));
    gtk_widget_add_css_class(GTK_WIDGET(tabbarRow), "tabbar");
    gtk_box_append(tabbarRow, GTK_WIDGET(tabbarScroll));
    gtk_box_append(tabbarRow, GTK_WIDGET(newTabBtn));

    // Barra de navegación
    bw->backBtn    = makeNavBtn("←", "Atrás (Alt+Izq)",    G_CALLBACK(+[](GtkButton*, gpointer p) { auto* b = static_cast<BrowserWindow*>(p); if (webkit_web_view_can_go_back(currentWv(b))) webkit_web_view_go_back(currentWv(b)); }), bw);
    bw->forwardBtn = makeNavBtn("→", "Adelante (Alt+Der)",  G_CALLBACK(+[](GtkButton*, gpointer p) { auto* b = static_cast<BrowserWindow*>(p); if (webkit_web_view_can_go_forward(currentWv(b))) webkit_web_view_go_forward(currentWv(b)); }), bw);
    bw->reloadBtn  = makeNavBtn("↺", "Recargar (Ctrl+R)",   G_CALLBACK(+[](GtkButton*, gpointer p) { auto* b = static_cast<BrowserWindow*>(p); if (webkit_web_view_is_loading(currentWv(b))) webkit_web_view_stop_loading(currentWv(b)); else webkit_web_view_reload(currentWv(b)); }), bw);
    bw->homeBtn    = makeNavBtn("⌂", "Ir al inicio (Alt+Home)", G_CALLBACK(+[](GtkButton*, gpointer p) { auto* b = static_cast<BrowserWindow*>(p); webkit_web_view_load_uri(currentWv(b), b->app->homeUri.c_str()); }), bw);

    bw->bookmarkStar = makeNavBtn("◆", "Guardar/quitar marcador", G_CALLBACK(+[](GtkButton*, gpointer p) {
        auto* bw2 = static_cast<BrowserWindow*>(p);
        const char* uri = webkit_web_view_get_uri(currentWv(bw2));
        if (!uri || std::string(uri) == "about:blank") return;
        const char* t = webkit_web_view_get_title(currentWv(bw2));
        if (bw2->app->isBookmarked(uri)) {
            bw2->app->removeBookmark(uri); gtk_button_set_label(bw2->bookmarkStar, "◇");
            gtk_label_set_text(bw2->statusbar, "Marcador eliminado");
        } else {
            bw2->app->addBookmark(uri, t ? t : uri); gtk_button_set_label(bw2->bookmarkStar, "◆");
            gtk_label_set_text(bw2->statusbar, "Marcador guardado");
        }
        g_timeout_add(2000, [](gpointer q) -> gboolean { gtk_label_set_text(GTK_LABEL(q), ""); return FALSE; }, bw2->statusbar);
        // Refrescar sidebar si está mostrando marcadores
        if (bw2->sidebarMode == "bookmarks") showSidebar(bw2, "bookmarks");
    }), bw);

    bw->urlEntry = GTK_ENTRY(gtk_entry_new());
    gtk_widget_set_hexpand(GTK_WIDGET(bw->urlEntry), TRUE);
    gtk_widget_add_css_class(GTK_WIDGET(bw->urlEntry), "url-entry");
    gtk_entry_set_placeholder_text(bw->urlEntry, "Ingresa una URL o busca en DuckDuckGo...");
    g_signal_connect(bw->urlEntry, "activate", G_CALLBACK(+[](GtkEntry* e, gpointer p) {
        auto* bw2 = static_cast<BrowserWindow*>(p);
        const char* txt = gtk_editable_get_text(GTK_EDITABLE(e));
        if (txt && txt[0]) webkit_web_view_load_uri(currentWv(bw2), resolveInput(bw2, txt).c_str());
    }), bw);

    bw->badge = GTK_LABEL(gtk_label_new(""));
    gtk_widget_add_css_class(GTK_WIDGET(bw->badge), "badge-normal");
    gtk_widget_set_tooltip_text(GTK_WIDGET(bw->badge), "Modo de red actual");
    gtk_widget_set_visible(GTK_WIDGET(bw->badge), FALSE);

    bw->secBadge = GTK_LABEL(gtk_label_new(""));
    gtk_widget_set_tooltip_text(GTK_WIDGET(bw->secBadge), "Estado de seguridad");
    gtk_widget_set_visible(GTK_WIDGET(bw->secBadge), FALSE);

    // ── Menú sandwich ─────────────────────────────────────────────────────
    bw->menuBtn = GTK_BUTTON(gtk_button_new_with_label("☰"));
    gtk_widget_add_css_class(GTK_WIDGET(bw->menuBtn), "nav-button");
    gtk_widget_set_tooltip_text(GTK_WIDGET(bw->menuBtn), "Menú");

    // Popover con botones del menú
    GtkWidget* popover = gtk_popover_new();
    bw->menuPopover = popover;
    gtk_widget_set_parent(popover, GTK_WIDGET(bw->menuBtn));
    gtk_popover_set_has_arrow(GTK_POPOVER(popover), TRUE);

    GtkBox* menuBox = GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL, 2));
    gtk_widget_set_margin_top(GTK_WIDGET(menuBox), 4);
    gtk_widget_set_margin_bottom(GTK_WIDGET(menuBox), 4);
    gtk_widget_set_margin_start(GTK_WIDGET(menuBox), 4);
    gtk_widget_set_margin_end(GTK_WIDGET(menuBox), 4);

    auto addMenuItem = [&](const char* label, const char* tooltip, auto callback) {
        GtkButton* btn = GTK_BUTTON(gtk_button_new_with_label(label));
        gtk_widget_add_css_class(GTK_WIDGET(btn), "sidebar-item");
        gtk_widget_set_tooltip_text(GTK_WIDGET(btn), tooltip);
        g_signal_connect(btn, "clicked", G_CALLBACK(+callback), bw);
        gtk_box_append(menuBox, GTK_WIDGET(btn));
    };

    addMenuItem("☐  Marcadores",     "Mostrar marcadores",
        [](GtkButton*, gpointer p){ auto* b=static_cast<BrowserWindow*>(p); gtk_popover_popdown(GTK_POPOVER(b->menuPopover)); toggleSidebar(b,"bookmarks"); });
    addMenuItem("⧖  Historial",       "Mostrar historial",
        [](GtkButton*, gpointer p){ auto* b=static_cast<BrowserWindow*>(p); gtk_popover_popdown(GTK_POPOVER(b->menuPopover)); toggleSidebar(b,"history"); });
    addMenuItem("↓  Descargas",       "Panel de descargas (Ctrl+Alt+D)",
        [](GtkButton*, gpointer p){ auto* b=static_cast<BrowserWindow*>(p); gtk_popover_popdown(GTK_POPOVER(b->menuPopover)); toggleDlPanel(b); });
    addMenuItem("⌕  Buscar en página","Buscar en página (Ctrl+F)",
        [](GtkButton*, gpointer p){ auto* b=static_cast<BrowserWindow*>(p); gtk_popover_popdown(GTK_POPOVER(b->menuPopover)); toggleFindbar(b); });
    addMenuItem("</> Inspector HTML", "Inspector HTML",
        [](GtkButton*, gpointer p){ auto* b=static_cast<BrowserWindow*>(p); gtk_popover_popdown(GTK_POPOVER(b->menuPopover)); toggleInspector(b); });
    addMenuItem("JS  Consola JS",     "Consola JavaScript (Ctrl+Alt+J)",
        [](GtkButton*, gpointer p){ auto* b=static_cast<BrowserWindow*>(p); gtk_popover_popdown(GTK_POPOVER(b->menuPopover)); toggleJsConsole(b); });
    addMenuItem("PE  Perú",           "República del Perú",
        [](GtkButton*, gpointer p){ auto* b=static_cast<BrowserWindow*>(p); gtk_popover_popdown(GTK_POPOVER(b->menuPopover)); webkit_web_view_load_uri(currentWv(b), "froez://peru"); });

    // Separador
    GtkWidget* sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_append(menuBox, sep);

    addMenuItem("雨  HTTPS-Only",     "Activar/desactivar HTTPS-Only",
        [](GtkButton*, gpointer p){
            auto* b=static_cast<BrowserWindow*>(p);
            gtk_popover_popdown(GTK_POPOVER(b->menuPopover));
            b->app->httpsOnly = !b->app->httpsOnly;
            saveSettings(b->app);
            gtk_label_set_text(b->statusbar, b->app->httpsOnly ? "HTTPS-Only: activado" : "HTTPS-Only: desactivado");
            g_timeout_add(2500, [](gpointer q)->gboolean{ gtk_label_set_text(GTK_LABEL(q),""); return FALSE; }, b->statusbar);
        });
    addMenuItem("⊘  Bloquear JS",    "Activar/desactivar JavaScript",
        [](GtkButton*, gpointer p){
            auto* b=static_cast<BrowserWindow*>(p);
            gtk_popover_popdown(GTK_POPOVER(b->menuPopover));
            b->app->jsBlocked = !b->app->jsBlocked;
            saveSettings(b->app);
            // Aplicar a la pestaña actual
            WebKitSettings* s = webkit_web_view_get_settings(currentWv(b));
            webkit_settings_set_enable_javascript(s, !b->app->jsBlocked);
            gtk_label_set_text(b->statusbar, b->app->jsBlocked ? "JavaScript: bloqueado" : "JavaScript: habilitado");
            g_timeout_add(2500, [](gpointer q)->gboolean{ gtk_label_set_text(GTK_LABEL(q),""); return FALSE; }, b->statusbar);
        });
    addMenuItem("⚒  Ajustes",        "Abrir ajustes",
        [](GtkButton*, gpointer p){ auto* b=static_cast<BrowserWindow*>(p); gtk_popover_popdown(GTK_POPOVER(b->menuPopover)); webkit_web_view_load_uri(currentWv(b), "froez://settings"); });
    addMenuItem("⚙  Ajustes","Abrir ajustes",
        [](GtkButton*, gpointer p){ auto* b=static_cast<BrowserWindow*>(p); gtk_popover_popdown(GTK_POPOVER(b->menuPopover)); webkit_web_view_load_uri(currentWv(b), "froez://settings"); });

    gtk_popover_set_child(GTK_POPOVER(popover), GTK_WIDGET(menuBox));

    g_signal_connect(bw->menuBtn, "clicked", G_CALLBACK(+[](GtkButton*, gpointer p) {
        auto* bw2 = static_cast<BrowserWindow*>(p);
        gtk_popover_popup(GTK_POPOVER(bw2->menuPopover));
    }), bw);

    // ── Barra de navegación ───────────────────────────────────────────────
    GtkButton* termBtn = makeNavBtn(">_", "Terminal (Ctrl+Alt+T)",
        G_CALLBACK(+[](GtkButton*, gpointer p) { toggleTerminal(static_cast<BrowserWindow*>(p)); }), bw);

    GtkBox* navBox = GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4));
    gtk_widget_add_css_class(GTK_WIDGET(navBox), "toolbar");
    for (GtkWidget* w : {GTK_WIDGET(bw->backBtn), GTK_WIDGET(bw->forwardBtn), GTK_WIDGET(bw->reloadBtn),
                          GTK_WIDGET(bw->homeBtn),
                          GTK_WIDGET(bw->secBadge), GTK_WIDGET(bw->urlEntry), GTK_WIDGET(bw->bookmarkStar),
                          GTK_WIDGET(bw->badge),
                          GTK_WIDGET(termBtn), GTK_WIDGET(bw->menuBtn)})
        gtk_box_append(navBox, w);

    // Área de contenido
    bw->contentArea = GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0));
    gtk_widget_set_vexpand(GTK_WIDGET(bw->contentArea), TRUE);
    gtk_widget_set_hexpand(GTK_WIDGET(bw->contentArea), TRUE);

    bw->tabStack = GTK_STACK(gtk_stack_new());
    gtk_widget_set_vexpand(GTK_WIDGET(bw->tabStack), TRUE);
    gtk_widget_set_hexpand(GTK_WIDGET(bw->tabStack), TRUE);
    gtk_box_append(bw->contentArea, GTK_WIDGET(bw->tabStack));

    // Terminal — se necesita g_object_ref para sobrevivir a gtk_box_remove
    bw->terminalBuf = gtk_text_buffer_new(nullptr);
    bw->terminalTv  = GTK_TEXT_VIEW(gtk_text_view_new_with_buffer(bw->terminalBuf));
    gtk_text_view_set_editable(bw->terminalTv, TRUE);
    gtk_text_view_set_cursor_visible(bw->terminalTv, TRUE);
    gtk_text_view_set_wrap_mode(bw->terminalTv, GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_monospace(bw->terminalTv, TRUE);
    gtk_widget_add_css_class(GTK_WIDGET(bw->terminalTv), "terminal");
    gtk_widget_set_size_request(GTK_WIDGET(bw->terminalTv), 340, 200);

    // Tag para bloquear la edición del historial.
    // El TextView sigue siendo editable=TRUE; el tag sobreescribe eso
    // en la zona del historial. La zona del prompt (sin tag) queda libre.
    bw->termReadonlyTag = gtk_text_buffer_create_tag(
        bw->terminalBuf, "term-readonly", "editable", FALSE, nullptr);

    bw->termScroll = GTK_SCROLLED_WINDOW(gtk_scrolled_window_new());
    gtk_widget_set_vexpand(GTK_WIDGET(bw->termScroll), TRUE);
    gtk_scrolled_window_set_min_content_width(bw->termScroll, 340);
    gtk_scrolled_window_set_min_content_height(bw->termScroll, 200);
    gtk_scrolled_window_set_child(bw->termScroll, GTK_WIDGET(bw->terminalTv));
    // Mantener vivo cuando se remueve del box
    g_object_ref(bw->termScroll);

    GtkEventControllerKey* termKey = GTK_EVENT_CONTROLLER_KEY(gtk_event_controller_key_new());
    g_signal_connect(termKey, "key-pressed", G_CALLBACK(onTerminalKey), bw);
    gtk_widget_add_controller(GTK_WIDGET(bw->terminalTv), GTK_EVENT_CONTROLLER(termKey));

    // Redirigir clic fuera del prompt al final del buffer
    GtkGestureClick* termClick = GTK_GESTURE_CLICK(gtk_gesture_click_new());
    gtk_gesture_single_set_button(GTK_GESTURE_SINGLE(termClick), 1);
    g_signal_connect(termClick, "released", G_CALLBACK(onTerminalClick), bw);
    gtk_widget_add_controller(GTK_WIDGET(bw->terminalTv), GTK_EVENT_CONTROLLER(termClick));

    // Inspector
    bw->inspectorBuf = gtk_text_buffer_new(nullptr);
    bw->inspectorTv  = GTK_TEXT_VIEW(gtk_text_view_new_with_buffer(bw->inspectorBuf));
    gtk_text_view_set_editable(bw->inspectorTv, TRUE);
    gtk_text_view_set_cursor_visible(bw->inspectorTv, TRUE);
    gtk_text_view_set_wrap_mode(bw->inspectorTv, GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_monospace(bw->inspectorTv, TRUE);
    gtk_widget_add_css_class(GTK_WIDGET(bw->inspectorTv), "inspector-tv");
    gtk_widget_set_size_request(GTK_WIDGET(bw->inspectorTv), 400, 200);

    GtkScrolledWindow* inspScroll = GTK_SCROLLED_WINDOW(gtk_scrolled_window_new());
    gtk_widget_set_vexpand(GTK_WIDGET(inspScroll), TRUE);
    gtk_scrolled_window_set_min_content_width(inspScroll, 400);
    gtk_scrolled_window_set_min_content_height(inspScroll, 200);
    gtk_scrolled_window_set_child(inspScroll, GTK_WIDGET(bw->inspectorTv));

    GtkBox* inspBtnBox = GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4));
    gtk_widget_add_css_class(GTK_WIDGET(inspBtnBox), "toolbar");
    gtk_box_append(inspBtnBox, GTK_WIDGET(makeNavBtn("Cargar HTML", "Obtener HTML", G_CALLBACK(+[](GtkButton*, gpointer p) { inspectorLoad(static_cast<BrowserWindow*>(p)); }), bw)));
    gtk_box_append(inspBtnBox, GTK_WIDGET(makeNavBtn("Aplicar",     "Aplicar HTML", G_CALLBACK(+[](GtkButton*, gpointer p) { inspectorApply(static_cast<BrowserWindow*>(p)); }), bw)));
    gtk_box_append(inspBtnBox, GTK_WIDGET(makeNavBtn("Cerrar",      "Cerrar",       G_CALLBACK(+[](GtkButton*, gpointer p) { closeInspector(static_cast<BrowserWindow*>(p)); }), bw)));

    GtkBox* inspPanel = GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL, 0));
    gtk_box_append(inspPanel, GTK_WIDGET(inspBtnBox));
    gtk_box_append(inspPanel, GTK_WIDGET(inspScroll));
    bw->inspPanel = GTK_WIDGET(inspPanel);
    // Mantener vivo cuando se remueve del box
    g_object_ref(bw->inspPanel);

    GtkEventControllerKey* inspKey = GTK_EVENT_CONTROLLER_KEY(gtk_event_controller_key_new());
    g_signal_connect(inspKey, "key-pressed", G_CALLBACK(onInspectorKey), bw);
    gtk_widget_add_controller(GTK_WIDGET(bw->inspectorTv), GTK_EVENT_CONTROLLER(inspKey));

    // ─── Consola JavaScript ──────────────────────────────────────────────────
    bw->jsBuf = gtk_text_buffer_new(nullptr);
    bw->jsTv  = GTK_TEXT_VIEW(gtk_text_view_new_with_buffer(bw->jsBuf));
    gtk_text_view_set_editable(bw->jsTv, TRUE);
    gtk_text_view_set_cursor_visible(bw->jsTv, TRUE);
    gtk_text_view_set_wrap_mode(bw->jsTv, GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_monospace(bw->jsTv, TRUE);
    gtk_widget_add_css_class(GTK_WIDGET(bw->jsTv), "js-console");
    gtk_widget_set_size_request(GTK_WIDGET(bw->jsTv), 340, 180);

    bw->jsScroll = GTK_SCROLLED_WINDOW(gtk_scrolled_window_new());
    gtk_widget_set_vexpand(GTK_WIDGET(bw->jsScroll), TRUE);
    gtk_scrolled_window_set_min_content_width(bw->jsScroll, 340);
    gtk_scrolled_window_set_min_content_height(bw->jsScroll, 180);
    gtk_scrolled_window_set_child(bw->jsScroll, GTK_WIDGET(bw->jsTv));

    GtkBox* jsBtnBox = GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4));
    gtk_widget_add_css_class(GTK_WIDGET(jsBtnBox), "toolbar");
    GtkLabel* jsLabel = GTK_LABEL(gtk_label_new("  JS Console  "));
    gtk_widget_add_css_class(GTK_WIDGET(jsLabel), "findbar-label");
    gtk_widget_set_hexpand(GTK_WIDGET(jsLabel), TRUE);
    gtk_box_append(jsBtnBox, GTK_WIDGET(jsLabel));
    gtk_box_append(jsBtnBox, GTK_WIDGET(makeNavBtn("Limpiar", "Limpiar consola", G_CALLBACK(+[](GtkButton*, gpointer p) {
        auto* b = static_cast<BrowserWindow*>(p);
        gtk_text_buffer_set_text(b->jsBuf, "", -1);
        jsPrompt(b);
    }), bw)));
    gtk_box_append(jsBtnBox, GTK_WIDGET(makeNavBtn("Cerrar", "Cerrar consola", G_CALLBACK(+[](GtkButton*, gpointer p) {
        toggleJsConsole(static_cast<BrowserWindow*>(p));
    }), bw)));

    GtkBox* jsPanel = GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL, 0));
    gtk_box_append(jsPanel, GTK_WIDGET(jsBtnBox));
    gtk_box_append(jsPanel, GTK_WIDGET(bw->jsScroll));
    bw->jsPanel = GTK_WIDGET(jsPanel);
    g_object_ref(bw->jsPanel);

    GtkEventControllerKey* jsKey = GTK_EVENT_CONTROLLER_KEY(gtk_event_controller_key_new());
    g_signal_connect(jsKey, "key-pressed", G_CALLBACK(onJsConsoleKey), bw);
    gtk_widget_add_controller(GTK_WIDGET(bw->jsTv), GTK_EVENT_CONTROLLER(jsKey));

    // Findbar
    bw->findbarBox = GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6));
    gtk_widget_add_css_class(GTK_WIDGET(bw->findbarBox), "findbar");
    bw->findEntry = GTK_ENTRY(gtk_entry_new());
    gtk_widget_add_css_class(GTK_WIDGET(bw->findEntry), "findbar-entry");
    gtk_entry_set_placeholder_text(bw->findEntry, "Buscar en página...");
    g_signal_connect(bw->findEntry, "activate", G_CALLBACK(+[](GtkEntry*, gpointer p) {
        auto* bw2 = static_cast<BrowserWindow*>(p);
        const char* t = gtk_editable_get_text(GTK_EDITABLE(bw2->findEntry));
        if (t && t[0]) webkit_find_controller_search_next(webkit_web_view_get_find_controller(currentWv(bw2)));
    }), bw);
    g_signal_connect(bw->findEntry, "changed", G_CALLBACK(+[](GtkEntry*, gpointer p) { findChanged(static_cast<BrowserWindow*>(p)); }), bw);
    bw->findLabel = GTK_LABEL(gtk_label_new(""));
    gtk_widget_add_css_class(GTK_WIDGET(bw->findLabel), "findbar-label");
    gtk_box_append(bw->findbarBox, GTK_WIDGET(bw->findEntry));
    gtk_box_append(bw->findbarBox, GTK_WIDGET(makeNavBtn("↑", "Anterior", G_CALLBACK(+[](GtkButton*, gpointer p) { auto* b = static_cast<BrowserWindow*>(p); const char* t = gtk_editable_get_text(GTK_EDITABLE(b->findEntry)); if (t && t[0]) webkit_find_controller_search_previous(webkit_web_view_get_find_controller(currentWv(b))); }), bw)));
    gtk_box_append(bw->findbarBox, GTK_WIDGET(makeNavBtn("↓", "Siguiente", G_CALLBACK(+[](GtkButton*, gpointer p) { auto* b = static_cast<BrowserWindow*>(p); const char* t = gtk_editable_get_text(GTK_EDITABLE(b->findEntry)); if (t && t[0]) webkit_find_controller_search_next(webkit_web_view_get_find_controller(currentWv(b))); }), bw)));
    gtk_box_append(bw->findbarBox, GTK_WIDGET(bw->findLabel));
    gtk_box_append(bw->findbarBox, GTK_WIDGET(makeNavBtn("x", "Cerrar (Esc)", G_CALLBACK(+[](GtkButton*, gpointer p) { closeFindbar(static_cast<BrowserWindow*>(p)); }), bw)));

    // Barra de estado
    bw->statusbar = GTK_LABEL(gtk_label_new(""));
    gtk_widget_add_css_class(GTK_WIDGET(bw->statusbar), "statusbar");
    gtk_label_set_xalign(bw->statusbar, 0.0f);
    gtk_widget_set_hexpand(GTK_WIDGET(bw->statusbar), TRUE);
    gtk_label_set_ellipsize(bw->statusbar, PANGO_ELLIPSIZE_END);

    bw->dlProgress = GTK_PROGRESS_BAR(gtk_progress_bar_new());
    gtk_widget_add_css_class(GTK_WIDGET(bw->dlProgress), "dl-progress");
    gtk_widget_set_visible(GTK_WIDGET(bw->dlProgress), FALSE);
    gtk_widget_set_valign(GTK_WIDGET(bw->dlProgress), GTK_ALIGN_CENTER);
    gtk_widget_set_size_request(GTK_WIDGET(bw->dlProgress), 150, -1);

    GtkBox* statusbarBox = GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8));
    gtk_widget_add_css_class(GTK_WIDGET(statusbarBox), "statusbar");
    gtk_box_append(statusbarBox, GTK_WIDGET(bw->statusbar));
    gtk_box_append(statusbarBox, GTK_WIDGET(bw->dlProgress));

    gtk_box_append(root, GTK_WIDGET(tabbarRow));
    gtk_box_append(root, GTK_WIDGET(navBox));
    gtk_box_append(root, GTK_WIDGET(bw->contentArea));
    gtk_box_append(root, GTK_WIDGET(bw->findbarBox));
    gtk_box_append(root, GTK_WIDGET(statusbarBox));
    gtk_window_set_child(GTK_WINDOW(bw->window), GTK_WIDGET(root));
    gtk_widget_set_visible(GTK_WIDGET(bw->findbarBox), FALSE);

    // Atajos globales
    GtkEventControllerKey* globalKey = GTK_EVENT_CONTROLLER_KEY(gtk_event_controller_key_new());
    g_signal_connect(globalKey, "key-pressed", G_CALLBACK(onGlobalKey), bw);
    gtk_widget_add_controller(GTK_WIDGET(bw->window), GTK_EVENT_CONTROLLER(globalKey));

    termPrint(bw, "I4 Froez v0.8  —  escribe 'help' para ver los comandos \n");
    termPrompt(bw);

    // Inicializar consola JS
    jsPrint(bw, "I4 Froez JS Console  —  Ctrl+L para limpiar \n");
    jsPrompt(bw);

    return bw;
}

// ─── switchProfile — restart limpio al cambiar de perfil ──────────────────
// Destruye la ventana actual, wipe de RAM (solo si salimos de Tor/I2P),
// cambia el perfil global y construye una nueva ventana con el nuevo perfil.

static void switchProfile(GtkApplication* app, BrowserProfile newProfile) {
    // Wipe agresivo solo al salir de Tor o I2P
    bool wipeNeeded = (g_activeProfile == BrowserProfile::TOR ||
                       g_activeProfile == BrowserProfile::I2P);
    if (wipeNeeded) {
        wipeSessionMemory(&g_app);
    } else {
        // Clearnet: solo limpiar la clave maestra
        if (!g_masterKey.empty()) {
            OPENSSL_cleanse(g_masterKey.data(), g_masterKey.size());
            g_masterKey.clear();
        }
    }

    // Cerrar la ventana actual si existe
    if (g_bw && g_bw->window) {
        gtk_window_destroy(GTK_WINDOW(g_bw->window));
        g_bw = nullptr;
    }

    // Cambiar perfil global
    g_activeProfile = newProfile;

    // Crear directorio del nuevo perfil
    g_mkdir_with_parents(profileDir().c_str(), 0700);

    // Inicializar clave del nuevo perfil (pide contraseña)
    initMasterKey(app);

    // Cargar datos del nuevo perfil
    g_app = AppData{};
    g_app.homeUri   = "froez://newtab";
    g_app.history   = loadJson(historyFile(),   json::array());
    g_app.bookmarks = loadJson(bookmarksFile(), json::array());
    loadSettings(&g_app);

    // Construir nueva ventana
    BrowserWindow* bw = buildWindow(app, &g_app);
    g_bw = bw;
    openTab(bw, g_app.homeUri.c_str());

    // Mostrar badge del perfil activo en el título de la ventana
    std::string profName = profileDisplayName(g_activeProfile);
    std::string title = "I4 Froez [" + profName + "]";
    gtk_window_set_title(GTK_WINDOW(bw->window), title.c_str());

    gtk_window_present(GTK_WINDOW(bw->window));
}

// ─── Callbacks de la GtkApplication ────────────────────────────────────────

static void onActivate(GtkApplication* app, gpointer) {
    // 1. Pedir seleccion de perfil al usuario
    g_activeProfile = askProfileSelection(app);

    // 2. Crear directorio del perfil seleccionado
    g_mkdir_with_parents(profileDir().c_str(), 0700);

    // 3. Inicializar clave maestra del perfil
    initMasterKey(app);

    // 4. Registrar esquema froez:// (debe hacerse antes de crear WebViews)
    WebKitWebContext* ctx = webkit_web_context_get_default();
    webkit_web_context_register_uri_scheme(ctx, "froez", froezSchemeHandler, nullptr, nullptr);

    // 5. Cargar CSS global
    GtkCssProvider* provider = gtk_css_provider_new();
    gtk_css_provider_load_from_string(provider, GLOBAL_CSS);
    gtk_style_context_add_provider_for_display(
        gdk_display_get_default(), GTK_STYLE_PROVIDER(provider),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(provider);

    // 6. Inicializar datos del perfil
    g_app.homeUri   = "froez://newtab";
    g_app.history   = loadJson(historyFile(),   json::array());
    g_app.bookmarks = loadJson(bookmarksFile(), json::array());
    loadSettings(&g_app);

    // 7. Construir y mostrar ventana
    BrowserWindow* bw = buildWindow(app, &g_app);
    g_bw = bw;
    openTab(bw, g_app.homeUri.c_str());

    // Mostrar perfil activo en el título
    gtk_window_set_title(GTK_WINDOW(bw->window),
        ("I4 Froez [" + profileDisplayName(g_activeProfile) + "]").c_str());

    gtk_window_present(GTK_WINDOW(bw->window));
}

// ─── Punto de entrada ───────────────────────────────────────────────────────

int main(int argc, char** argv) {
    // Configuración de entorno
    g_setenv("GDK_DEBUG", "portals", FALSE);
    g_setenv("GTK_A11Y", "none", FALSE);

    GtkApplication* app = gtk_application_new(
        "com.freetazapablo.i4froez",
        G_APPLICATION_DEFAULT_FLAGS
    );
    g_signal_connect(app, "activate", G_CALLBACK(onActivate), nullptr);

    // Wipe de RAM al cerrar el proceso si salimos de Tor/I2P
    g_signal_connect(app, "shutdown", G_CALLBACK(+[](GApplication*, gpointer) {
        if (g_activeProfile == BrowserProfile::TOR ||
            g_activeProfile == BrowserProfile::I2P) {
            wipeSessionMemory(&g_app);
        } else {
            if (!g_masterKey.empty()) {
                OPENSSL_cleanse(g_masterKey.data(), g_masterKey.size());
                g_masterKey.clear();
            }
        }
    }), nullptr);

    int status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    return status;
}

// Paquetes necesarios:
// gtk4
// webkitgtk-6.0
// openssl
// nlohmann-json
// glib2
// base-devel
// pkgconf
// tor
// i2pd
// torsocks
