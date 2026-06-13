/*
 * chkrootkit-gui - a friendly GTK3 front-end for chkrootkit
 *
 * Runs chkrootkit and shows the scan live, line by line, with colors:
 *   green  = clean / not infected / nothing found
 *   yellow = warning / vulnerable / suspicious
 *   red    = INFECTED
 *   blue   = section headers ("Checking ...")
 *
 * chkrootkit needs root, so the scan is launched through pkexec unless the
 * program is already running as root.
 *
 * Copyright (c) 2026. Released under the MIT license.
 */

#include <gtk/gtk.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#define CHKROOTKIT_PATH "/usr/sbin/chkrootkit"

typedef struct {
    GtkWidget    *window;
    GtkWidget    *textview;
    GtkTextBuffer *buffer;
    GtkWidget    *scan_btn;
    GtkWidget    *stop_btn;
    GtkWidget    *clear_btn;
    GtkWidget    *filter_check;
    GtkWidget    *spinner;
    GtkWidget    *statusbar;
    guint         status_ctx;

    /* running scan state */
    GPid          pid;
    GIOChannel   *out_chan;
    GIOChannel   *err_chan;
    guint         out_watch;
    guint         err_watch;
    guint         child_watch;
    gboolean      running;

    /* live tallies */
    int infected;
    int warnings;

    /* false-positive filtering state */
    int      rtnetlink_count;   /* harmless network-check errors swallowed */
    gboolean in_susp_block;     /* inside the "suspicious files" dotfile dump */
    int      susp_count;        /* dotfiles swallowed in that block */
} App;

/* ---- helpers ---------------------------------------------------------- */

static gboolean str_icontains(const char *hay, const char *needle)
{
    if (!hay || !needle) return FALSE;
    size_t nlen = strlen(needle);
    for (const char *p = hay; *p; p++) {
        if (g_ascii_strncasecmp(p, needle, nlen) == 0)
            return TRUE;
    }
    return FALSE;
}

/* Decide which color tag a line of chkrootkit output deserves. */
static const char *classify_line(const char *line)
{
    /* Order matters: INFECTED beats everything. */
    if (str_icontains(line, "INFECTED"))
        return "infected";

    /* "not infected" / "nothing found" / "not found" / "clean" -> good */
    if (str_icontains(line, "not infected")  ||
        str_icontains(line, "nothing found") ||
        str_icontains(line, "nothing detected") ||
        str_icontains(line, "not found")     ||
        str_icontains(line, "not vulnerable")||
        str_icontains(line, "nothing deleted") ||
        g_ascii_strncasecmp(line, "not tested", 10) == 0)
        return "ok";

    if (str_icontains(line, "warning")    ||
        str_icontains(line, "vulnerable") ||
        str_icontains(line, "suspicious") ||
        str_icontains(line, "possible")   ||
        str_icontains(line, "tampered"))
        return "warn";

    if (g_str_has_prefix(line, "Checking") ||
        g_str_has_prefix(line, "Searching") ||
        g_str_has_prefix(line, "ROOTDIR"))
        return "header";

    return NULL; /* plain text */
}

static void append_line(App *app, const char *line, const char *forced_tag)
{
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(app->buffer, &end);

    const char *tag = forced_tag ? forced_tag : classify_line(line);

    if (tag) {
        if (strcmp(tag, "infected") == 0) app->infected++;
        else if (strcmp(tag, "warn") == 0) app->warnings++;
        gtk_text_buffer_insert_with_tags_by_name(app->buffer, &end,
                                                 line, -1, tag, NULL);
    } else {
        gtk_text_buffer_insert(app->buffer, &end, line, -1);
    }
    gtk_text_buffer_insert(app->buffer, &end, "\n", -1);

    /* keep the view scrolled to the bottom */
    GtkTextMark *mark = gtk_text_buffer_get_insert(app->buffer);
    gtk_text_view_scroll_mark_onscreen(GTK_TEXT_VIEW(app->textview), mark);
}

static void update_status(App *app)
{
    char msg[256];
    if (app->running)
        g_snprintf(msg, sizeof msg,
                   "Scanning…   infected: %d   warnings: %d",
                   app->infected, app->warnings);
    else if (app->infected > 0)
        g_snprintf(msg, sizeof msg,
                   "Finished — %d INFECTED, %d warning(s). Review the red lines!",
                   app->infected, app->warnings);
    else if (app->warnings > 0)
        g_snprintf(msg, sizeof msg,
                   "Finished — clean of known rootkits, but %d warning(s) to review.",
                   app->warnings);
    else
        g_snprintf(msg, sizeof msg, "Ready.");

    gtk_statusbar_pop(GTK_STATUSBAR(app->statusbar), app->status_ctx);
    gtk_statusbar_push(GTK_STATUSBAR(app->statusbar), app->status_ctx, msg);
}

/* Is this line just a hidden dotfile path (the classic chkrootkit
 * false positive), or a wrapped continuation of one? */
static gboolean looks_like_dotfile_entry(const char *line)
{
    if (line[0] == '/') return TRUE;          /* a path */
    /* continuation lines from wrapped names (e.g. ".NET", "Framework") */
    if (line[0] != '\0' && !isspace((unsigned char)line[0]) &&
        !str_icontains(line, "RTNETLINK") &&
        !g_str_has_prefix(line, "WARNING") &&
        !g_str_has_prefix(line, "Checking") &&
        !g_str_has_prefix(line, "Searching"))
        return TRUE;
    return FALSE;
}

/* Apply the "ignore known false positives" filter, then print.
 * Returns nothing; it decides what (if anything) reaches the view. */
static void handle_output_line(App *app, const char *line, const char *forced)
{
    gboolean filter = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON(app->filter_check));

    if (!filter) {
        append_line(app, line, forced);
        return;
    }

    /* Inside the dotfile dump: swallow paths, fold into one info line. */
    if (app->in_susp_block) {
        if (line[0] == '\0' || !looks_like_dotfile_entry(line)) {
            char buf[160];
            g_snprintf(buf, sizeof buf,
                "  \xE2\x84\xB9 %d hidden dotfile(s) flagged — known false positive, "
                "hidden (untick the box to see them).", app->susp_count);
            append_line(app, buf, "info");
            app->in_susp_block = FALSE;
            /* fall through so the current (non-dotfile) line gets handled */
        } else {
            app->susp_count++;
            return;
        }
    }

    /* Swallow the harmless network-check noise. */
    if (str_icontains(line, "RTNETLINK answers")) {
        app->rtnetlink_count++;
        return;
    }

    /* Start of the suspicious-files dump. */
    if (str_icontains(line, "suspicious files and directories were found")) {
        app->in_susp_block = TRUE;
        app->susp_count = 0;
        return;
    }

    append_line(app, line, forced);
}

/* ---- scan lifecycle --------------------------------------------------- */

static void set_running_ui(App *app, gboolean running)
{
    app->running = running;
    gtk_widget_set_sensitive(app->scan_btn, !running);
    gtk_widget_set_sensitive(app->stop_btn, running);
    if (running) {
        gtk_spinner_start(GTK_SPINNER(app->spinner));
        gtk_widget_show(app->spinner);
    } else {
        gtk_spinner_stop(GTK_SPINNER(app->spinner));
        gtk_widget_hide(app->spinner);
    }
    update_status(app);
}

static gboolean on_io(GIOChannel *src, GIOCondition cond, gpointer data)
{
    App *app = data;

    /* Forget the watch id when the source is about to be auto-removed,
     * so cleanup_scan() doesn't try to remove it a second time. */
    guint *watch_id = (src == app->err_chan) ? &app->err_watch
                                             : &app->out_watch;

    if (cond & (G_IO_HUP | G_IO_ERR)) {
        *watch_id = 0;
        return FALSE; /* remove watch */
    }

    char *line = NULL;
    gsize len = 0;
    GError *err = NULL;
    GIOStatus st = g_io_channel_read_line(src, &line, &len, NULL, &err);

    if (st == G_IO_STATUS_NORMAL && line) {
        /* strip trailing newline */
        g_strchomp(line);
        const char *forced = (src == app->err_chan) ? "warn" : NULL;
        handle_output_line(app, line, forced);
        update_status(app);
        g_free(line);
        return TRUE;
    }
    if (line) g_free(line);
    if (err) g_error_free(err);
    if (st == G_IO_STATUS_AGAIN)
        return TRUE;
    *watch_id = 0;
    return FALSE; /* EOF -> remove */
}

static void cleanup_scan(App *app)
{
    if (app->out_watch) { g_source_remove(app->out_watch); app->out_watch = 0; }
    if (app->err_watch) { g_source_remove(app->err_watch); app->err_watch = 0; }
    if (app->out_chan)  { g_io_channel_unref(app->out_chan); app->out_chan = NULL; }
    if (app->err_chan)  { g_io_channel_unref(app->err_chan); app->err_chan = NULL; }
    if (app->pid)       { g_spawn_close_pid(app->pid); app->pid = 0; }
}

static void on_child_exit(GPid pid, gint status, gpointer data)
{
    (void)pid; (void)status;
    App *app = data;
    app->child_watch = 0;

    /* flush a still-open dotfile block (output ended without a blank line) */
    if (app->in_susp_block) {
        char buf[160];
        g_snprintf(buf, sizeof buf,
            "  \xE2\x84\xB9 %d hidden dotfile(s) flagged — known false positive, hidden.",
            app->susp_count);
        append_line(app, buf, "info");
        app->in_susp_block = FALSE;
    }
    if (app->rtnetlink_count > 0) {
        char buf[160];
        g_snprintf(buf, sizeof buf,
            "  \xE2\x84\xB9 %d harmless network-check error(s) hidden (RTNETLINK).",
            app->rtnetlink_count);
        append_line(app, buf, "info");
    }

    GtkTextIter end;
    gtk_text_buffer_get_end_iter(app->buffer, &end);
    gtk_text_buffer_insert(app->buffer, &end, "\n", -1);

    char summary[128];
    if (app->infected > 0)
        g_snprintf(summary, sizeof summary,
                   "=== Scan complete: %d INFECTED, %d warning(s) ===",
                   app->infected, app->warnings);
    else
        g_snprintf(summary, sizeof summary,
                   "=== Scan complete: no rootkits found, %d warning(s) ===",
                   app->warnings);
    append_line(app, summary, app->infected ? "infected"
                              : (app->warnings ? "warn" : "ok"));

    cleanup_scan(app);
    set_running_ui(app, FALSE);
}

static void start_scan(App *app)
{
    if (app->running) return;

    app->infected = 0;
    app->warnings = 0;
    app->rtnetlink_count = 0;
    app->in_susp_block = FALSE;
    app->susp_count = 0;

    /* Build argv. Run through pkexec when we are not root. */
    GPtrArray *argv = g_ptr_array_new();
    gboolean need_priv = (geteuid() != 0);
    if (need_priv)
        g_ptr_array_add(argv, "pkexec");
    g_ptr_array_add(argv, CHKROOTKIT_PATH);
    g_ptr_array_add(argv, "-q");          /* quiet: only show problems + checks */
    g_ptr_array_add(argv, NULL);

    gint out_fd = -1, err_fd = -1;
    GError *err = NULL;
    gboolean ok = g_spawn_async_with_pipes(
        NULL, (char **)argv->pdata, NULL,
        G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_SEARCH_PATH,
        NULL, NULL, &app->pid,
        NULL, &out_fd, &err_fd, &err);
    g_ptr_array_free(argv, TRUE);

    if (!ok) {
        char buf[512];
        g_snprintf(buf, sizeof buf, "Failed to launch chkrootkit: %s",
                   err ? err->message : "unknown error");
        append_line(app, buf, "infected");
        if (err) g_error_free(err);
        return;
    }

    char hdr[256];
    g_snprintf(hdr, sizeof hdr, "Starting chkrootkit%s …",
               need_priv ? " (asking for administrator password)" : "");
    append_line(app, hdr, "header");

    app->out_chan = g_io_channel_unix_new(out_fd);
    app->err_chan = g_io_channel_unix_new(err_fd);
    g_io_channel_set_flags(app->out_chan, G_IO_FLAG_NONBLOCK, NULL);
    g_io_channel_set_flags(app->err_chan, G_IO_FLAG_NONBLOCK, NULL);
    g_io_channel_set_close_on_unref(app->out_chan, TRUE);
    g_io_channel_set_close_on_unref(app->err_chan, TRUE);

    app->out_watch = g_io_add_watch(app->out_chan,
                                    G_IO_IN | G_IO_HUP | G_IO_ERR, on_io, app);
    app->err_watch = g_io_add_watch(app->err_chan,
                                    G_IO_IN | G_IO_HUP | G_IO_ERR, on_io, app);
    app->child_watch = g_child_watch_add(app->pid, on_child_exit, app);

    set_running_ui(app, TRUE);
}

static void stop_scan(App *app)
{
    if (!app->running || !app->pid) return;
    kill((pid_t)app->pid, SIGTERM);
    append_line(app, "Scan stopped by user.", "warn");
}

/* ---- callbacks -------------------------------------------------------- */

static void on_scan_clicked(GtkButton *b, gpointer data) { (void)b; start_scan(data); }
static void on_stop_clicked(GtkButton *b, gpointer data) { (void)b; stop_scan(data); }

static void on_clear_clicked(GtkButton *b, gpointer data)
{
    (void)b;
    App *app = data;
    gtk_text_buffer_set_text(app->buffer, "", -1);
    app->infected = 0;
    app->warnings = 0;
    update_status(app);
}

static void on_save_clicked(GtkButton *b, gpointer data)
{
    (void)b;
    App *app = data;
    GtkWidget *dlg = gtk_file_chooser_dialog_new(
        "Save scan report", GTK_WINDOW(app->window),
        GTK_FILE_CHOOSER_ACTION_SAVE,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Save", GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dlg), TRUE);
    gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dlg), "chkrootkit-report.txt");

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        char *fname = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        GtkTextIter s, e;
        gtk_text_buffer_get_bounds(app->buffer, &s, &e);
        char *text = gtk_text_buffer_get_text(app->buffer, &s, &e, FALSE);
        g_file_set_contents(fname, text, -1, NULL);
        g_free(text);
        g_free(fname);
    }
    gtk_widget_destroy(dlg);
}

static gboolean on_delete(GtkWidget *w, GdkEvent *e, gpointer data)
{
    (void)w; (void)e;
    App *app = data;
    if (app->running && app->pid)
        kill((pid_t)app->pid, SIGTERM);
    return FALSE;
}

/* ---- UI construction -------------------------------------------------- */

/* Cyber palette — neon accents on a deep, near-black backdrop. */
#define CY_BG        "#0a0e14"   /* terminal background        */
#define CY_GREEN     "#39ff14"   /* clean / OK — neon green    */
#define CY_CYAN      "#00e5ff"   /* headers — electric cyan    */
#define CY_AMBER     "#ffb000"   /* warnings — amber           */
#define CY_RED       "#ff2d55"   /* infected — hot red         */
#define CY_DIM       "#5c6f8a"   /* info / muted               */

static void setup_tags(App *app)
{
    gtk_text_buffer_create_tag(app->buffer, "infected",
        "foreground", "#ffffff", "background", CY_RED,
        "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(app->buffer, "warn",
        "foreground", CY_AMBER, "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(app->buffer, "ok",
        "foreground", CY_GREEN, NULL);
    gtk_text_buffer_create_tag(app->buffer, "header",
        "foreground", CY_CYAN, "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(app->buffer, "info",
        "foreground", CY_DIM, "style", PANGO_STYLE_ITALIC, NULL);
}

/* Install a global dark "cyber" stylesheet for the whole app. */
static void apply_cyber_theme(void)
{
    static const char *css =
        "window, .background {"
        "  background-color: #070a0f;"
        "  color: #c7d3e3;"
        "}"
        "headerbar, headerbar.titlebar {"
        "  background: linear-gradient(180deg, #0e1622, #0a0f18);"
        "  border-bottom: 1px solid #00e5ff;"
        "  box-shadow: 0 1px 8px rgba(0,229,255,0.25);"
        "  min-height: 42px;"
        "  padding: 0 8px;"
        "}"
        "headerbar .title {"
        "  color: #00e5ff;"
        "  font-weight: bold;"
        "  letter-spacing: 2px;"
        "  text-shadow: 0 0 8px rgba(0,229,255,0.6);"
        "}"
        "headerbar .subtitle { color: #5c6f8a; letter-spacing: 1px; }"
        "button {"
        "  background: #0f1622;"
        "  color: #c7d3e3;"
        "  border: 1px solid #1d3147;"
        "  border-radius: 4px;"
        "  padding: 5px 14px;"
        "  font-weight: bold;"
        "  letter-spacing: 1px;"
        "}"
        "button:hover {"
        "  border-color: #00e5ff;"
        "  color: #00e5ff;"
        "  box-shadow: 0 0 8px rgba(0,229,255,0.35);"
        "}"
        "button:active { background: #122033; }"
        "button:disabled { color: #3a475a; border-color: #15202e; }"
        "button#scan {"
        "  border-color: #39ff14; color: #39ff14;"
        "}"
        "button#scan:hover {"
        "  box-shadow: 0 0 10px rgba(57,255,20,0.5);"
        "}"
        "button#stop { border-color: #ff2d55; color: #ff7a90; }"
        "button#stop:hover { box-shadow: 0 0 10px rgba(255,45,85,0.5); }"
        "checkbutton { color: #8aa0bd; }"
        "checkbutton check {"
        "  background: #0f1622; border: 1px solid #1d3147;"
        "}"
        "checkbutton check:checked {"
        "  background: #00e5ff; border-color: #00e5ff;"
        "}"
        "textview, textview text {"
        "  background-color: " CY_BG ";"
        "  color: #aeb9c9;"
        "  caret-color: #39ff14;"
        "}"
        "textview { padding: 6px; }"
        "scrolledwindow {"
        "  border: 1px solid #14202e;"
        "}"
        "statusbar {"
        "  background: #0a0f18;"
        "  color: #5c6f8a;"
        "  border-top: 1px solid #14202e;"
        "  font-size: 90%;"
        "  letter-spacing: 1px;"
        "}"
        "spinner { color: #00e5ff; }";

    GtkCssProvider *prov = gtk_css_provider_new();
    gtk_css_provider_load_from_data(prov, css, -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(prov),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(prov);
}

static void build_ui(App *app)
{
    app->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(app->window),
                         "chkrootkit — rootkit scanner");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 820, 560);
    gtk_window_set_icon_name(GTK_WINDOW(app->window), "chkrootkit-gui");
    g_signal_connect(app->window, "delete-event", G_CALLBACK(on_delete), app);
    g_signal_connect(app->window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    /* cyber-styled header bar */
    GtkWidget *hbar = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(hbar), TRUE);
    gtk_header_bar_set_title(GTK_HEADER_BAR(hbar), "\xE2\x9A\xA1 CHKROOTKIT");
    gtk_header_bar_set_subtitle(GTK_HEADER_BAR(hbar),
                                "rootkit detection console");
    gtk_window_set_titlebar(GTK_WINDOW(app->window), hbar);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(app->window), vbox);

    /* toolbar */
    GtkWidget *bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_container_set_border_width(GTK_CONTAINER(bar), 6);
    gtk_box_pack_start(GTK_BOX(vbox), bar, FALSE, FALSE, 0);

    app->scan_btn = gtk_button_new_with_label("\xE2\x96\xB6 START SCAN");
    app->stop_btn = gtk_button_new_with_label("\xE2\x96\xA0 STOP");
    app->clear_btn = gtk_button_new_with_label("CLEAR");
    GtkWidget *save_btn = gtk_button_new_with_label("SAVE REPORT");
    gtk_widget_set_sensitive(app->stop_btn, FALSE);

    /* widget names so the stylesheet can give scan/stop their accent colors */
    gtk_widget_set_name(app->scan_btn, "scan");
    gtk_widget_set_name(app->stop_btn, "stop");

    app->spinner = gtk_spinner_new();

    app->filter_check = gtk_check_button_new_with_label(
        "Ignore known false positives");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(app->filter_check), TRUE);
    gtk_widget_set_tooltip_text(app->filter_check,
        "Hide the RTNETLINK network-check noise and the hidden-dotfile dump,\n"
        "which are harmless false positives. Untick to see the raw output.");

    gtk_box_pack_start(GTK_BOX(bar), app->scan_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bar), app->stop_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bar), app->clear_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bar), save_btn, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(bar), app->spinner, FALSE, FALSE, 6);
    gtk_box_pack_end(GTK_BOX(bar), app->filter_check, FALSE, FALSE, 6);

    g_signal_connect(app->scan_btn, "clicked", G_CALLBACK(on_scan_clicked), app);
    g_signal_connect(app->stop_btn, "clicked", G_CALLBACK(on_stop_clicked), app);
    g_signal_connect(app->clear_btn, "clicked", G_CALLBACK(on_clear_clicked), app);
    g_signal_connect(save_btn, "clicked", G_CALLBACK(on_save_clicked), app);

    /* text view */
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_box_pack_start(GTK_BOX(vbox), scroll, TRUE, TRUE, 0);

    app->textview = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(app->textview), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(app->textview), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(app->textview), TRUE);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(app->textview), 8);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(app->textview), 8);
    gtk_container_add(GTK_CONTAINER(scroll), app->textview);

    app->buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->textview));
    setup_tags(app);

    /* legend */
    GtkWidget *legend = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(legend),
        "  <span foreground='" CY_CYAN "'>\xE2\x97\x86 check</span>   "
        "<span foreground='" CY_GREEN "'>\xE2\x97\x8f clean</span>   "
        "<span foreground='" CY_AMBER "'>\xE2\x97\x8f warning</span>   "
        "<span background='" CY_RED "' foreground='#ffffff'>\xE2\x97\x8f INFECTED</span>");
    gtk_widget_set_halign(legend, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(vbox), legend, FALSE, FALSE, 4);

    /* status bar */
    app->statusbar = gtk_statusbar_new();
    app->status_ctx = gtk_statusbar_get_context_id(
        GTK_STATUSBAR(app->statusbar), "main");
    gtk_box_pack_start(GTK_BOX(vbox), app->statusbar, FALSE, FALSE, 0);

    update_status(app);
}

int main(int argc, char **argv)
{
    gtk_init(&argc, &argv);
    apply_cyber_theme();

    App app;
    memset(&app, 0, sizeof app);

    build_ui(&app);
    gtk_widget_show_all(app.window);
    gtk_widget_hide(app.spinner); /* hidden until a scan runs */

    gtk_main();
    return 0;
}
