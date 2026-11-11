// linux-passkey-dialog: the default approval agent of linux-passkey (GTK4 +
// libadwaita). The daemon starts it per request and talks JSON lines over
// stdin/stdout; the protocol is described in the daemon's src/agent.rs.
// It only shows the request and reports the answer: every decision stays in
// the daemon.

use adw::prelude::*;
use gtk::glib;
use serde::Deserialize;
use std::cell::{Cell, RefCell};
use std::io::{BufRead, Write};
use std::rc::Rc;

const APP_ID: &str = "io.github.koxu1996.LinuxPasskey.Dialog";

#[derive(Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
struct Account {
    #[serde(default)]
    id: String,
    name: Option<String>,
    display_name: Option<String>,
}

#[derive(Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
struct Ask {
    op: String,
    #[serde(default)]
    rp: String,
    origin: Option<String>,
    app: Option<String>,
    user: Option<Account>,
    #[serde(default)]
    accounts: Vec<Account>,
    #[serde(default)]
    elsewhere: bool,
    #[serde(default)]
    fingerprint: bool,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Message {
    Ask(Ask),
    Fingerprint { state: String },
    Done,
}

/// Write one answer line. Only the first answer counts.
fn answer(sent: &Cell<bool>, msg: serde_json::Value) {
    if sent.replace(true) {
        return;
    }
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{msg}");
    let _ = out.flush();
}

/// Site-supplied text: no control characters, and short.
fn clean(s: &str) -> String {
    let mut out: String = s.chars().filter(|c| !c.is_control()).take(64).collect();
    if s.chars().count() > 64 {
        out.push('…');
    }
    out
}

fn host_of(origin: &str) -> &str {
    origin.split("://").nth(1).unwrap_or(origin)
}

struct Wording {
    title: String,
    body: String,
    ok: &'static str,
    destructive: bool,
}

fn wording(ask: &Ask) -> Wording {
    let rp = clean(&ask.rp);
    let w = |title: String, body: &str, ok, destructive| Wording { title, body: body.to_string(), ok, destructive };
    match ask.op.as_str() {
        "register" => w(format!("Create a passkey for {rp}"), "The passkey stays in this computer's secure hardware.", "Create", false),
        "already-registered" => w(
            format!("{rp} already has a passkey"),
            "This computer is already registered with this account. Nothing new is created.",
            "OK",
            false,
        ),
        "sign-in" => w(format!("Sign in to {rp}"), "", "Sign in", false),
        "select" => w(
            "Use this security key?".into(),
            "The browser asks which security key to use. Nothing is created.",
            "Select",
            false,
        ),
        "reset" => w(
            "Reset the authenticator?".into(),
            "This permanently deletes ALL passkeys on this computer.",
            "Reset",
            true,
        ),
        "u2f-register" => w("Register this security key".into(), "A site asks to register this key (legacy U2F).", "Register", false),
        "u2f-sign-in" => w("Sign in with this security key".into(), "A site asks to use this key (legacy U2F).", "Sign in", false),
        _ => w("Use your passkey?".into(), "", "Confirm", false),
    }
}

fn account_row(a: &Account) -> adw::ActionRow {
    let name = a.name.as_deref().or(a.display_name.as_deref()).unwrap_or("Unnamed account");
    let row = adw::ActionRow::builder().title(glib::markup_escape_text(&clean(name))).build();
    if let (Some(display), Some(n)) = (&a.display_name, &a.name) {
        if display != n {
            row.set_subtitle(&glib::markup_escape_text(&clean(display)));
        }
    }
    row.add_prefix(&gtk::Image::from_icon_name("avatar-default-symbolic"));
    row
}

struct Ui {
    window: adw::ApplicationWindow,
    stack: gtk::Stack,
    finger_status: gtk::Label,
    sent: Rc<Cell<bool>>,
    /// The daemon said done: closing is no answer any more.
    done: Rc<Cell<bool>>,
}

/// The request page: what, for whom, which account, and the buttons.
fn ask_page(ui: &Ui, ask: &Ask) -> gtk::Widget {
    let words = wording(ask);
    let page = gtk::Box::new(gtk::Orientation::Vertical, 12);
    page.set_margin_top(24);
    page.set_margin_bottom(20);
    page.set_margin_start(24);
    page.set_margin_end(24);

    let icon = gtk::Image::from_icon_name("dialog-password-symbolic");
    icon.set_pixel_size(48);
    icon.add_css_class("dim-label");
    page.append(&icon);

    let title = gtk::Label::new(Some(&words.title));
    title.add_css_class("title-2");
    title.set_wrap(true);
    title.set_justify(gtk::Justification::Center);
    page.append(&title);

    // Who asks: "Brave · accounts.google.com".
    let from: Vec<String> = [ask.app.clone(), ask.origin.as_deref().map(|o| clean(host_of(o)))]
        .into_iter()
        .flatten()
        .collect();
    if !from.is_empty() {
        let label = gtk::Label::new(Some(&from.join(" · ")));
        label.add_css_class("dim-label");
        page.append(&label);
    }

    // The account: one to register, or a choice to sign in with.
    let chosen: Rc<RefCell<Option<String>>> = Rc::default();
    let list = gtk::ListBox::new();
    list.add_css_class("boxed-list");
    list.set_selection_mode(gtk::SelectionMode::None);
    list.set_margin_top(6);
    if ask.op == "sign-in" && !ask.accounts.is_empty() {
        let mut group: Option<gtk::CheckButton> = None;
        for (i, a) in ask.accounts.iter().enumerate() {
            let row = account_row(a);
            let check = gtk::CheckButton::new();
            check.set_group(group.as_ref());
            group.get_or_insert_with(|| check.clone());
            if i == 0 {
                check.set_active(true);
                *chosen.borrow_mut() = Some(a.id.clone());
            }
            let (chosen, id) = (chosen.clone(), a.id.clone());
            check.connect_toggled(move |c| {
                if c.is_active() {
                    *chosen.borrow_mut() = Some(id.clone());
                }
            });
            row.add_suffix(&check);
            row.set_activatable_widget(Some(&check));
            list.append(&row);
        }
        // One account needs no choosing, only naming.
        if ask.accounts.len() == 1 {
            if let Some(c) = group {
                c.set_visible(false);
            }
        }
        page.append(&list);
    } else if let Some(user) = &ask.user {
        list.append(&account_row(user));
        page.append(&list);
    }

    let mut body = words.body.clone();
    if ask.fingerprint {
        if !body.is_empty() {
            body.push(' ');
        }
        body.push_str("Then touch the fingerprint sensor.");
    }
    if !body.is_empty() {
        let label = gtk::Label::new(Some(&body));
        label.set_wrap(true);
        label.set_justify(gtk::Justification::Center);
        label.set_max_width_chars(44);
        label.add_css_class("dim-label");
        page.append(&label);
    }

    let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    buttons.set_margin_top(12);
    if ask.elsewhere {
        let other = gtk::Button::with_label("Use another device");
        other.add_css_class("flat");
        let (sent, window) = (ui.sent.clone(), ui.window.clone());
        other.connect_clicked(move |_| {
            answer(&sent, serde_json::json!({ "answer": "elsewhere" }));
            window.close();
        });
        buttons.append(&other);
    }
    let spacer = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    spacer.set_hexpand(true);
    buttons.append(&spacer);

    let cancel = gtk::Button::with_label("Cancel");
    let (sent, window) = (ui.sent.clone(), ui.window.clone());
    cancel.connect_clicked(move |_| {
        answer(&sent, serde_json::json!({ "answer": "deny" }));
        window.close();
    });
    buttons.append(&cancel);

    let ok = gtk::Button::with_label(words.ok);
    ok.add_css_class(if words.destructive { "destructive-action" } else { "suggested-action" });
    let (sent, window, stack, fingerprint) = (ui.sent.clone(), ui.window.clone(), ui.stack.clone(), ask.fingerprint);
    ok.connect_clicked(move |_| {
        let mut msg = serde_json::json!({ "answer": "approve" });
        if let Some(id) = chosen.borrow().as_ref() {
            msg["account"] = id.clone().into();
        }
        answer(&sent, msg);
        if fingerprint {
            stack.set_visible_child_name("finger");
        } else {
            window.close();
        }
    });
    buttons.append(&ok);
    page.append(&buttons);
    ui.window.set_default_widget(Some(&ok));
    ok.grab_focus();
    page.upcast()
}

/// The fingerprint page, after an approve.
fn finger_page(ui_window: &adw::ApplicationWindow, status: &gtk::Label) -> gtk::Widget {
    let page = gtk::Box::new(gtk::Orientation::Vertical, 12);
    page.set_margin_top(32);
    page.set_margin_bottom(20);
    page.set_margin_start(24);
    page.set_margin_end(24);
    let icon = gtk::Image::from_icon_name("auth-fingerprint-symbolic");
    icon.set_pixel_size(64);
    icon.add_css_class("accent");
    page.append(&icon);
    let title = gtk::Label::new(Some("Touch the fingerprint sensor"));
    title.add_css_class("title-2");
    page.append(&title);
    status.add_css_class("dim-label");
    page.append(status);
    let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    buttons.set_halign(gtk::Align::End);
    buttons.set_margin_top(12);
    let cancel = gtk::Button::with_label("Cancel");
    let window = ui_window.clone();
    cancel.connect_clicked(move |_| window.close());
    buttons.append(&cancel);
    // Same height as the request page (see build): Cancel stays at the bottom.
    let spacer = gtk::Box::new(gtk::Orientation::Vertical, 0);
    spacer.set_vexpand(true);
    page.append(&spacer);
    page.append(&buttons);
    page.upcast()
}

fn build(app: &adw::Application) {
    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("Passkey")
        .default_width(420)
        .resizable(false)
        .build();
    let stack = gtk::Stack::new();
    // Both pages the same size: the window never resizes (a resize races the
    // compositor's own animation and shows stale pixels at the edges).
    stack.set_transition_type(gtk::StackTransitionType::Crossfade);
    stack.set_hhomogeneous(true);
    stack.set_vhomogeneous(true);
    let finger_status = gtk::Label::new(Some("Waiting…"));
    let ui = Rc::new(Ui {
        window: window.clone(),
        stack: stack.clone(),
        finger_status,
        sent: Rc::default(),
        done: Rc::default(),
    });
    stack.add_named(&finger_page(&window, &ui.finger_status), Some("finger"));
    window.set_content(Some(&stack));

    // Esc and the close button deny. After an approve, while the daemon
    // waits for the finger, a deny cancels that wait.
    let (sent, done, s) = (ui.sent.clone(), ui.done.clone(), ui.stack.clone());
    window.connect_close_request(move |_| {
        if !sent.get() {
            answer(&sent, serde_json::json!({ "answer": "deny" }));
        } else if !done.get() && s.visible_child_name().as_deref() == Some("finger") {
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "{}", serde_json::json!({ "answer": "deny" }));
            let _ = out.flush();
        }
        glib::Propagation::Proceed
    });
    let keys = gtk::EventControllerKey::new();
    let w = window.clone();
    keys.connect_key_pressed(move |_, key, _, _| {
        if key == gtk::gdk::Key::Escape {
            w.close();
            return glib::Propagation::Stop;
        }
        glib::Propagation::Proceed
    });
    window.add_controller(keys);

    // Messages from the daemon, read on a thread.
    let (tx, rx) = async_channel::unbounded::<Option<String>>();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            match line {
                Ok(l) => {
                    if tx.send_blocking(Some(l)).is_err() {
                        return;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = tx.send_blocking(None);
    });
    let app = app.clone();
    glib::spawn_future_local(async move {
        while let Ok(Some(line)) = rx.recv().await {
            match serde_json::from_str::<Message>(&line) {
                Ok(Message::Ask(ask)) => {
                    let page = ask_page(&ui, &ask);
                    ui.stack.add_named(&page, Some("ask"));
                    ui.stack.set_visible_child_name("ask");
                    ui.window.present();
                }
                Ok(Message::Fingerprint { state }) => {
                    ui.stack.set_visible_child_name("finger");
                    ui.finger_status.set_text(match state.as_str() {
                        "waiting" => "Waiting…",
                        "no-match" => "Not recognized. Try again.",
                        "match" => "Recognized",
                        _ => "The fingerprint check failed.",
                    });
                }
                Ok(Message::Done) => {
                    ui.done.set(true);
                    break;
                }
                Err(e) => eprintln!("linux-passkey-dialog: bad message: {e}"),
            }
        }
        // Done, or the daemon went away.
        ui.done.set(true);
        app.quit();
    });
}

fn main() -> glib::ExitCode {
    let app = adw::Application::builder()
        .application_id(APP_ID)
        // One window per request, never handed to another instance.
        .flags(gtk::gio::ApplicationFlags::NON_UNIQUE)
        .build();
    app.connect_activate(build);
    app.run_with_args::<&str>(&[])
}
