import sqlite3
import hashlib
from textual.app import App, ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Header, Footer, DataTable, Button, Label, Static, Input, Select
from textual.containers import Container, Vertical, Horizontal

# Helper function ya kusimba password
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# 1. Pop-up ya Akaunti Yangu & Kusimamia Bidhaa (My Listings Modal)
# 1. Pop-up ya Akaunti Yangu & Kusimamia Bidhaa (My Listings Modal)
class MyListingsModal(ModalScreen):
    CSS = """
    MyListingsModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.7);
    }
    #listings-dialog {
        width: 85%;
        height: 90%;
        border: thick $accent;
        background: $surface;
        padding: 1;
    }
    DataTable {
        height: 1fr;
        margin-bottom: 1;
    }
    .action-box {
        height: 3;
        margin-bottom: 1;
    }
    Input {
        width: 40%;
        margin-right: 1;
    }
    Button {
        margin-right: 1;
    }
    """

    def __init__(self, current_user: dict):
        super().__init__()
        self.current_user = current_user

    def compose(self) -> ComposeResult:
        with Vertical(id="listings-dialog"):
            yield Label(f"[bold magenta]📦 BIDHAA ZANGU - {self.current_user['username'].upper()}[/bold magenta]")
            yield Label("[dim]Bofya mstari wa bidhaa kisha chagua hatua chini:[/dim]\n")
            yield DataTable(id="my-product-table")
            
            with Horizontal(classes="action-box"):
                yield Input(placeholder="ID ya Bidhaa", id="input-item-id", type="number")
                yield Button("Mark as Sold", id="btn-mark-sold", variant="success")
                yield Button("Futa (Delete)", id="btn-delete", variant="error")
                yield Button("Funga", id="btn-close", variant="primary")
class LoginModal(ModalScreen):
    CSS = """
    LoginModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.7);
    }
    #login-dialog {
        width: 50%;
        height: auto;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }
    Input {
        margin-bottom: 1;
    }
    #button-box {
        margin-top: 1;
        height: 3;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="login-dialog"):
            yield Label("[bold blue]🔑 INGIA KWENYE AKAUNTI (LOG IN)[/bold blue]\n")
            yield Input(placeholder="Username", id="input-username")
            yield Input(placeholder="Password", id="input-password", password=True)
            
            with Horizontal(id="button-box"):
                yield Button("Ingia", id="btn-do-login", variant="primary")
                yield Button("Ghairi", id="btn-cancel", variant="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-do-login":
            username = self.query_one("#input-username", Input).value.strip().lower()
            password = self.query_one("#input-password", Input).value

            if not (username and password):
                self.app.notify("⚠️ Weka Username na Password!", severity="error")
                return

            hashed_pw = hash_password(password)
            try:
                conn = sqlite3.connect("local_market.db")
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id, username, phone, location FROM users WHERE username = ? AND password = ?",
                    (username, hashed_pw)
                )
                user = cursor.fetchone()
                conn.close()

                if user:
                    user_data = {
                        "id": user[0],
                        "username": user[1],
                        "phone": user[2],
                        "location": user[3]
                    }
                    self.app.notify(f"✓ Karibu tena, {username.capitalize()}!")
                    self.dismiss(user_data)
                else:
                    self.app.notify("❌ Username au Password siyo sahihi!", severity="error")
            except Exception as e:
                self.app.notify(f"❌ Kosa: {str(e)}", severity="error")

        elif event.button.id == "btn-cancel":
            self.dismiss(None)


# 3. Pop-up Screen ya Usajili (Register Modal)
class RegisterModal(ModalScreen):
    CSS = """
    RegisterModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.7);
    }
    #register-dialog {
        width: 50%;
        height: auto;
        border: thick $success;
        background: $surface;
        padding: 1 2;
    }
    Input {
        margin-bottom: 1;
    }
    #button-box {
        margin-top: 1;
        height: 3;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="register-dialog"):
            yield Label("[bold green]📝 TENGENEZA AKAUNTI MPYA[/bold green]\n")
            yield Input(placeholder="Jina la kutumia (Username)", id="reg-username")
            yield Input(placeholder="Nywila (Password)", id="reg-password", password=True)
            yield Input(placeholder="Namba ya Simu / WhatsApp", id="reg-phone")
            yield Input(placeholder="Eneo/Mtaa wako (mf. Mwenge, Sinza)", id="reg-location")

            with Horizontal(id="button-box"):
                yield Button("Sajili Akaunti", id="btn-do-register", variant="success")
                yield Button("Ghairi", id="btn-cancel", variant="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-do-register":
            username = self.query_one("#reg-username", Input).value.strip().lower()
            password = self.query_one("#reg-password", Input).value
            phone = self.query_one("#reg-phone", Input).value.strip()
            location = self.query_one("#reg-location", Input).value.strip()

            if not (username and password and phone and location):
                self.app.notify("⚠️ Jaza taarifa zote!", severity="error")
                return

            hashed_pw = hash_password(password)
            try:
                conn = sqlite3.connect("local_market.db")
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
                if cursor.fetchone():
                    self.app.notify("❌ Jina hili limeshatumiwa!", severity="error")
                    conn.close()
                    return

                cursor.execute(
                    "INSERT INTO users (username, password, phone, location) VALUES (?, ?, ?, ?)",
                    (username, hashed_pw, phone, location)
                )
                conn.commit()
                conn.close()

                self.app.notify("✓ Akaunti imetengenezwa! Sasa unaweza kuingia.")
                self.dismiss(True)
            except Exception as e:
                self.app.notify(f"❌ Kosa: {str(e)}", severity="error")

        elif event.button.id == "btn-cancel":
            self.dismiss(False)


# 4. Pop-up Screen ya Kuweka Bidhaa Mpya (Add Product Modal)
class AddProductModal(ModalScreen):
    CSS = """
    AddProductModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.7);
    }
    #modal-dialog {
        width: 60%;
        height: auto;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }
    Input, Select {
        margin-bottom: 1;
    }
    #button-box {
        margin-top: 1;
        height: 3;
    }
    """

    def __init__(self, current_user: dict):
        super().__init__()
        self.current_user = current_user

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-dialog"):
            yield Label(f"[bold green]➕ WEKA BIDHAA MPYA (Muuzaji: {self.current_user['username']})[/bold green]\n")
            yield Input(placeholder="Jina la Bidhaa", id="input-title")
            yield Select(
                options=[
                    ("Samani (Furniture)", "Samani (Furniture)"),
                    ("Vifaa vya Umeme", "Vifaa vya Umeme"),
                    ("Vyombo vya Jikoni", "Vyombo vya Jikoni"),
                    ("Nguo / Viatu", "Nguo / Viatu"),
                    ("Mengineyo", "Mengineyo"),
                ],
                prompt="Chagua Kategoria",
                id="select-category"
            )
            yield Input(placeholder="Bei (TZS)", id="input-price", type="number")
            yield Select(
                options=[
                    ("Mpya", "Mpya"),
                    ("Imetumika Kidogo", "Imetumika Kidogo"),
                    ("Imetumika Sana", "Imetumika Sana"),
                ],
                prompt="Chagua Hali ya Bidhaa",
                id="select-condition"
            )
            yield Input(placeholder="Eneo", value=self.current_user['location'], id="input-location")
            yield Input(placeholder="Namba ya Simu", value=self.current_user['phone'], id="input-phone")

            with Horizontal(id="button-box"):
                yield Button("Hifadhi Bidhaa", id="btn-save", variant="success")
                yield Button("Ghairi", id="btn-cancel", variant="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-save":
            title = self.query_one("#input-title", Input).value.strip()
            category = self.query_one("#select-category", Select).value
            price = self.query_one("#input-price", Input).value.strip()
            condition = self.query_one("#select-condition", Select).value
            location = self.query_one("#input-location", Input).value.strip()
            phone = self.query_one("#input-phone", Input).value.strip()

            if not (title and category and price and condition and location and phone):
                self.app.notify("⚠️ Tafadhali jaza taarifa zote!", severity="error")
                return

            try:
                conn = sqlite3.connect("local_market.db")
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO products (seller_id, title, category, price, condition, location, phone, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'Available')",
                    (self.current_user['id'], title, str(category), float(price), str(condition), location, phone)
                )
                conn.commit()
                conn.close()

                self.app.notify("✓ Bidhaa imehifadhiwa kikamilifu!")
                self.dismiss(True)
            except Exception as e:
                self.app.notify(f"❌ Kosa: {str(e)}", severity="error")

        elif event.button.id == "btn-cancel":
            self.dismiss(False)


# 5. Main TUI Application
class SokoLaMtaaApp(App):
    CSS = """
    Screen {
        layout: vertical;
        background: $surface;
    }
    #title-box {
        height: 3;
        content-align: center middle;
        background: $accent;
        color: $text;
        text-style: bold;
    }
    #main-container {
        layout: horizontal;
        height: 1fr;
    }
    #left-panel {
        width: 32%;
        border: solid green;
        padding: 0 1;
    }
    #right-panel {
        width: 68%;
        border: solid blue;
        padding: 0 1;
    }
    Button {
        width: 100%;
        margin-bottom: 0;
        height: 3;
    }
    DataTable {
        height: 1fr;
    }
    """
    BINDINGS = [
        ("q", "quit", "Ondoka"),
        ("r", "refresh", "Refresh Data"),
    ]

    def __init__(self):
        super().__init__()
        self.current_user = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("🛒 JUKWAA LA SOKO LA MTAA - TUI DASHBOARD", id="title-box")
        
        with Container(id="main-container"):
            with Vertical(id="left-panel"):
                yield Label("[bold green]MENYU KUU[/bold green]", id="status-label")
                yield Button("1. Bidhaa Sokoni", id="btn-browse", variant="primary")
                yield Button("2. Kuza Bidhaa Mpya", id="btn-add", variant="success")
                yield Button("3. Akaunti / Bidhaa Zangu", id="btn-my-items", variant="warning")
                yield Button("4. Log In", id="btn-login", variant="default")
                yield Button("5. Register Akaunti", id="btn-register", variant="default")
                yield Button("0. Ondoka", id="btn-quit", variant="error")
            
            with Vertical(id="right-panel"):
                yield Label("[bold cyan]Orodha ya Bidhaa Zilizopo Sokoni[/bold cyan]\n")
                yield DataTable(id="product-table")

        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("ID", "Bidhaa", "Kategoria", "Bei (TZS)", "Hali", "Eneo", "Simu")
        self.update_user_ui()
        self.load_products()

    def update_user_ui(self) -> None:
        status_lbl = self.query_one("#status-label", Label)
        login_btn = self.query_one("#btn-login", Button)
        
        if self.current_user:
            status_lbl.update(f"[bold green]Mtumiaji: {self.current_user['username'].upper()}[/bold green]")
            login_btn.label = "4. Log Out"
            login_btn.variant = "error"
        else:
            status_lbl.update("[bold yellow]Status: Hujaingia (Guest)[/bold yellow]")
            login_btn.label = "4. Log In"
            login_btn.variant = "default"

    def load_products(self) -> None:
        table = self.query_one(DataTable)
        table.clear()

        try:
            conn = sqlite3.connect("local_market.db")
            cursor = conn.cursor()
            cursor.execute("SELECT id, title, category, price, condition, location, phone FROM products WHERE status = 'Available'")
            rows = cursor.fetchall()
            conn.close()

            if rows:
                for row in rows:
                    table.add_row(
                        str(row[0]),
                        str(row[1]),
                        str(row[2]),
                        f"{row[3]:,.0f}",
                        str(row[4]),
                        str(row[5]),
                        str(row[6])
                    )
            else:
                table.add_row("-", "Hakuna Bidhaa Sokoni", "-", "-", "-", "-", "-")
        except Exception:
            table.add_row("1", "Shirt", "Nguo / Viatu", "5,000", "Mpya", "Mtekente", "0700000000")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-browse":
            self.load_products()
            self.notify("Orodha ya bidhaa imesasishwa!")

        elif event.button.id == "btn-add":
            if not self.current_user:
                self.notify("⚠️ Ingia (Log In) kwanza ili uweze kuuza bidhaa!", severity="error")
                return
            
            def check_add(saved: bool | None):
                if saved:
                    self.load_products()

            self.push_screen(AddProductModal(self.current_user), check_add)

        elif event.button.id == "btn-my-items":
            if not self.current_user:
                self.notify("⚠️ Ingia (Log In) kwanza kuona akaunti yako!", severity="error")
                return

            def check_refresh(updated: bool | None):
                if updated:
                    self.load_products()

            self.push_screen(MyListingsModal(self.current_user), check_refresh)

        elif event.button.id == "btn-login":
            if self.current_user:
                self.current_user = None
                self.update_user_ui()
                self.notify("Umetoka kwenye akaunti yako (Logged Out).")
            else:
                def check_login(user_data: dict | None):
                    if user_data:
                        self.current_user = user_data
                        self.update_user_ui()

                self.push_screen(LoginModal(), check_login)

        elif event.button.id == "btn-register":
            self.push_screen(RegisterModal())

        elif event.button.id == "btn-quit":
            self.exit()

    def action_refresh(self) -> None:
        self.load_products()


if __name__ == "__main__":
    app = SokoLaMtaaApp()
    app.run()
