import sqlite3
import hashlib
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

console = Console()
CURRENT_USER = None  # Itahifadhi taarifa za aliyeingia (logged in user)

# 1. Kutengeneza Database na Meza (Tables)
def init_db():
    conn = sqlite3.connect("local_market.db")
    cursor = conn.cursor()
    
    # Meza ya watumiaji
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            phone TEXT NOT NULL,
            location TEXT NOT NULL
        )
    """)
    
    # Meza ya bidhaa (Tumeongeza column ya status)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            seller_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL,
            condition TEXT NOT NULL,
            location TEXT NOT NULL,
            phone TEXT NOT NULL,
            status TEXT DEFAULT 'Available',
            FOREIGN KEY (seller_id) REFERENCES users (id)
        )
    """)
    
    # Mfumo wa kuhakikisha column ya status ipo hata kama database ilikuwepo
    try:
        cursor.execute("ALTER TABLE products ADD COLUMN status TEXT DEFAULT 'Available'")
    except sqlite3.OperationalError:
        pass  # Column tayari ipo

    conn.commit()
    conn.close()

# Helper function ya kusimba password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# 2. Usajili wa Mtumiaji MPYA
def register_user():
    console.print(Panel("[bold green]TENGENEZA AKAUNTI MPYA[/bold green]"))
    username = Prompt.ask("Jina la kutumia (Username)").strip().lower()
    
    conn = sqlite3.connect("local_market.db")
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        console.print("[bold red]❌ Jina hili limeshatumiwa! Jaribu jina jingine.[/bold red]\n")
        conn.close()
        return

    password = Prompt.ask("Nywila (Password)", password=True)
    phone = Prompt.ask("Namba ya Simu / WhatsApp (mf. 0712345678)")
    location = Prompt.ask("Eneo/Mtaa wako (mf. Mwenge, Sinza, Kijichi)")

    hashed_pw = hash_password(password)
    cursor.execute(
        "INSERT INTO users (username, password, phone, location) VALUES (?, ?, ?, ?)",
        (username, hashed_pw, phone, location)
    )
    conn.commit()
    conn.close()
    console.print(f"\n[bold green]✓ Hongera {username}! Akaunti yako imetengenezwa. Sasa unaweza kuingia.[/bold green]\n")

# 3. Kuingia Kwenye Mfumo (Log In)
def login_user():
    global CURRENT_USER
    console.print(Panel("[bold blue]INGIA KWENYE AKAUNTI (LOG IN)[/bold blue]"))
    username = Prompt.ask("Jina la kutumia (Username)").strip().lower()
    password = Prompt.ask("Nywila (Password)", password=True)

    hashed_pw = hash_password(password)
    
    conn = sqlite3.connect("local_market.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, phone, location FROM users WHERE username = ? AND password = ?",
        (username, hashed_pw)
    )
    user = cursor.fetchone()
    conn.close()

    if user:
        CURRENT_USER = {
            "id": user[0],
            "username": user[1],
            "phone": user[2],
            "location": user[3]
        }
        console.print(f"\n[bold green]✓ Karibu tena, {CURRENT_USER['username'].capitalize()}![/bold green]\n")
    else:
        console.print("\n[bold red]❌ Username au Password siyo sahihi![/bold red]\n")

# 4. Kuweka Bidhaa Sokoni (Post Product)
def add_product():
    if not CURRENT_USER:
        console.print("[bold red]⚠️ Unatakiwa Uingie (Log In) kwanza ndipo uweze kuuza bidhaa![/bold red]\n")
        return

    console.print(Panel(f"[bold green]UZA BIDHAA (Muuzaji: {CURRENT_USER['username']})[/bold green]"))
    title = Prompt.ask("Jina la Bidhaa")
    
    console.print("\nChagua Kategoria ya Bidhaa:")
    console.print("1. Samani (Furniture)")
    console.print("2. Vifaa vya Umeme")
    console.print("3. Vyombo vya Jikoni")
    console.print("4. Nguo / Viatu")
    console.print("5. Mengineyo")
    
    cat_choice = Prompt.ask("Chagua namba ya kategoria", choices=["1", "2", "3", "4", "5"])
    categories = {
        "1": "Samani (Furniture)",
        "2": "Vifaa vya Umeme",
        "3": "Vyombo vya Jikoni",
        "4": "Nguo / Viatu",
        "5": "Mengineyo"
    }
    category = categories[cat_choice]

    price = float(Prompt.ask("Bei (TZS)"))
    
    console.print("\nChagua Hali ya Bidhaa:")
    console.print("1. Mpya")
    console.print("2. Imetumika Kidogo")
    console.print("3. Imetumika Sana")
    
    cond_choice = Prompt.ask("Chagua namba ya hali", choices=["1", "2", "3"])
    conditions = {
        "1": "Mpya",
        "2": "Imetumika Kidogo",
        "3": "Imetumika Sana"
    }
    condition = conditions[cond_choice]

    location = Prompt.ask("Eneo la Bidhaa", default=CURRENT_USER['location'])
    phone = Prompt.ask("Namba ya Mawasiliano", default=CURRENT_USER['phone'])

    conn = sqlite3.connect("local_market.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO products (seller_id, title, category, price, condition, location, phone, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'Available')",
        (CURRENT_USER['id'], title, category, price, condition, location, phone)
    )
    conn.commit()
    conn.close()
    console.print("\n[bold blue]✓ Bidhaa imeorodheshwa sokoni kikamilifu![/bold blue]\n")

# 5. Kuangalia na Kuchuja Bidhaa Zilizopo Sokoni (Available ONLY)
def view_products():
    console.print(Panel("[bold cyan]TAFUTA / CHUJA BIDHAA SOKONI[/bold cyan]"))
    console.print("1. Angalia Bidhaa Zote Zilizopo")
    console.print("2. Chuja kwa Kategoria")
    console.print("3. Chuja kwa Kiwango cha Bei (Price Range)")
    console.print("4. Chuja kwa Eneo / Mtaa")
    
    choice = Prompt.ask("Chagua njia ya kuangalia bidhaa", choices=["1", "2", "3", "4"])

    # Tunaonyesha tu bidhaa ambazo ziko 'Available'
    query = "SELECT id, title, category, price, condition, location, phone FROM products WHERE status = 'Available'"
    params = []

    if choice == "2":
        console.print("\nChagua Kategoria:")
        console.print("1. Samani (Furniture)")
        console.print("2. Vifaa vya Umeme")
        console.print("3. Vyombo vya Jikoni")
        console.print("4. Nguo / Viatu")
        console.print("5. Mengineyo")
        cat_choice = Prompt.ask("Chagua namba ya kategoria", choices=["1", "2", "3", "4", "5"])
        categories = {
            "1": "Samani (Furniture)",
            "2": "Vifaa vya Umeme",
            "3": "Vyombo vya Jikoni",
            "4": "Nguo / Viatu",
            "5": "Mengineyo"
        }
        query += " AND category = ?"
        params.append(categories[cat_choice])

    elif choice == "3":
        min_p = float(Prompt.ask("Weka Bei ya Chini (TZS)", default="0"))
        max_p = float(Prompt.ask("Weka Bei ya Juu (TZS)", default="10000000"))
        query += " AND price BETWEEN ? AND ?"
        params.extend([min_p, max_p])

    elif choice == "4":
        search_loc = Prompt.ask("Weka jina la eneo/mtaa")
        query += " AND location LIKE ?"
        params.append(f"%{search_loc}%")

    conn = sqlite3.connect("local_market.db")
    cursor = conn.cursor()
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        console.print("\n[yellow]Hakuna bidhaa zilizopatikana kulingana na utafutaji wako.[/yellow]\n")
        return

    table = Table(title="\nBidhaa Zilizopatikana Sokoni")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Bidhaa", style="bold white")
    table.add_column("Kategoria", style="magenta")
    table.add_column("Bei (TZS)", style="green")
    table.add_column("Hali", style="yellow")
    table.add_column("Eneo", style="blue")
    table.add_column("Mawasiliano", style="bold cyan")

    for row in rows:
        table.add_row(str(row[0]), row[1], row[2], f"{row[3]:,.0f}", row[4], row[5], row[6])

    console.print(table)
    console.print()

# 6. Akaunti Yangu - Mark as Sold & Delete Item
def manage_my_products():
    if not CURRENT_USER:
        console.print("[bold red]⚠️ Ingia (Log In) ili kuona akaunti yako![/bold red]\n")
        return

    while True:
        console.print(Panel(f"[bold magenta]AKAUNTI YANGU - {CURRENT_USER['username'].upper()}[/bold magenta]"))
        
        conn = sqlite3.connect("local_market.db")
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, title, category, price, condition, status FROM products WHERE seller_id = ?",
            (CURRENT_USER['id'],)
        )
        my_products = cursor.fetchall()
        conn.close()

        if not my_products:
            console.print("[yellow]Hujapost bidhaa yoyote bado.[/yellow]\n")
            break

        table = Table(title="Bidhaa Zako Ulizopost Sokoni")
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Bidhaa", style="bold white")
        table.add_column("Kategoria", style="magenta")
        table.add_column("Bei (TZS)", style="green")
        table.add_column("Hali ya Bidhaa", style="yellow")
        table.add_column("Hali ya Mauzo (Status)", style="bold blue")

        for row in my_products:
            status_style = "[bold green]Available[/bold green]" if row[5] == 'Available' else "[bold red]SOLD (Imeshauzwa)[/bold red]"
            table.add_row(str(row[0]), row[1], row[2], f"{row[3]:,.0f}", row[4], status_style)

        console.print(table)
        console.print("\n1. Badili Kuwa 'Imeshauzwa' (Mark as Sold)")
        console.print("2. Futa Bidhaa (Delete Item)")
        console.print("0. Rudi Menyu Kuu")
        
        sub_choice = Prompt.ask("Chagua", choices=["1", "2", "0"])
        
        if sub_choice == "1":
            product_id = Prompt.ask("Weka ID ya bidhaa uliyoiuza")
            conn = sqlite3.connect("local_market.db")
            cursor = conn.cursor()
            cursor.execute("SELECT title, status FROM products WHERE id = ? AND seller_id = ?", (product_id, CURRENT_USER['id']))
            item = cursor.fetchone()

            if item:
                if item[1] == 'Sold':
                    console.print("\n[yellow]⚠️ Bidhaa hii tayari ilishawekwa kama Imeshauzwa![/yellow]\n")
                else:
                    cursor.execute("UPDATE products SET status = 'Sold' WHERE id = ?", (product_id,))
                    conn.commit()
                    console.print(f"\n[bold green]✓ Hongera! Bidhaa '{item[0]}' sasa imewekwa kama IMESHAUZWA (SOLD)![/bold green]\n")
            else:
                console.print("\n[bold red]❌ ID haipo au bidhaa hiyo siyo yako![/bold red]\n")
            conn.close()

        elif sub_choice == "2":
            product_id = Prompt.ask("Weka ID ya bidhaa unayotaka kufuta")
            conn = sqlite3.connect("local_market.db")
            cursor = conn.cursor()
            cursor.execute("SELECT title FROM products WHERE id = ? AND seller_id = ?", (product_id, CURRENT_USER['id']))
            item = cursor.fetchone()

            if item:
                confirm = Confirm.ask(f"Je, una uhakika unataka kufuta '[bold red]{item[0]}[/bold red]'?")
                if confirm:
                    cursor.execute("DELETE FROM products WHERE id = ?", (product_id,))
                    conn.commit()
                    console.print("\n[bold green]✓ Bidhaa imefutwa kikamilifu![/bold green]\n")
            else:
                console.print("\n[bold red]❌ ID haipo au bidhaa hiyo siyo yako![/bold red]\n")
            conn.close()

        elif sub_choice == "0":
            break

# 7. Menyu Kuu
def main():
    global CURRENT_USER
    init_db()
    
    while True:
        status_text = f"Mtumiaji: [bold green]{CURRENT_USER['username']}[/bold green]" if CURRENT_USER else "[yellow]Hujaingia (Guest)[/yellow]"
        console.print(Panel(f"[bold cyan]JUKWAA LA SOKO LA MTAA (LOCAL MARKETPLACE)[/bold cyan]\nStatus: {status_text}"))
        
        console.print("1. Angalia Bidhaa Zilizopo (Search/Browse)")
        console.print("2. Uza Bidhaa (Post Item)")
        
        if not CURRENT_USER:
            console.print("3. Ingia Kwenye Akaunti (Log In)")
            console.print("4. Tengeneza Akaunti MPYA (Register)")
        else:
            console.print("3. Akaunti Yangu / Bidhaa Zangu (My Listings & Delete)")
            console.print("4. Toka Kwenye Akaunti (Log Out)")
            
        console.print("0. Ondoka Kwenye Programu")
        
        choices = ["1", "2", "3", "4", "0"]
        choice = Prompt.ask("Chagua huduma", choices=choices)
        
        if choice == "1":
            view_products()
        elif choice == "2":
            add_product()
        elif choice == "3":
            if not CURRENT_USER:
                login_user()
            else:
                manage_my_products()
        elif choice == "4":
            if not CURRENT_USER:
                register_user()
            else:
                CURRENT_USER = None
                console.print("\n[bold yellow]Umetoka kwenye akaunti yako.[/bold yellow]\n")
        elif choice == "0":
            console.print("[bold red]Kwaheri na ahsante kwa kutumia Soko la Mtaa![/bold red]")
            break

if __name__ == "__main__":
    main()
