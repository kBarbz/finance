import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    rows = db.execute("SELECT stock_id, SUM(shares) FROM purchases WHERE user_id = :id GROUP BY stock_id", id=session["user_id"])
    price = []
    stock_value = []
    value = 0
    for i in range(len(rows)):
        stock = lookup(db.execute("SELECT stock_symbol FROM stocks WHERE id = :id", id=rows[i]['stock_id'])[0]['stock_symbol'])
        price.append(stock["price"])
        stock_value.append(usd(stock["price"] * rows[i]['SUM(shares)']))
        rows[i]['stock_id'] = stock["name"] + " (" + stock["symbol"] + ")"
        value += price[i] * rows[i]['SUM(shares)']
    cash = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])[0]['cash']
    value = usd(cash + value)
    cash = usd(cash)
    return render_template("index.html", cash=cash, rows=rows, price=price, value=value, stock_value=stock_value)


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    """Change password"""

    if request.method == "POST":
        rows = db.execute("SELECT * FROM users WHERE id= :id",
                          id=session["user_id"])

        if not request.form.get("old_password"):
            return apology("must provide old password", 400)
        elif not request.form.get("new_password"):
            return apology("must provide new password", 400)
        elif not request.form.get("new_password2"):
            return apology("must confirm new password", 400)

        if request.form.get("new_password") != request.form.get("new_password2"):
            return apology("both passwords must match", 400)

        if not check_password_hash(rows[0]["hash"], request.form.get("old_password")):
            return apology("current password was incorrect")
        else:
            pass_hash = generate_password_hash(request.form.get("new_password2"))
            db.execute("UPDATE users SET hash = :hash WHERE id = :id", hash=pass_hash, id=session["user_id"])

        return redirect('/')
    else:
        return render_template("password.html")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        stock = lookup(request.form.get("symbol"))
        if stock == None:
            return apology("Invalid stock", 400)

        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("Please enter the number of shares", 400)
        if not shares > 0:
            return apology("Please enter a positive number", 400)

        db.execute("INSERT INTO stocks (stock_symbol, stock_name) VALUES(:stock_symbol, :stock_name)",
                   stock_symbol=stock['symbol'], stock_name=stock['name'])
        stock_id = db.execute("SELECT id FROM stocks WHERE stock_symbol = :stock_symbol",
                              stock_symbol=stock['symbol'])[0]['id']
        money = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])
        money = money[0]['cash']
        price = stock["price"]
        if price * shares > money:
            return apology("You can't afford that")
        else:
            db.execute("INSERT INTO purchases (stock_id, user_id, shares, price) VALUES(:stock_id, :user_id, :shares, :price)",
                       stock_id=stock_id, user_id=session["user_id"], shares=shares, price=price)
            db.execute("UPDATE users SET cash = cash - :cost WHERE id = :id", cost=price * shares, id=session["user_id"])
            return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""

    username = request.args.get("username")

    user = db.execute("SELECT username FROM users WHERE username = :username", username=username)
    if not user:
        return jsonify(True)
    return jsonify(False)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    rows = db.execute("SELECT stock_id, shares, price, date FROM purchases WHERE user_id = :id", id=session["user_id"])
    for i in range(len(rows)):
        stock = db.execute("SELECT stock_symbol FROM stocks WHERE id = :id", id=rows[i]['stock_id'])[0]['stock_symbol']
        rows[i]["stock_id"] = stock
        rows[i]["price"] = usd(rows[i]["price"])
        if rows[i]["shares"] > 0:
            rows[i]["shares"] = str(rows[i]["shares"]) + " (bought)"
        elif rows[i]["shares"] < 0:
            rows[i]["shares"] = str(abs(rows[i]["shares"])) + " (sold)"

    return render_template("history.html", rows=rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))
        if quote == None:
            return apology("Invalid stock", 400)
        stock = quote['name']
        symbol = quote['symbol']
        price = usd(quote['price'])
        return render_template("quoted.html", stock=stock, symbol=symbol, price=price)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure passwords were submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)

        # Ensure passwords match
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("both passwords must match", 400)

        pass_hash = generate_password_hash(request.form.get("confirmation"))
        result = db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)",
                            username=request.form.get("username"), hash=pass_hash)
        if not result:
            return apology("must choose a valid username", 400)
        else:
            rows = db.execute("SELECT * FROM users WHERE username = :username",
                              username=request.form.get("username"))
            session["user_id"] = rows[0]["id"]
            return redirect('/')

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":

        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("Please enter the number of shares", 400)
        if not shares > 0:
            return apology("Please enter a positive number", 400)

        stock_id = db.execute("SELECT id FROM stocks WHERE stock_symbol = :stock_symbol",
                              stock_symbol=request.form.get("symbol"))[0]["id"]
        avail_shares = db.execute(
            "SELECT SUM(shares) FROM purchases WHERE stock_id = :stock_id GROUP BY stock_id",
            stock_id=stock_id)[0]["SUM(shares)"]
        if shares > avail_shares:
            return apology("You don't have that many shares", 400)

        stock = lookup(request.form.get("symbol"))
        price = stock["price"]
        db.execute("INSERT INTO purchases (stock_id, user_id, shares, price) VALUES(:stock_id, :user_id, :shares, :price)",
                   stock_id=stock_id, user_id=session["user_id"], shares=-abs(shares), price=price)
        db.execute("UPDATE users SET cash = cash + :cost WHERE id = :id", cost=shares * price, id=session["user_id"])

        return redirect('/')
    else:
        rows = db.execute("SELECT stock_id, SUM(shares) FROM purchases WHERE user_id = :id GROUP BY stock_id",
                          id=session["user_id"])
        for i in range(len(rows)):
            rows[i]['stock_id'] = db.execute("SELECT stock_symbol FROM stocks WHERE id = :id",
                                             id=rows[i]['stock_id'])[0]['stock_symbol']

        return render_template("sell.html", rows=rows)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

if __name__ == '__main__':
    app.run(debug=True)