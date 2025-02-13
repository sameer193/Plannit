#Authentication and Authorization

#Authentication is the process of verifying user identify
#This will check wheather user is authenticated to visit website or 
# Inside authentication following steps are included
# 1.SignUp   2.Login   3.password hashing    4.Session Management
# Authorization
# Authorization is the procss of granting acess to user
    # for particular route according 


from flask import Flask, render_template,request,redirect,flash,url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_manager,login_user,logout_user,UserMixin,LoginManager, login_required, current_user

app=Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SECRET_KEY"]="welcome"
db=SQLAlchemy(app)

login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view='login'



@app.route("/")
def home():
    return render_template("base.html")


# Usermixin will provided you some additional methods like  |  is_authentiicated()(this will return True if user is logged in)  |  , | is_active()|  , | get_id()(this will return user_id)|    . 
class User(db.Model,UserMixin):
    __tablename__="users"
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(100))
    email=db.Column(db.String(100))
    password_hash=db.Column(db.String(100))
    role=db.Column(db.String(100),default="user")

    # for saving hash password # 123
    def save_hash_password(self,password):
        self.password_hash=generate_password_hash(password)
        # we generating encrypted password here

    def check_hash_password(self,password):
            return check_password_hash(self.password_hash, password)
        # we are return true or false 




@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method=="POST":
         username=request.form.get("username")
         email=request.form.get("email")
         password=request.form.get("password")

         if User.query.filter_by(email=email).first():
              flash("User Alreeady exist")
              return redirect(url_for("home"))

         user_data=User(username=username,email=email)
         user_data.save_hash_password(password)

         db.session.add(user_data)
         db.session.commit()
         flash("User Registered successfully")
         return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method=="POST":
         email=request.form.get("email")
         password=request.form.get("password")

         user_data=User.query.filter_by(email=email).first()

         if user_data and user_data.check_hash_password(password):
            login_user(user_data)   # storing user object in the session.
            flash("User logged in successfully")
            return redirect(url_for("dashboard"))
    return render_template("login.html")


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))  # this will fetch user_id from session and retrive current object from database.


        
@app.route("/dashboard")
@login_required
def dashboard():
     
    return render_template("dashboard.html")

@app.route("/profile")
def profile():
     return render_template("profile.html")


@app.route("/logout")
def logout():
     logout_user()
     flash("User logged Out Successfully")
     return redirect(url_for("home"))



def role_required(role):  # we are passing role here
    def decorater(func):  # here passing admin view function
        def wrap(*args,**kwargs):   # argument of view function
            if current_user.role!=role:   # admin
                flash("Unauthorized Access")
                return redirect(url_for("login"))
            return func(*args,**kwargs)
        return wrap
    return decorater



@app.route("/admin")
@login_required
@role_required("admin")
def admin():
    return render_template("admin.html")



     

with app.app_context():
     db.create_all()
    

     if not User.query.filter_by(role="admin").first():
        admin=User(username="admin",email="admin@gmail.com",role="admin")
        admin.save_hash_password("admin")

        db.session.add(admin)
        db.session.commit()


if __name__=="__main__":
    app.run(debug=True)
