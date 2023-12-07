package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/lib/pq"
)

var (
	tmpl *template.Template
	db   *sql.DB
)

const mysecretkey = "my_secret_key"

type user struct {
	Id        int //`id:id`
	User_name string
	Age       string
	Email     string
	Password  string
	Role      bool
}

// to ask
func init() {
	var err error

	if err = godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
		return
	}

	tmpl, err = template.ParseGlob("templates/*.html")
	if err != nil {
		log.Fatal(err)
		return
	}

	connStr := "user=" + os.Getenv("DB_USER") +
		" password=" + os.Getenv("DB_PASSWORD") +
		" dbname=" + os.Getenv("DB_NAME") +
		" sslmode=" + os.Getenv("DB_SSL_MODE")

	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
		return
	}
}

// middleware for no cache
func noCacheMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		next.ServeHTTP(w, r)
	})
}

// middlewar for user authentication
func userAuthentication(next http.Handler) http.Handler {
	// fmt.Println("*****user auth is working***")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		cookie, err := r.Cookie("user_jwt")
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("invalid signing method")
			}
			return []byte(mysecretkey), nil
		})
		if err != nil || !token.Valid {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// middleware for admin authentication
func adminAuthentication(next http.Handler) http.Handler {
	// fmt.Println("*****amin auth is working****88")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		cookie, err := r.Cookie("admin_jwt")
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("invalid signing method")
			}
			return []byte(mysecretkey), nil
		})
		if err != nil || !token.Valid {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// main function
func main() {

	defer db.Close() //close when the main function exits

	//user side
	http.Handle("/", noCacheMiddleware(http.HandlerFunc(loginPageHandler)))
	http.Handle("/login", noCacheMiddleware(http.HandlerFunc(loginHandler)))
	http.Handle("/home", noCacheMiddleware(userAuthentication(http.HandlerFunc(homePageHandler))))
	http.HandleFunc("/userLogout", userLogout)
	http.Handle("/register", noCacheMiddleware(http.HandlerFunc(userRegisterPage)))
	http.Handle("/userRegister", noCacheMiddleware(http.HandlerFunc(userRegister)))

	//admin side
	http.Handle("/admin", noCacheMiddleware(adminAuthentication(http.HandlerFunc(adminHomePageHandler))))
	http.Handle("/delete/", noCacheMiddleware(adminAuthentication(http.HandlerFunc(deleteUser))))
	http.Handle("/update/", noCacheMiddleware(adminAuthentication(http.HandlerFunc(updateUser))))
	http.Handle("/updateUser/", noCacheMiddleware(adminAuthentication(http.HandlerFunc(updateUserHandler))))
	http.Handle("/search", noCacheMiddleware(adminAuthentication(http.HandlerFunc(search))))
	http.HandleFunc("/adminLogout", adminLogout)

	fmt.Println("function started: ")
	err := http.ListenAndServe(":8080", nil) //uses default serve mux in case of nil handler
	if err != nil {
		fmt.Println("error:", err)
	}
}

// login page handler
func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	err := tmpl.ExecuteTemplate(w, "login.page.html", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// login handler
// *****the user is authenticated, creates a jwt token for each one, checks for admin or user , makes two different cookies with different paths
func loginHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("******Login Handler is working*******")
	u := &user{}

	userEmail := r.FormValue("email")
	userPassword := r.FormValue("password")

	err := db.QueryRow("select username,age,password,role,email from login_user where email = $1", userEmail).Scan(&u.User_name, &u.Age, &u.Password, &u.Role, &u.Email)
	fmt.Println(u)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Println(err)
			err := tmpl.ExecuteTemplate(w, "login.page.html", "user not found")

			if err != nil {
				log.Println(err)
				return
			}
			return
		}
		log.Println(err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if userPassword != u.Password {
		fmt.Println(userEmail, userPassword)
		err := tmpl.ExecuteTemplate(w, "login.page.html", "wrong password/email")

		if err != nil {
			log.Println(err)
			return
		}
		return
	} else {

		claims := jwt.MapClaims{
			"user_name": u.User_name,
			"exp":       time.Now().Add(time.Hour * 1).Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		secretKey := []byte(mysecretkey)

		signedToken, err := token.SignedString(secretKey)

		if err != nil {
			log.Fatal(err)
			http.Error(w, "error in jwt", http.StatusInternalServerError)
			return
		}

		// checking for admin or user
		if !u.Role {

			// fmt.Println("jwt Token", signedToken)
			cookie := http.Cookie{
				Name:     "user_jwt",
				Value:    signedToken,
				Expires:  time.Now().Add(time.Hour * 1),
				HttpOnly: true,
				Path:     "/",
			}
			http.SetCookie(w, &cookie)
			http.Redirect(w, r, "/home", http.StatusSeeOther)
		} else {
			cookie := http.Cookie{
				Name:     "admin_jwt",
				Value:    signedToken,
				Expires:  time.Now().Add(time.Hour * 1),
				HttpOnly: true,
				Path:     "/",
			}
			http.SetCookie(w, &cookie)
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
		}
		// http.Redirect(w, r, "/home", http.StatusSeeOther)
	}

}

// home page handler
func homePageHandler(w http.ResponseWriter, r *http.Request) {
	err := tmpl.ExecuteTemplate(w, "home.page.html", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

//user logout cookie is set to -ve time so it expires

func userLogout(w http.ResponseWriter, r *http.Request) {

	cookie := http.Cookie{
		Name:     "user_jwt",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)

}

//user register page

func userRegisterPage(w http.ResponseWriter, r *http.Request) {
	err := tmpl.ExecuteTemplate(w, "register.page.html", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

//user register

func userRegister(w http.ResponseWriter, r *http.Request) {
	fmt.Println("********the user register handler is working*********")
	user := &user{}

	user.User_name = r.FormValue("user_name")
	user.Email = r.FormValue("email")
	user.Age = r.FormValue("age")
	user.Password = r.FormValue("password")
	// fmt.Println(user)
	if user.User_name != "" && user.Email != "" && user.Age != "" && user.Password != "" {

		var ins *sql.Stmt
		var err error
		ins, err = db.Prepare("INSERT INTO login_user(username,age,email,password) values ($1,$2,$3,$4)")
		if err != nil {
			log.Fatal(err)
			return
		}
		defer ins.Close()

		_, err = ins.Exec(user.User_name, user.Age, user.Email, user.Password)
		if err != nil {
			log.Println(err)
			if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" { //this is code for pq error or postgres error, unique violation
				err := tmpl.ExecuteTemplate(w, "register.page.html", "Username or Email already exists")
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return

		}
		http.Redirect(w, r, "/", http.StatusSeeOther)

	} else {
		err := tmpl.ExecuteTemplate(w, "register.page.html", "Please dont leave any field empty")
		if err != nil {
			log.Fatal(err)
			return
		}
	}
}

// admin Home page handler
func adminHomePageHandler(w http.ResponseWriter, r *http.Request) {

	rows, err := db.Query("SELECT * FROM login_user order by id;")
	if err != nil {
		log.Fatal(err)
		return
	}
	defer rows.Close()
	var users []user
	for rows.Next() {
		var u user
		if err := rows.Scan(&u.Id, &u.User_name, &u.Age, &u.Password, &u.Role, &u.Email); err != nil {
			log.Fatal(err)
			return
		}
		users = append(users, u)
	}
	// var err error
	err = tmpl.ExecuteTemplate(w, "admin.page.html", users)
	if err != nil {
		log.Println(err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

}

//admin delete user handler

func deleteUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("*****delete Handler is working********")

	userId := r.FormValue("idproducts")

	if userId == "" {
		http.Error(w, "Invalid or missing id products", 400)
		return
	}

	_, err := db.Exec("delete from login_user where id = $1", userId)
	if err != nil {
		log.Fatal(err)
		http.Error(w, "Failed ot delete user", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

//update handler

func updateUser(w http.ResponseWriter, r *http.Request) {
	userId := r.URL.Query().Get("idproducts")
	var u user

	rows, err := db.Query("SELECT id,username,age,password,role,email from login_user where id = $1", userId)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer rows.Close()
	if rows.Next() {
		err = rows.Scan(&u.Id, &u.User_name, &u.Age, &u.Password, &u.Role, &u.Email)
		if err != nil {
			log.Fatal(err)
			return
		}
	} else {
		log.Printf("No data found for id %s", userId)
		return
	}
	err = tmpl.ExecuteTemplate(w, "update.page.html", u)
	if err != nil {
		log.Fatal(err)
	}
}

// update user handler
func updateUserHandler(w http.ResponseWriter, r *http.Request) {
	// userId := r.URL.Query().Get("id")

	user := &user{}

	userId := r.FormValue("id")
	var err error
	user.Id, err = strconv.Atoi(userId)
	if err != nil {
		http.Error(w, "invalid ", 400)
		return
	}

	user.Age = r.FormValue("age")
	user.User_name = r.FormValue("user_name")
	user.Email = r.FormValue("email")
	user.Password = r.FormValue("password")
	userRole := (r.FormValue("role"))

	if userRole == "true" {
		user.Role = true
	} else {
		user.Role = false
	}
	// fmt.Println("User:", user, userId)
	_, err = db.Exec("UPDATE login_user SET username = $1 , age = $2 , password = $3 , role = $4, email = $5 where id = $6", user.User_name, user.Age, user.Password, user.Role, user.Email, user.Id)
	if err != nil {
		log.Println("Error:", err)
		// Here, you can add more detailed error messages to help identify the problematic variable.
		// You can also log the values of the variables.
		if strings.Contains(err.Error(), "invalid input syntax for type integer") {
			log.Println("Invalid input for age:", user.Age)
		}
		log.Fatal(err)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// search
func search(w http.ResponseWriter, r *http.Request) {
	fmt.Println("*******search handle is working***")
	keyword := r.FormValue("search")
	fmt.Println(keyword)
	if keyword == "" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	rows, err := db.Query("SELECT * FROM login_user WHERE email LIKE $1 ORDER BY email;", "%"+keyword+"%")
	if err != nil {
		log.Fatal(err)
		return
	}
	defer rows.Close()
	var users []user
	for rows.Next() {
		var u user
		if err := rows.Scan(&u.Id, &u.User_name, &u.Age, &u.Password, &u.Role, &u.Email); err != nil {
			log.Fatal(err)
			return
		}
		users = append(users, u)
	}
	// var err error
	err = tmpl.ExecuteTemplate(w, "admin.page.html", users)
	if err != nil {
		log.Println(err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return

	}
}

func adminLogout(w http.ResponseWriter, r *http.Request) {
	fmt.Println("*******admin logout handler is working*********")
	cookie := http.Cookie{
		Name:     "admin_jwt",
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)

}
