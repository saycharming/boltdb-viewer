package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/bcrypt"
)

var (
	db             *bolt.DB
	templates      *template.Template
	bucketsPerPage = 10
	recordsPerPage = 10 // Show 10 records per page
	dbPath         string

	// sessions stores session_token => username mapping (in-memory)
	sessions     = make(map[string]string)
	sessionMutex sync.Mutex
)

const sessionCookieName = "session_token"

func main() {
	// Get the user's home directory.
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Failed to get home directory: %v", err)
	}
	// Construct the full path to your BoltDB file.
	dbPath = filepath.Join(homeDir, ".fewchoreapi", "db")

	// Open the BoltDB file with a timeout.
	db, err = bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Fatalf("Failed to open BoltDB file at %s: %v", dbPath, err)
	}
	defer db.Close()

	// Initialize users bucket and default admin if not exists.
	err = db.Update(func(tx *bolt.Tx) error {
		usersBucket, err := tx.CreateBucketIfNotExists([]byte("users"))
		if err != nil {
			return err
		}
		// If "admin" doesn't exist, create it with default password "admin".
		// IMPORTANT: For production, change the default password immediately.
		if usersBucket.Get([]byte("admin")) == nil {
			hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
			if err != nil {
				return err
			}
			log.Println("Default admin user created with password 'admin'. Change this immediately for production!")
			return usersBucket.Put([]byte("admin"), hash)
		}
		return nil
	})
	if err != nil {
		log.Fatalf("Error initializing users: %v", err)
	}

	// Parse embedded templates.
	initTemplates()

	// Set up HTTP endpoints (with authentication middleware applied to all protected routes).
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", authMiddleware(logoutHandler))
	http.HandleFunc("/reset-password", authMiddleware(resetPasswordHandler))
	http.HandleFunc("/export", authMiddleware(exportHandler))

	// Protected endpoints.
	http.HandleFunc("/", authMiddleware(homeHandler))
	http.HandleFunc("/bucket", authMiddleware(bucketHandler))
	http.HandleFunc("/bucket/edit", authMiddleware(bucketEditHandler))
	http.HandleFunc("/bucket/delete", authMiddleware(bucketDeleteHandler))

	// Serve static files (if needed, e.g., custom CSS or JS).
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	fmt.Println("BoltDB viewer running on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

// initTemplates parses our embedded HTML templates.
func initTemplates() {
	funcMap := template.FuncMap{
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
		"until": func(count int) []int {
			s := make([]int, count)
			for i := 0; i < count; i++ {
				s[i] = i
			}
			return s
		},
	}
	templates = template.Must(template.New("t").Funcs(funcMap).Parse(
		loginTemplate + homeTemplate + bucketTemplate + editTemplate + resetPasswordTemplate + exportTemplate,
	))
}

// authMiddleware protects routes that require authentication.
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || cookie.Value == "" || !isValidSession(cookie.Value) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// isValidSession checks if a session token is valid.
func isValidSession(token string) bool {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	_, ok := sessions[token]
	return ok
}

// generateSessionToken creates a random session token.
func generateSessionToken() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// loginHandler renders and processes the login form.
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "login", nil)
		return
	}

	// Process POST login.
	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" || password == "" {
		http.Error(w, "Username and password required", http.StatusBadRequest)
		return
	}

	// Validate credentials from BoltDB "users" bucket.
	var storedHash []byte
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		if b == nil {
			return fmt.Errorf("users bucket not found")
		}
		storedHash = b.Get([]byte(username))
		if storedHash == nil {
			return fmt.Errorf("invalid credentials")
		}
		return nil
	})
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	// Compare provided password with stored hash.
	if err = bcrypt.CompareHashAndPassword(storedHash, []byte(password)); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Credentials valid, generate session token.
	token, err := generateSessionToken()
	if err != nil {
		http.Error(w, "Failed to generate session token", http.StatusInternalServerError)
		return
	}
	sessionMutex.Lock()
	sessions[token] = username
	sessionMutex.Unlock()

	// Set secure session cookie.
	cookie := http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		HttpOnly: true,
		// Secure: true, // Uncomment when using HTTPS.
		Path: "/",
	}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// logoutHandler clears the session.
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		sessionMutex.Lock()
		delete(sessions, cookie.Value)
		sessionMutex.Unlock()
		// Clear the cookie.
		http.SetCookie(w, &http.Cookie{
			Name:   sessionCookieName,
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// resetPasswordHandler allows an authenticated user to change their password.
func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "reset", nil)
		return
	}

	// Process POST reset.
	username := getUsernameFromSession(r)
	oldPassword := r.FormValue("old_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	if newPassword == "" || newPassword != confirmPassword {
		http.Error(w, "Passwords do not match or are empty", http.StatusBadRequest)
		return
	}

	// Validate old password.
	var storedHash []byte
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		if b == nil {
			return fmt.Errorf("users bucket not found")
		}
		storedHash = b.Get([]byte(username))
		if storedHash == nil {
			return fmt.Errorf("user not found")
		}
		return nil
	})
	if err != nil {
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}

	if err = bcrypt.CompareHashAndPassword(storedHash, []byte(oldPassword)); err != nil {
		http.Error(w, "Old password incorrect", http.StatusUnauthorized)
		return
	}

	// Hash new password and store it.
	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing new password", http.StatusInternalServerError)
		return
	}
	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		if b == nil {
			return fmt.Errorf("users bucket not found")
		}
		return b.Put([]byte(username), newHash)
	})
	if err != nil {
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// exportHandler provides options to export the database.
func exportHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "export", nil)
		return
	}
	// Process export request.
	exportType := r.FormValue("type")
	if exportType == "json" {
		exportDBAsJSON(w, r)
		return
	} else if exportType == "db" {
		// Serve the raw .db file.
		http.ServeFile(w, r, dbPath)
		return
	}
	http.Error(w, "Unknown export type", http.StatusBadRequest)
}

// exportDBAsJSON exports all buckets and key–value pairs as JSON.
func exportDBAsJSON(w http.ResponseWriter, r *http.Request) {
	exportData := make(map[string]map[string]string)
	err := db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(bucketName []byte, b *bolt.Bucket) error {
			bucketData := make(map[string]string)
			c := b.Cursor()
			for k, v := c.First(); k != nil; k, v = c.Next() {
				bucketData[string(k)] = string(v)
			}
			exportData[string(bucketName)] = bucketData
			return nil
		})
	})
	if err != nil {
		http.Error(w, "Error exporting DB: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(exportData)
}

// getUsernameFromSession retrieves the username associated with the session.
func getUsernameFromSession(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	return sessions[cookie.Value]
}

// homeHandler lists all buckets with pagination.
func homeHandler(w http.ResponseWriter, r *http.Request) {
	page := getPageParam(r, "page")

	var buckets []string
	err := db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			// Exclude internal buckets such as "users"
			if string(name) == "users" {
				return nil
			}
			buckets = append(buckets, string(name))
			return nil
		})
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	totalBuckets := len(buckets)
	start, end := paginate(totalBuckets, page, bucketsPerPage)
	pagedBuckets := buckets[start:end]

	data := struct {
		Buckets     []string
		CurrentPage int
		TotalPages  int
	}{
		Buckets:     pagedBuckets,
		CurrentPage: page,
		TotalPages:  (totalBuckets + bucketsPerPage - 1) / bucketsPerPage,
	}
	templates.ExecuteTemplate(w, "home", data)
}

// bucketHandler shows records for a given bucket with search and pagination.
func bucketHandler(w http.ResponseWriter, r *http.Request) {
	bucketName := r.URL.Query().Get("name")
	if bucketName == "" {
		http.Error(w, "Bucket name is required as query parameter 'name'", http.StatusBadRequest)
		return
	}
	page := getPageParam(r, "page")
	searchQuery := r.URL.Query().Get("q")

	var records []map[string]string
	totalRecords := 0
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			return fmt.Errorf("bucket %s not found", bucketName)
		}
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			// If a search query is provided, filter records.
			if searchQuery != "" && !contains(string(k), searchQuery) && !contains(string(v), searchQuery) {
				continue
			}
			totalRecords++
			// Only include records for the current page.
			if totalRecords > (page-1)*recordsPerPage && totalRecords <= page*recordsPerPage {
				records = append(records, map[string]string{
					"key":   hex.EncodeToString(k), // display key as hex
					"value": string(v),
				})
			}
		}
		return nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	totalPages := (totalRecords + recordsPerPage - 1) / recordsPerPage
	data := struct {
		BucketName  string
		Records     []map[string]string
		CurrentPage int
		TotalPages  int
		SearchQuery string
	}{
		BucketName:  bucketName,
		Records:     records,
		CurrentPage: page,
		TotalPages:  totalPages,
		SearchQuery: searchQuery,
	}
	templates.ExecuteTemplate(w, "bucket", data)
}

// bucketEditHandler handles showing the edit form (GET) and processing the update (POST).
func bucketEditHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		bucketName := r.URL.Query().Get("bucket")
		keyHex := r.URL.Query().Get("key")
		if bucketName == "" || keyHex == "" {
			http.Error(w, "Bucket name and key are required", http.StatusBadRequest)
			return
		}
		decodedKey, err := hex.DecodeString(keyHex)
		if err != nil {
			http.Error(w, "Invalid key format", http.StatusBadRequest)
			return
		}
		var value string
		err = db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(bucketName))
			if b == nil {
				return fmt.Errorf("bucket %s not found", bucketName)
			}
			v := b.Get(decodedKey)
			if v == nil {
				return fmt.Errorf("key %s not found in bucket %s", keyHex, bucketName)
			}
			value = string(v)
			return nil
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		data := struct {
			Bucket string
			Key    string
			Value  string
		}{
			Bucket: bucketName,
			Key:    keyHex,
			Value:  value,
		}
		templates.ExecuteTemplate(w, "edit", data)
	} else if r.Method == http.MethodPost {
		bucketName := r.FormValue("bucket")
		keyHex := r.FormValue("key")
		newValue := r.FormValue("value")
		if bucketName == "" || keyHex == "" {
			http.Error(w, "Bucket name and key are required", http.StatusBadRequest)
			return
		}
		decodedKey, err := hex.DecodeString(keyHex)
		if err != nil {
			http.Error(w, "Invalid key format", http.StatusBadRequest)
			return
		}
		err = db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(bucketName))
			if b == nil {
				return fmt.Errorf("bucket %s not found", bucketName)
			}
			return b.Put(decodedKey, []byte(newValue))
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("/bucket?name=%s", bucketName), http.StatusSeeOther)
	}
}

// bucketDeleteHandler deletes a key-value pair from a bucket.
func bucketDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	bucketName := r.FormValue("bucket")
	keyHex := r.FormValue("key")
	if bucketName == "" || keyHex == "" {
		http.Error(w, "Bucket name and key are required", http.StatusBadRequest)
		return
	}
	decodedKey, err := hex.DecodeString(keyHex)
	if err != nil {
		http.Error(w, "Invalid key format", http.StatusBadRequest)
		return
	}
	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			return fmt.Errorf("bucket %s not found", bucketName)
		}
		return b.Delete(decodedKey)
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/bucket?name=%s", bucketName), http.StatusSeeOther)
}

// getPageParam returns the page number from the URL query (default is 1).
func getPageParam(r *http.Request, param string) int {
	page := 1
	if p, err := strconv.Atoi(r.URL.Query().Get(param)); err == nil && p > 0 {
		page = p
	}
	return page
}

// paginate returns the start and end indices for slicing.
func paginate(total, page, perPage int) (int, int) {
	start := (page - 1) * perPage
	end := start + perPage
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}
	return start, end
}

// contains checks if needle is in haystack (case-sensitive).
func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}

// (Optional) API endpoint to get raw JSON of buckets.
func apiBucketsHandler(w http.ResponseWriter, r *http.Request) {
	var buckets []string
	err := db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			buckets = append(buckets, string(name))
			return nil
		})
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(buckets)
}

//
// Embedded HTML Templates
//

const loginTemplate = `
{{define "login"}}
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>BoltDB Viewer - Login</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
</head>
<body>
<div class="container my-4">
  <h1>Login</h1>
  <form method="post" action="/login">
    <div class="mb-3">
      <label class="form-label">Username</label>
      <input type="text" class="form-control" name="username" required>
    </div>
    <div class="mb-3">
      <label class="form-label">Password</label>
      <input type="password" class="form-control" name="password" required>
    </div>
    <button type="submit" class="btn btn-primary">Login</button>
  </form>
</div>
</body>
</html>
{{end}}
`

const homeTemplate = `
{{define "home"}}
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>BoltDB Viewer - Buckets</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
</head>
<body>
<div class="container my-4">
  <div class="d-flex justify-content-between">
    <h1>BoltDB Buckets</h1>
    <div>
      <a class="btn btn-secondary" href="/export">Export DB</a>
      <a class="btn btn-secondary" href="/reset-password">Reset Password</a>
      <a class="btn btn-secondary" href="/logout">Logout</a>
    </div>
  </div>
  <table class="table table-bordered table-hover">
    <thead class="table-light">
      <tr>
        <th>Bucket Name</th>
        <th>Action</th>
      </tr>
    </thead>
    <tbody>
      {{range .Buckets}}
      <tr>
        <td>{{.}}</td>
        <td><a class="btn btn-sm btn-primary" href="/bucket?name={{.}}">Browse</a></td>
      </tr>
      {{end}}
    </tbody>
  </table>
  <nav>
    <ul class="pagination">
      {{if gt .CurrentPage 1}}
      <li class="page-item">
        <a class="page-link" href="/?page={{sub .CurrentPage 1}}">&laquo; Prev</a>
      </li>
      {{end}}
      {{range $i := until .TotalPages}}
      <li class="page-item {{if eq (add $i 1) $.CurrentPage}}active{{end}}">
        <a class="page-link" href="/?page={{add $i 1}}">{{add $i 1}}</a>
      </li>
      {{end}}
      {{if lt .CurrentPage .TotalPages}}
      <li class="page-item">
        <a class="page-link" href="/?page={{add .CurrentPage 1}}">Next &raquo;</a>
      </li>
      {{end}}
    </ul>
  </nav>
</div>
</body>
</html>
{{end}}
`

const bucketTemplate = `
{{define "bucket"}}
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>BoltDB Viewer - Bucket {{.BucketName}}</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
</head>
<body>
<div class="container my-4">
  <div class="d-flex justify-content-between">
    <h1>Bucket: {{.BucketName}}</h1>
    <div>
      <a class="btn btn-secondary" href="/export">Export DB</a>
      <a class="btn btn-secondary" href="/reset-password">Reset Password</a>
      <a class="btn btn-secondary" href="/logout">Logout</a>
    </div>
  </div>
  <form class="row g-3 mb-4" method="get" action="/bucket">
    <input type="hidden" name="name" value="{{.BucketName}}">
    <div class="col-auto">
      <input type="text" class="form-control" name="q" placeholder="Search..." value="{{.SearchQuery}}">
    </div>
    <div class="col-auto">
      <button type="submit" class="btn btn-secondary mb-3">Search</button>
    </div>
  </form>
  <table class="table table-bordered table-hover">
    <thead class="table-light">
      <tr>
        <th>Key (hex)</th>
        <th>Value</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
      {{range .Records}}
      <tr>
        <td>{{.key}}</td>
        <td>{{.value}}</td>
        <td>
          <a class="btn btn-sm btn-warning" href="/bucket/edit?bucket={{$.BucketName}}&key={{.key}}">Edit</a>
          <form method="post" action="/bucket/delete" style="display:inline-block;" onsubmit="return confirm('Delete key {{.key}}?');">
            <input type="hidden" name="bucket" value="{{$.BucketName}}">
            <input type="hidden" name="key" value="{{.key}}">
            <button type="submit" class="btn btn-sm btn-danger">Delete</button>
          </form>
        </td>
      </tr>
      {{end}}
    </tbody>
  </table>
  <nav>
    <ul class="pagination">
      {{if gt .CurrentPage 1}}
      <li class="page-item">
        <a class="page-link" href="/bucket?name={{.BucketName}}&page={{sub .CurrentPage 1}}&q={{.SearchQuery}}">&laquo; Prev</a>
      </li>
      {{end}}
      {{range $i := until .TotalPages}}
      <li class="page-item {{if eq (add $i 1) $.CurrentPage}}active{{end}}">
        <a class="page-link" href="/bucket?name={{$.BucketName}}&page={{add $i 1}}&q={{$.SearchQuery}}">{{add $i 1}}</a>
      </li>
      {{end}}
      {{if lt .CurrentPage .TotalPages}}
      <li class="page-item">
        <a class="page-link" href="/bucket?name={{.BucketName}}&page={{add .CurrentPage 1}}&q={{.SearchQuery}}">Next &raquo;</a>
      </li>
      {{end}}
    </ul>
  </nav>
  <a class="btn btn-secondary mt-3" href="/">Back to Buckets</a>
</div>
</body>
</html>
{{end}}
`

const editTemplate = `
{{define "edit"}}
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Edit Entry - Bucket {{.Bucket}}</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
</head>
<body>
<div class="container my-4">
  <h1>Edit Entry</h1>
  <form method="post" action="/bucket/edit">
    <input type="hidden" name="bucket" value="{{.Bucket}}">
    <div class="mb-3">
      <label class="form-label">Key (hex)</label>
      <input type="text" class="form-control" name="key" value="{{.Key}}" readonly>
    </div>
    <div class="mb-3">
      <label class="form-label">Value</label>
      <textarea class="form-control" name="value" rows="5">{{.Value}}</textarea>
    </div>
    <button type="submit" class="btn btn-primary">Save Changes</button>
    <a class="btn btn-secondary" href="/bucket?name={{.Bucket}}">Cancel</a>
  </form>
</div>
</body>
</html>
{{end}}
`

const resetPasswordTemplate = `
{{define "reset"}}
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Reset Password</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
</head>
<body>
<div class="container my-4">
  <h1>Reset Password</h1>
  <form method="post" action="/reset-password">
    <div class="mb-3">
      <label class="form-label">Old Password</label>
      <input type="password" class="form-control" name="old_password" required>
    </div>
    <div class="mb-3">
      <label class="form-label">New Password</label>
      <input type="password" class="form-control" name="new_password" required>
    </div>
    <div class="mb-3">
      <label class="form-label">Confirm New Password</label>
      <input type="password" class="form-control" name="confirm_password" required>
    </div>
    <button type="submit" class="btn btn-primary">Change Password</button>
    <a class="btn btn-secondary" href="/">Cancel</a>
  </form>
</div>
</body>
</html>
{{end}}
`

const exportTemplate = `
{{define "export"}}
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Export Database</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
</head>
<body>
<div class="container my-4">
  <h1>Export Database</h1>
  <form method="post" action="/export">
    <div class="mb-3">
      <label class="form-label">Choose Export Type</label>
      <select class="form-select" name="type">
        <option value="json">JSON</option>
        <option value="db">Raw .db File</option>
      </select>
    </div>
    <button type="submit" class="btn btn-primary">Export</button>
    <a class="btn btn-secondary" href="/">Cancel</a>
  </form>
</div>
</body>
</html>
{{end}}
`
