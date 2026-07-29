package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// ── JWT key ────────────────────────────────────────────────────────────────────

var jwtKey = func() []byte {
	if secret := os.Getenv("SESSION_SECRET"); secret != "" {
		return []byte(secret)
	}
	log.Println("WARNING: SESSION_SECRET not set — using insecure fallback JWT key.")
	return []byte("callsync_secret_security_key_2026")
}()

// ── Models ─────────────────────────────────────────────────────────────────────

type User struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Username  string    `gorm:"uniqueIndex;not null" json:"username"`
	Password  string    `gorm:"not null" json:"-"` // SHA-256 hex
	CreatedAt time.Time `json:"created_at"`
}

type Device struct {
	ID             string    `gorm:"primaryKey" json:"id"`
	Name           string    `gorm:"not null" json:"name"`
	AndroidVersion string    `json:"android_version"`
	LastSeen       time.Time `json:"last_seen"`
}

type Recording struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Name         string    `gorm:"not null" json:"name"`
	Size         int64     `gorm:"not null" json:"size"`
	SHA256       string    `gorm:"uniqueIndex;not null" json:"sha256"`
	Duration     float64   `json:"duration"`
	UploadDate   time.Time `json:"upload_date"`
	CreationDate time.Time `json:"creation_date"`
	Path         string    `gorm:"not null" json:"path"`
	DeviceID     string    `gorm:"not null" json:"device_id"`
	Device       Device    `gorm:"foreignKey:DeviceID" json:"device"`
}

// DeleteCommand is posted by the Flutter receiver and polled by the Kotlin recorder.
type DeleteCommand struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	DeviceID  string    `gorm:"index;not null" json:"device_id"`
	SHA256    string    `gorm:"not null" json:"sha256"`
	Done      bool      `gorm:"default:false" json:"done"`
	CreatedAt time.Time `json:"created_at"`
}

var db *gorm.DB

// sha256Hex returns the hex-encoded SHA-256 of a string.
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// ── DB init ────────────────────────────────────────────────────────────────────

func initDB() {
	var err error
	db, err = gorm.Open(sqlite.Open("callsync.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to SQLite database: %v", err)
	}
	if err = db.AutoMigrate(&User{}, &Device{}, &Recording{}, &DeleteCommand{}); err != nil {
		log.Fatalf("Database migration failed: %v", err)
	}

	var userCount int64
	db.Model(&User{}).Count(&userCount)
	if userCount == 0 {
		admin := User{
			Username:  "admin",
			Password:  sha256Hex("admin123"),
			CreatedAt: time.Now(),
		}
		db.Create(&admin)
		log.Println("Seeded default admin: username=admin / password=admin123")
	}
}

// ── JWT ────────────────────────────────────────────────────────────────────────

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func generateToken(username string) (string, error) {
	exp := time.Now().Add(72 * time.Hour)
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtKey)
}

func parseToken(tokenStr string) (*Claims, bool) {
	claims := &Claims{}
	tok, err := jwt.ParseWithClaims(tokenStr, claims, func(_ *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	return claims, err == nil && tok.Valid
}

// ── Helpers ────────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	parts := strings.SplitN(h, " ", 2)
	if len(parts) == 2 && parts[0] == "Bearer" {
		return parts[1], true
	}
	return "", false
}

func getDiskStats(path string) (total, free, used uint64) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0, 0
	}
	total = stat.Blocks * uint64(stat.Bsize)
	free = stat.Bfree * uint64(stat.Bsize)
	used = total - free
	return
}

func storageUsedByRecordings() int64 {
	var total int64
	filepath.Walk("storage", func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total
}

// ── Middleware ─────────────────────────────────────────────────────────────────

type handler func(w http.ResponseWriter, r *http.Request)

func cors(next handler) handler {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers",
			"Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func auth(next handler) handler {
	return cors(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := bearerToken(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Authorization header missing"})
			return
		}
		_, valid := parseToken(tok)
		if !valid {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid or expired JWT token"})
			return
		}
		next(w, r)
	})
}

// ── Router ─────────────────────────────────────────────────────────────────────

type router struct {
	mux *http.ServeMux
}

func (ro *router) get(path string, h handler) {
	ro.mux.HandleFunc("GET "+path, h)
}
func (ro *router) post(path string, h handler) {
	ro.mux.HandleFunc("POST "+path, h)
}
func (ro *router) delete(path string, h handler) {
	ro.mux.HandleFunc("DELETE "+path, h)
}

// pathSuffix extracts the part of the URL path after the prefix.
// e.g. prefix="/record/", path="/record/42" → "42"
func pathSuffix(r *http.Request, prefix string) string {
	return strings.TrimPrefix(r.URL.Path, prefix)
}

// ── Handlers ───────────────────────────────────────────────────────────────────

func handleRoot(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"app":     "CallSync Server",
		"version": "2.2.0",
		"status":  "running",
		"endpoints": []string{
			"GET    /",
			"GET    /health",
			"POST   /login",
			"POST   /upload              (Bearer token)",
			"GET    /records             (Bearer token)",
			"GET    /record/{id}         (Bearer token)",
			"GET    /stream/{id}         (Bearer token)",
			"GET    /download/{id}       (Bearer token)",
			"DELETE /record/{id}         (Bearer token)",
			"DELETE /purge-all           (Bearer token)",
			"GET    /storage/stats       (Bearer token)",
			"POST   /delete-commands     (Bearer token) — queue source-delete commands",
			"GET    /delete-commands/{device_id} — polled by Kotlin recorder",
		},
	})
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	var recCount, devCount int64
	db.Model(&Recording{}).Count(&recCount)
	db.Model(&Device{}).Count(&devCount)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "healthy",
		"version":     "2.2.0",
		"recordings":  recCount,
		"devices":     devCount,
		"server_time": time.Now().UTC().Format(time.RFC3339),
	})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &input); err != nil || input.Username == "" || input.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username and password required"})
		return
	}

	var user User
	if err := db.Where("username = ?", input.Username).First(&user).Error; err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid credentials"})
		return
	}
	if user.Password != sha256Hex(input.Password) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid credentials"})
		return
	}

	token, err := generateToken(user.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to generate token"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(512 << 20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Failed to parse form"})
		return
	}

	phoneID := r.FormValue("phone_id")
	deviceName := r.FormValue("device_name")
	androidVersion := r.FormValue("android_version")
	timestampStr := r.FormValue("timestamp")
	clientSHA256 := r.FormValue("sha256")

	if phoneID == "" || deviceName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Missing required fields: phone_id and device_name"})
		return
	}

	file, fileHeader, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "No file uploaded"})
		return
	}
	defer file.Close()

	// Compute SHA-256
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to compute file hash"})
		return
	}
	computedSHA256 := hex.EncodeToString(hasher.Sum(nil))

	if clientSHA256 != "" && clientSHA256 != computedSHA256 {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":    "SHA256 mismatch — file may be corrupted",
			"expected": clientSHA256,
			"got":      computedSHA256,
		})
		return
	}

	// Upsert device
	device := Device{ID: phoneID, Name: deviceName, AndroidVersion: androidVersion, LastSeen: time.Now()}
	db.Save(&device)

	// Deduplicate
	var existingRecording Recording
	if db.Where("sha256 = ?", computedSHA256).First(&existingRecording).Error == nil {
		writeJSON(w, http.StatusOK, map[string]any{"message": "File already exists (duplicate)", "id": existingRecording.ID})
		return
	}

	// Path safety
	safeFilename := filepath.Base(fileHeader.Filename)
	deviceFolder := filepath.Join("storage", filepath.Clean(phoneID))
	cleaned := filepath.Clean(deviceFolder)
	if !strings.HasPrefix(cleaned, "storage"+string(filepath.Separator)) && cleaned != "storage" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid phone_id"})
		return
	}
	os.MkdirAll(deviceFolder, 0755)
	targetPath := filepath.Join(deviceFolder, safeFilename)

	// Rewind file and write to disk
	if seeker, ok := file.(io.Seeker); ok {
		seeker.Seek(0, io.SeekStart)
	}
	out, err := os.Create(targetPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to create file on disk"})
		return
	}
	defer out.Close()
	if _, err := io.Copy(out, file); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to write file to disk"})
		return
	}

	creationTime := time.Now()
	if timestampStr != "" {
		if ms, err := strconv.ParseInt(timestampStr, 10, 64); err == nil {
			creationTime = time.Unix(ms/1000, (ms%1000)*1000000)
		}
	}

	recording := Recording{
		Name:         safeFilename,
		Size:         fileHeader.Size,
		SHA256:       computedSHA256,
		UploadDate:   time.Now(),
		CreationDate: creationTime,
		Path:         targetPath,
		DeviceID:     phoneID,
	}
	if err := db.Create(&recording).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to save recording metadata"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"message": "Upload successful",
		"id":      recording.ID,
		"sha256":  computedSHA256,
		"size":    fileHeader.Size,
	})
}

func handleRecords(w http.ResponseWriter, r *http.Request) {
	var recordings []Recording
	if err := db.Preload("Device").Order("creation_date DESC").Find(&recordings).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to fetch recordings"})
		return
	}
	writeJSON(w, http.StatusOK, recordings)
}

func handleRecordByID(w http.ResponseWriter, r *http.Request) {
	id := pathSuffix(r, "/record/")
	var rec Recording
	if err := db.Preload("Device").First(&rec, id).Error; err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Recording not found"})
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func handleStream(w http.ResponseWriter, r *http.Request) {
	id := pathSuffix(r, "/stream/")
	var rec Recording
	if err := db.First(&rec, id).Error; err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Recording not found"})
		return
	}
	if _, err := os.Stat(rec.Path); os.IsNotExist(err) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Audio file missing from disk"})
		return
	}

	ext := strings.ToLower(filepath.Ext(rec.Name))
	contentType := "audio/mpeg"
	switch ext {
	case ".m4a":
		contentType = "audio/mp4"
	case ".wav":
		contentType = "audio/wav"
	case ".ogg":
		contentType = "audio/ogg"
	case ".amr":
		contentType = "audio/amr"
	case ".3gp":
		contentType = "video/3gpp"
	case ".aac":
		contentType = "audio/aac"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Accept-Ranges", "bytes")
	http.ServeFile(w, r, rec.Path)
}

func handleDownload(w http.ResponseWriter, r *http.Request) {
	id := pathSuffix(r, "/download/")
	var rec Recording
	if err := db.First(&rec, id).Error; err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Recording not found"})
		return
	}
	if _, err := os.Stat(rec.Path); os.IsNotExist(err) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Audio file missing from disk"})
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, rec.Name))
	w.Header().Set("Content-Transfer-Encoding", "binary")
	http.ServeFile(w, r, rec.Path)
}

func handleDeleteRecord(w http.ResponseWriter, r *http.Request) {
	id := pathSuffix(r, "/record/")
	var rec Recording
	if err := db.First(&rec, id).Error; err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Recording not found"})
		return
	}
	if err := db.Delete(&rec).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to delete recording"})
		return
	}
	if err := os.Remove(rec.Path); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: could not remove file %s: %v", rec.Path, err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"message": "Recording deleted", "id": id, "name": rec.Name})
}

func handlePurgeAll(w http.ResponseWriter, r *http.Request) {
	var recordings []Recording
	if err := db.Find(&recordings).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to fetch recordings for purge"})
		return
	}

	deleted, errors := 0, 0
	for _, rec := range recordings {
		if err := os.Remove(rec.Path); err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: could not remove file %s: %v", rec.Path, err)
			errors++
		}
		if err := db.Delete(&rec).Error; err != nil {
			log.Printf("Warning: could not delete DB record %d: %v", rec.ID, err)
			errors++
		} else {
			deleted++
		}
	}

	// Clean up empty device folders
	filepath.Walk("storage", func(path string, info os.FileInfo, err error) error {
		if err == nil && info.IsDir() && path != "storage" {
			entries, _ := os.ReadDir(path)
			if len(entries) == 0 {
				os.Remove(path)
			}
		}
		return nil
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"message": "Purge complete",
		"deleted": deleted,
		"errors":  errors,
		"total":   len(recordings),
	})
}

func handleStorageStats(w http.ResponseWriter, r *http.Request) {
	var recCount, totalSize int64
	db.Model(&Recording{}).Count(&recCount)
	db.Model(&Recording{}).Select("COALESCE(SUM(size), 0)").Scan(&totalSize)

	diskTotal, diskFree, diskUsed := getDiskStats("storage")
	recordingsUsed := storageUsedByRecordings()

	writeJSON(w, http.StatusOK, map[string]any{
		"recordings":       recCount,
		"recordings_bytes": recordingsUsed,
		"disk_total":       diskTotal,
		"disk_free":        diskFree,
		"disk_used":        diskUsed,
		"db_total_size":    totalSize,
	})
}

// POST /delete-commands — Flutter receiver queues commands.
// Body: { "device_id": "...", "sha256_list": ["...", "..."] }
func handlePostDeleteCommands(w http.ResponseWriter, r *http.Request) {
	var input struct {
		DeviceID   string   `json:"device_id"`
		SHA256List []string `json:"sha256_list"`
	}
	if err := readJSON(r, &input); err != nil || input.DeviceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device_id and sha256_list required"})
		return
	}

	queued := 0
	for _, h := range input.SHA256List {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		// Deduplicate: only insert if not already pending
		var existing DeleteCommand
		if db.Where("device_id = ? AND sha256 = ? AND done = ?", input.DeviceID, h, false).
			First(&existing).Error != nil {
			db.Create(&DeleteCommand{DeviceID: input.DeviceID, SHA256: h, CreatedAt: time.Now()})
			queued++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"message": "Commands queued",
		"queued":  queued,
	})
}

// GET /delete-commands/{device_id} — Kotlin recorder polls this.
// Returns pending sha256 list, marks them done immediately.
func handleGetDeleteCommands(w http.ResponseWriter, r *http.Request) {
	deviceID := pathSuffix(r, "/delete-commands/")
	if deviceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device_id required"})
		return
	}

	var cmds []DeleteCommand
	db.Where("device_id = ? AND done = ?", deviceID, false).Find(&cmds)

	hashes := make([]string, 0, len(cmds))
	for _, c := range cmds {
		hashes = append(hashes, c.SHA256)
	}

	// Mark all as done
	if len(cmds) > 0 {
		db.Model(&DeleteCommand{}).
			Where("device_id = ? AND done = ?", deviceID, false).
			Update("done", true)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"device_id":   deviceID,
		"sha256_list": hashes,
		"count":       len(hashes),
	})
}

// only wraps a handler to enforce a single HTTP method (Go 1.21 compatible).
// OPTIONS is always allowed for CORS preflight.
func only(method string, h handler) handler {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			cors(func(w http.ResponseWriter, _ *http.Request) {})(w, r)
			return
		}
		if r.Method != method {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		h(w, r)
	}
}

// ── Main ───────────────────────────────────────────────────────────────────────

func main() {
	initDB()
	os.MkdirAll("storage", 0755)

	mux := http.NewServeMux()

	// Public routes — path-only registration (Go 1.21 compatible)
	mux.HandleFunc("/", cors(handleRoot))
	mux.HandleFunc("/health", cors(only(http.MethodGet, handleHealth)))
	mux.HandleFunc("/login", cors(only(http.MethodPost, handleLogin)))

	// GET /delete-commands/{device_id} — no auth (Kotlin poller)
	// NOTE: must be registered before /delete-commands (exact vs prefix)
	mux.HandleFunc("/delete-commands/", cors(only(http.MethodGet, handleGetDeleteCommands)))

	// Protected routes
	mux.HandleFunc("/upload", only(http.MethodPost, auth(handleUpload)))
	mux.HandleFunc("/records", only(http.MethodGet, auth(handleRecords)))

	// /record/{id} — GET and DELETE
	mux.HandleFunc("/record/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			auth(handleRecordByID)(w, r)
		case http.MethodDelete:
			auth(handleDeleteRecord)(w, r)
		case http.MethodOptions:
			cors(func(w http.ResponseWriter, r *http.Request) {})(w, r)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	})

	mux.HandleFunc("/stream/", only(http.MethodGet, auth(handleStream)))
	mux.HandleFunc("/download/", only(http.MethodGet, auth(handleDownload)))
	mux.HandleFunc("/purge-all", only(http.MethodDelete, auth(handlePurgeAll)))
	mux.HandleFunc("/storage/stats", only(http.MethodGet, auth(handleStorageStats)))
	mux.HandleFunc("/delete-commands", only(http.MethodPost, auth(handlePostDeleteCommands)))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("CallSync Server v2.2 starting on :%s (net/http • sha256 auth • no gin)", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
