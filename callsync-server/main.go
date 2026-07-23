package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var jwtKey = func() []byte {
	if secret := os.Getenv("SESSION_SECRET"); secret != "" {
		return []byte(secret)
	}
	return []byte("callsync_secret_security_key_2026")
}()

// ── Models ────────────────────────────────────────────────────────────────────

type User struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Username  string    `gorm:"uniqueIndex;not null" json:"username"`
	Password  string    `gorm:"not null" json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

type Device struct {
	ID             string    `gorm:"primaryKey" json:"id"`
	Name           string    `gorm:"not null" json:"name"`
	AndroidVersion string    `json:"android_version"`
	LastSeen       time.Time `json:"last_seen"`
}

type Recording struct {
	ID              uint      `gorm:"primaryKey" json:"id"`
	Name            string    `gorm:"not null" json:"name"`
	Size            int64     `gorm:"not null" json:"size"`
	SHA256          string    `gorm:"uniqueIndex;not null" json:"sha256"`
	Duration        float64   `json:"duration"`
	UploadDate      time.Time `json:"upload_date"`
	CreationDate    time.Time `json:"creation_date"`
	Path            string    `gorm:"not null" json:"path"`
	DeviceID        string    `gorm:"not null" json:"device_id"`
	Device          Device    `gorm:"foreignKey:DeviceID" json:"device"`
	TelegramMsgID   int64     `json:"telegram_msg_id,omitempty"`
	TelegramFileID  string    `json:"telegram_file_id,omitempty"`
	TelegramBacked  bool      `gorm:"default:false" json:"telegram_backed"`
}

var db *gorm.DB

// ── Database ──────────────────────────────────────────────────────────────────

func initDB() {
	var err error
	db, err = gorm.Open(sqlite.Open("callsync.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to SQLite database: %v", err)
	}

	err = db.AutoMigrate(&User{}, &Device{}, &Recording{})
	if err != nil {
		log.Fatalf("Database migration failed: %v", err)
	}

	var userCount int64
	db.Model(&User{}).Count(&userCount)
	if userCount == 0 {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("Failed to hash default admin password: %v", err)
		}
		admin := User{
			Username:  "admin",
			Password:  string(hashedPassword),
			CreatedAt: time.Now(),
		}
		db.Create(&admin)
		log.Println("Seeded default admin user: username=admin, password=admin123")
	}
}

// ── Telegram Backup ───────────────────────────────────────────────────────────

type tgSendDocumentResp struct {
	OK     bool `json:"ok"`
	Result struct {
		MessageID int64 `json:"message_id"`
		Document  struct {
			FileID string `json:"file_id"`
		} `json:"document"`
		Audio struct {
			FileID string `json:"file_id"`
		} `json:"audio"`
	} `json:"result"`
}

// doBackupToTelegram performs the actual Telegram upload synchronously.
// Returns true on success. Called either in a goroutine (upload path) or
// directly in the retry loop (sequential, rate-limited).
func doBackupToTelegram(rec Recording, botToken, chatID string) bool {
	f, err := os.Open(rec.Path)
	if err != nil {
		log.Printf("[Telegram backup] cannot open %s: %v", rec.Path, err)
		return false
	}
	defer f.Close()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	_ = w.WriteField("chat_id", chatID)
	caption := fmt.Sprintf(
		"📞 *%s*\n📱 Device: %s\n📅 %s\n💾 %.1f KB\n🔑 `%s`",
		rec.Name,
		rec.DeviceID,
		rec.CreationDate.Format("2006-01-02 15:04"),
		float64(rec.Size)/1024,
		rec.SHA256[:16],
	)
	_ = w.WriteField("caption", caption)
	_ = w.WriteField("parse_mode", "Markdown")

	part, err := w.CreateFormFile("document", rec.Name)
	if err != nil {
		log.Printf("[Telegram backup] multipart create error: %v", err)
		return false
	}
	if _, err = io.Copy(part, f); err != nil {
		log.Printf("[Telegram backup] copy error: %v", err)
		return false
	}
	w.Close()

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", botToken)
	resp, err := http.Post(url, w.FormDataContentType(), &buf)
	if err != nil {
		log.Printf("[Telegram backup] HTTP error: %v", err)
		return false
	}
	defer resp.Body.Close()

	var tgResp tgSendDocumentResp
	if err := json.NewDecoder(resp.Body).Decode(&tgResp); err != nil {
		log.Printf("[Telegram backup] decode error: %v", err)
		return false
	}

	if !tgResp.OK {
		log.Printf("[Telegram backup] Telegram API error for recording %d", rec.ID)
		return false
	}

	fileID := tgResp.Result.Document.FileID
	if fileID == "" {
		fileID = tgResp.Result.Audio.FileID
	}

	db.Model(&Recording{}).Where("id = ?", rec.ID).Updates(map[string]interface{}{
		"telegram_msg_id":  tgResp.Result.MessageID,
		"telegram_file_id": fileID,
		"telegram_backed":  true,
	})

	log.Printf("[Telegram backup] ✅ Recording %d (%s) backed up — msg_id=%d",
		rec.ID, rec.Name, tgResp.Result.MessageID)
	return true
}

// backupToTelegram sends the audio file to Telegram asynchronously (non-blocking upload path).
// Requires env vars: TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
func backupToTelegram(recording *Recording) {
	botToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	chatID := os.Getenv("TELEGRAM_CHAT_ID")
	if botToken == "" || chatID == "" {
		return // Telegram backup not configured — silently skip
	}
	rec := *recording // copy so goroutine has its own value
	go func() {
		doBackupToTelegram(rec, botToken, chatID)
	}()
}

// retryTelegramBackups retries any recording that wasn't backed up yet.
// Runs sequentially with a 2-second delay between each to avoid Telegram flood limits.
// Called at server start and every 10 minutes.
func retryTelegramBackups() {
	botToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	chatID := os.Getenv("TELEGRAM_CHAT_ID")
	if botToken == "" || chatID == "" {
		return
	}

	go func() {
		// Wait for the server to fully start before first retry
		time.Sleep(30 * time.Second)
		for {
			var pending []Recording
			db.Where("telegram_backed = ? OR telegram_backed IS NULL", false).Find(&pending)
			if len(pending) > 0 {
				log.Printf("[Telegram backup] Retrying %d un-backed recordings…", len(pending))
				for i := range pending {
					// Sequential + rate-limited: wait for each upload to finish
					// before starting the next to avoid flooding Telegram.
					doBackupToTelegram(pending[i], botToken, chatID)
					time.Sleep(2 * time.Second)
				}
			}
			time.Sleep(10 * time.Minute)
		}
	}()
}

// ── JWT ───────────────────────────────────────────────────────────────────────

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func generateToken(username string) (string, error) {
	expirationTime := time.Now().Add(72 * time.Hour)
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// ── Middleware ────────────────────────────────────────────────────────────────

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header format"})
			c.Abort()
			return
		}

		tokenString := parts[1]
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired JWT token"})
			c.Abort()
			return
		}

		c.Set("username", claims.Username)
		c.Next()
	}
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}

// ── Disk stats ────────────────────────────────────────────────────────────────

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

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	initDB()
	os.MkdirAll("storage", 0755)
	retryTelegramBackups()

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())
	r.SetTrustedProxies(nil)
	r.Use(corsMiddleware())

	// ── Public routes ─────────────────────────────────────────────────────────

	r.GET("/", func(c *gin.Context) {
		telegramConfigured := os.Getenv("TELEGRAM_BOT_TOKEN") != "" && os.Getenv("TELEGRAM_CHAT_ID") != ""
		c.JSON(http.StatusOK, gin.H{
			"app":                "CallSync Server",
			"version":            "2.1.0",
			"status":             "running",
			"telegram_backup":    telegramConfigured,
			"endpoints": []string{
				"GET    /health",
				"POST   /login",
				"POST   /upload              (Bearer token)",
				"GET    /records             (Bearer token)",
				"GET    /record/:id          (Bearer token)",
				"GET    /stream/:id          (Bearer token)",
				"GET    /download/:id        (Bearer token)",
				"DELETE /record/:id          (Bearer token)",
				"DELETE /purge-all           (Bearer token)",
				"GET    /storage/stats       (Bearer token)",
				"GET    /backup/status       (Bearer token) — Telegram backup status",
				"POST   /backup/retry        (Bearer token) — retry failed backups",
			},
		})
	})

	r.GET("/health", func(c *gin.Context) {
		var recCount, devCount int64
		var backedCount int64
		db.Model(&Recording{}).Count(&recCount)
		db.Model(&Device{}).Count(&devCount)
		db.Model(&Recording{}).Where("telegram_backed = ?", true).Count(&backedCount)
		telegramConfigured := os.Getenv("TELEGRAM_BOT_TOKEN") != "" && os.Getenv("TELEGRAM_CHAT_ID") != ""
		c.JSON(http.StatusOK, gin.H{
			"status":              "healthy",
			"version":             "2.1.0",
			"recordings":          recCount,
			"devices":             devCount,
			"telegram_backup":     telegramConfigured,
			"telegram_backed":     backedCount,
			"server_time":         time.Now().UTC().Format(time.RFC3339),
		})
	})

	r.POST("/login", func(c *gin.Context) {
		var input struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
		}
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid payload: username and password required"})
			return
		}

		var user User
		if err := db.Where("username = ?", input.Username).First(&user).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		token, err := generateToken(user.Username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": token})
	})

	// ── Authenticated routes ──────────────────────────────────────────────────

	authorized := r.Group("/")
	authorized.Use(authMiddleware())
	{
		// Upload
		authorized.POST("/upload", func(c *gin.Context) {
			phoneID := c.PostForm("phone_id")
			deviceName := c.PostForm("device_name")
			androidVersion := c.PostForm("android_version")
			timestampStr := c.PostForm("timestamp")
			clientSHA256 := c.PostForm("sha256")

			if phoneID == "" || deviceName == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required fields: phone_id and device_name"})
				return
			}

			fileHeader, err := c.FormFile("file")
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded"})
				return
			}

			file, err := fileHeader.Open()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open uploaded file"})
				return
			}
			defer file.Close()

			hasher := sha256.New()
			if _, err := io.Copy(hasher, file); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to compute file hash"})
				return
			}
			computedSHA256 := hex.EncodeToString(hasher.Sum(nil))

			if clientSHA256 != "" && clientSHA256 != computedSHA256 {
				c.JSON(http.StatusBadRequest, gin.H{
					"error":    "SHA256 mismatch — file may be corrupted",
					"expected": clientSHA256,
					"got":      computedSHA256,
				})
				return
			}

			device := Device{ID: phoneID, Name: deviceName, AndroidVersion: androidVersion, LastSeen: time.Now()}
			db.Save(&device)

			var existingRecording Recording
			if err := db.Where("sha256 = ?", computedSHA256).First(&existingRecording).Error; err == nil {
				c.JSON(http.StatusOK, gin.H{"message": "File already exists (duplicate)", "id": existingRecording.ID})
				return
			}

			safeFilename := filepath.Base(fileHeader.Filename)
			// Guard against path traversal: ensure the resolved folder stays inside storage/
			deviceFolder := filepath.Join("storage", filepath.Clean(phoneID))
			if !strings.HasPrefix(filepath.Clean(deviceFolder), "storage"+string(filepath.Separator)) &&
				filepath.Clean(deviceFolder) != "storage" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone_id"})
				return
			}
			os.MkdirAll(deviceFolder, 0755)

			targetPath := filepath.Join(deviceFolder, safeFilename)
			if err := c.SaveUploadedFile(fileHeader, targetPath); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file to disk"})
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
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save recording metadata"})
				return
			}

			// Backup to Telegram asynchronously (non-blocking)
			backupToTelegram(&recording)

			telegramConfigured := os.Getenv("TELEGRAM_BOT_TOKEN") != "" && os.Getenv("TELEGRAM_CHAT_ID") != ""
			c.JSON(http.StatusOK, gin.H{
				"message":          "Upload successful",
				"id":               recording.ID,
				"sha256":           computedSHA256,
				"size":             fileHeader.Size,
				"telegram_backup":  telegramConfigured,
			})
		})

		// List records
		authorized.GET("/records", func(c *gin.Context) {
			var recordings []Recording
			if err := db.Preload("Device").Order("creation_date DESC").Find(&recordings).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch recordings"})
				return
			}
			c.JSON(http.StatusOK, recordings)
		})

		// Record detail
		authorized.GET("/record/:id", func(c *gin.Context) {
			id := c.Param("id")
			var recording Recording
			if err := db.Preload("Device").First(&recording, id).Error; err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "Recording not found", "id": id})
				return
			}
			c.JSON(http.StatusOK, recording)
		})

		// Stream (inline playback)
		authorized.GET("/stream/:id", func(c *gin.Context) {
			id := c.Param("id")
			var recording Recording
			if err := db.First(&recording, id).Error; err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "Recording not found", "id": id})
				return
			}

			if _, err := os.Stat(recording.Path); os.IsNotExist(err) {
				c.JSON(http.StatusNotFound, gin.H{"error": "Audio file missing from disk"})
				return
			}

			ext := strings.ToLower(filepath.Ext(recording.Name))
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

			c.Header("Content-Type", contentType)
			c.Header("Accept-Ranges", "bytes")
			c.File(recording.Path)
		})

		// Download (attachment)
		authorized.GET("/download/:id", func(c *gin.Context) {
			id := c.Param("id")
			var recording Recording
			if err := db.First(&recording, id).Error; err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "Recording not found", "id": id})
				return
			}

			if _, err := os.Stat(recording.Path); os.IsNotExist(err) {
				c.JSON(http.StatusNotFound, gin.H{"error": "Audio file missing from disk"})
				return
			}

			c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, recording.Name))
			c.Header("Content-Transfer-Encoding", "binary")
			c.File(recording.Path)
		})

		// Delete single record
		authorized.DELETE("/record/:id", func(c *gin.Context) {
			id := c.Param("id")
			var recording Recording
			if err := db.First(&recording, id).Error; err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "Recording not found", "id": id})
				return
			}

			if err := db.Delete(&recording).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete recording from database"})
				return
			}

			if err := os.Remove(recording.Path); err != nil && !os.IsNotExist(err) {
				log.Printf("Warning: could not remove file %s: %v", recording.Path, err)
			}

			c.JSON(http.StatusOK, gin.H{
				"message": "Recording deleted successfully",
				"id":      id,
				"name":    recording.Name,
			})
		})

		// Purge ALL recordings
		authorized.DELETE("/purge-all", func(c *gin.Context) {
			var recordings []Recording
			if err := db.Find(&recordings).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch recordings for purge"})
				return
			}

			deleted := 0
			errors := 0
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

			filepath.Walk("storage", func(path string, info os.FileInfo, err error) error {
				if err == nil && info.IsDir() && path != "storage" {
					entries, _ := os.ReadDir(path)
					if len(entries) == 0 {
						os.Remove(path)
					}
				}
				return nil
			})

			c.JSON(http.StatusOK, gin.H{
				"message": "Purge complete",
				"deleted": deleted,
				"errors":  errors,
				"total":   len(recordings),
			})
		})

		// Storage stats
		authorized.GET("/storage/stats", func(c *gin.Context) {
			var recCount, totalSize, backedCount int64
			db.Model(&Recording{}).Count(&recCount)
			db.Model(&Recording{}).Select("COALESCE(SUM(size), 0)").Scan(&totalSize)
			db.Model(&Recording{}).Where("telegram_backed = ?", true).Count(&backedCount)

			diskTotal, diskFree, diskUsed := getDiskStats("storage")
			recordingsUsed := storageUsedByRecordings()

			c.JSON(http.StatusOK, gin.H{
				"recordings":         recCount,
				"recordings_bytes":   recordingsUsed,
				"telegram_backed":    backedCount,
				"telegram_pending":   recCount - backedCount,
				"disk_total":         diskTotal,
				"disk_free":          diskFree,
				"disk_used":          diskUsed,
				"db_total_size":      totalSize,
			})
		})

		// Telegram backup status
		authorized.GET("/backup/status", func(c *gin.Context) {
			var total, backed, pending int64
			db.Model(&Recording{}).Count(&total)
			db.Model(&Recording{}).Where("telegram_backed = ?", true).Count(&backed)
			pending = total - backed
			telegramConfigured := os.Getenv("TELEGRAM_BOT_TOKEN") != "" && os.Getenv("TELEGRAM_CHAT_ID") != ""

			c.JSON(http.StatusOK, gin.H{
				"telegram_configured": telegramConfigured,
				"total":               total,
				"backed_up":           backed,
				"pending":             pending,
				"coverage_pct":        func() float64 {
					if total == 0 {
						return 100.0
					}
					return float64(backed) / float64(total) * 100
				}(),
			})
		})

		// Force retry all pending Telegram backups
		authorized.POST("/backup/retry", func(c *gin.Context) {
			var pending []Recording
			db.Where("telegram_backed = ? OR telegram_backed IS NULL", false).Find(&pending)

			for i := range pending {
				backupToTelegram(&pending[i])
			}

			c.JSON(http.StatusOK, gin.H{
				"message":   "Retry triggered",
				"triggered": len(pending),
			})
		})
	}

	// 404 handler
	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"error":  "Route not found",
			"method": c.Request.Method,
			"path":   c.Request.URL.Path,
			"hint":   "GET / for available endpoints",
		})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("CallSync server v2.1 starting on :%s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
