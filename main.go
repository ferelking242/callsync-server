package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"github.com/golang-jwt/jwt/v5"
)

var jwtKey = []byte("callsync_secret_security_key_2026")

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

var db *gorm.DB

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
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
		admin := User{
			Username:  "admin",
			Password:  string(hashedPassword),
			CreatedAt: time.Now(),
		}
		db.Create(&admin)
		log.Println("Seeded default admin user: username=admin, password=admin123")
	}
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func generateToken(username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
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

func main() {
	initDB()
	os.MkdirAll("storage", 0755)

	r := gin.Default()

	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy", "version": "1.0.0"})
	})

	r.POST("/login", func(c *gin.Context) {
		var input struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
		}
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid payload"})
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

		token, _ := generateToken(user.Username)
		c.JSON(http.StatusOK, gin.H{"token": token})
	})

	authorized := r.Group("/")
	authorized.Use(authMiddleware())
	{
		authorized.POST("/upload", func(c *gin.Context) {
			phoneID := c.PostForm("phone_id")
			deviceName := c.PostForm("device_name")
			androidVersion := c.PostForm("android_version")
			timestampStr := c.PostForm("timestamp")
			clientSHA256 := c.PostForm("sha256")

			if phoneID == "" || deviceName == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Missing phone_id or device_name"})
				return
			}

			fileHeader, err := c.FormFile("file")
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded"})
				return
			}

			file, _ := fileHeader.Open()
			defer file.Close()

			hasher := sha256.New()
			io.Copy(hasher, file)
			computedSHA256 := hex.EncodeToString(hasher.Sum(nil))

			if clientSHA256 != "" && clientSHA256 != computedSHA256 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "SHA256 mismatch"})
				return
			}

			device := Device{ID: phoneID, Name: deviceName, AndroidVersion: androidVersion, LastSeen: time.Now()}
			db.Save(&device)

			var existingRecording Recording
			if err := db.Where("sha256 = ?", computedSHA256).First(&existingRecording).Error; err == nil {
				c.JSON(http.StatusOK, gin.H{"message": "File already exists", "id": existingRecording.ID})
				return
			}

			safeFilename := filepath.Base(fileHeader.Filename)
			deviceFolder := filepath.Join("storage", filepath.Clean(phoneID))
			os.MkdirAll(deviceFolder, 0755)

			targetPath := filepath.Join(deviceFolder, safeFilename)
			c.SaveUploadedFile(fileHeader, targetPath)

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
			db.Create(&recording)

			c.JSON(http.StatusOK, gin.H{"message": "Upload successful", "id": recording.ID})
		})

		authorized.GET("/records", func(c *gin.Context) {
			var recordings []Recording
			db.Preload("Device").Order("creation_date DESC").Find(&recordings)
			c.JSON(http.StatusOK, recordings)
		})

		authorized.GET("/stream/:id", func(c *gin.Context) {
			id := c.Param("id")
			var recording Recording
			if err := db.First(&recording, id).Error; err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "Recording not found"})
				return
			}
			c.Header("Content-Type", "audio/mpeg")
			c.Header("Accept-Ranges", "bytes")
			c.File(recording.Path)
		})

		authorized.DELETE("/record/:id", func(c *gin.Context) {
			id := c.Param("id")
			var recording Recording
			if err := db.First(&recording, id).Error; err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "Recording not found"})
				return
			}
			db.Delete(&recording)
			os.Remove(recording.Path)
			c.JSON(http.StatusOK, gin.H{"message": "Recording deleted successfully"})
		})
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r.Run(":" + port)
}

