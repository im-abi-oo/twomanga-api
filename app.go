package main

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// ----- CONFIG -----

type Config struct {
	MongoURI       string
	DBName         string
	JWTSecret      []byte
	Port           string
	WorkerCount    int
	JobWaitSeconds time.Duration
	AdminUsernames []string
	AdminEnvUser   string
	AdminEnvPass   string
}

var cfg Config
var mongoClient *mongo.Client
var db *mongo.Database

func loadConfig() {
	godotenv.Load()

	cfg.MongoURI = os.Getenv("MONGO_URI")
	if cfg.MongoURI == "" {
		log.Println("WARNING: MONGO_URI is missing")
	}
	cfg.JWTSecret = []byte(os.Getenv("JWT_SECRET_KEY"))
	if len(cfg.JWTSecret) == 0 {
		log.Println("WARNING: JWT_SECRET_KEY is missing")
	}

	cfg.DBName = os.Getenv("MONGO_DBNAME")
	if cfg.DBName == "" {
		cfg.DBName = "twomanga"
	}

	cfg.Port = os.Getenv("PORT")
	if cfg.Port == "" {
		cfg.Port = "5001"
	}

	wc, _ := strconv.Atoi(os.Getenv("WORKER_COUNT"))
	if wc == 0 {
		wc = 4
	}
	cfg.WorkerCount = wc

	ws, _ := strconv.ParseFloat(os.Getenv("JOB_WAIT_SECONDS"), 64)
	if ws == 0 {
		ws = 8.0
	}
	cfg.JobWaitSeconds = time.Duration(ws * float64(time.Second))

	admins := os.Getenv("ADMIN_USERNAMES")
	for _, u := range strings.Split(admins, ",") {
		if t := strings.TrimSpace(u); t != "" {
			cfg.AdminUsernames = append(cfg.AdminUsernames, strings.ToLower(t))
		}
	}
	cfg.AdminEnvUser = strings.ToLower(os.Getenv("ADMIN_USERNAME"))
	cfg.AdminEnvPass = os.Getenv("ADMIN_PASSWORD")
}

// ----- DATABASE -----

func connectDB() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOptions := options.Client().ApplyURI(cfg.MongoURI)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatalf("MongoDB Ping Failed: %v", err)
	}

	mongoClient = client
	db = client.Database(cfg.DBName)
	log.Printf("Connected to MongoDB: %s", cfg.DBName)
}

// ----- MODELS -----

// User struct aligns with Python schema
type User struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Username       string             `bson:"username" json:"username"`
	Password       string             `bson:"password" json:"-"`
	Role           string             `bson:"role" json:"role"`
	SessionSalt    string             `bson:"session_salt" json:"-"`
	CreatedAt      time.Time          `bson:"created_at" json:"created_at"`
	TotalPurchases int                `bson:"total_purchases" json:"total_purchases"`
	// Python uses 'expiryDate' for user logic
	ExpiryDate *time.Time `bson:"expiryDate,omitempty" json:"expiryDate,omitempty"`
}

type Coupon struct {
	ID        primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	Code      string               `bson:"code" json:"code"`
	BonusDays int                  `bson:"bonus_days" json:"bonus_days"`
	MaxUses   *int                 `bson:"max_uses" json:"max_uses"`
	Uses      int                  `bson:"uses" json:"uses"`
	UsedBy    []primitive.ObjectID `bson:"used_by" json:"used_by"`
	ExpiresAt *time.Time           `bson:"expires_at" json:"expires_at"`
	CreatedAt time.Time            `bson:"created_at" json:"created_at"`
}

type Transaction struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID       primitive.ObjectID `bson:"user_id" json:"user_id"`
	Username     string             `bson:"username" json:"username"`
	TxHash       string             `bson:"tx_hash" json:"tx_hash"`
	Days         int                `bson:"days" json:"days"`
	Status       string             `bson:"status" json:"status"`
	CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
	ProcessedAt  *time.Time         `bson:"processed_at,omitempty" json:"processed_at,omitempty"`
	ApprovedBy   string             `bson:"approved_by,omitempty" json:"approved_by,omitempty"`
	RejectedAt   *time.Time         `bson:"rejected_at,omitempty" json:"rejected_at,omitempty"`
	RejectedBy   string             `bson:"rejected_by,omitempty" json:"rejected_by,omitempty"`
	RejectReason string             `bson:"reject_reason,omitempty" json:"reject_reason,omitempty"`
}

// ----- UTILS -----

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

func checkPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// ----- WORKER ENGINE (Priority Queue) -----

type JobResult struct {
	Data interface{}
	Err  error
	Code int
}

type Job struct {
	Priority   int
	Sequence   int64
	Func       func() (interface{}, int, error)
	ResultChan chan JobResult
}

type PriorityQueue []*Job

func (pq PriorityQueue) Len() int { return len(pq) }
func (pq PriorityQueue) Less(i, j int) bool {
	if pq[i].Priority != pq[j].Priority {
		return pq[i].Priority > pq[j].Priority // Max-heap (High priority first)
	}
	return pq[i].Sequence < pq[j].Sequence // FIFO
}
func (pq PriorityQueue) Swap(i, j int)       { pq[i], pq[j] = pq[j], pq[i] }
func (pq *PriorityQueue) Push(x interface{}) { *pq = append(*pq, x.(*Job)) }
func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	*pq = old[0 : n-1]
	return item
}

var (
	jobQueue   = make(PriorityQueue, 0)
	queueLock  sync.Mutex
	jobSignal  = make(chan struct{}, 1000)
	shutdownCh = make(chan struct{})
)

func SubmitJob(priority int, task func() (interface{}, int, error), wait bool) (interface{}, int, error) {
	resChan := make(chan JobResult, 1)
	job := &Job{
		Priority:   priority,
		Sequence:   time.Now().UnixNano(),
		Func:       task,
		ResultChan: resChan,
	}

	queueLock.Lock()
	heap.Push(&jobQueue, job)
	queueLock.Unlock()

	select {
	case jobSignal <- struct{}{}:
	default:
	}

	if !wait {
		return map[string]interface{}{"queued": true, "job_id": job.Sequence}, 202, nil
	}

	select {
	case res := <-resChan:
		return res.Data, res.Code, res.Err
	case <-time.After(cfg.JobWaitSeconds):
		return map[string]string{"msg": "Processing queued due to load"}, 202, nil
	}
}

func startWorkers(count int) {
	for i := 0; i < count; i++ {
		go func(id int) {
			log.Printf("Worker-%d started", id)
			for {
				select {
				case <-shutdownCh:
					return
				case <-jobSignal:
					queueLock.Lock()
					if jobQueue.Len() == 0 {
						queueLock.Unlock()
						continue
					}
					item := heap.Pop(&jobQueue).(*Job)
					queueLock.Unlock()

					data, code, err := item.Func()
					// Provide generic error message on map if needed
					if err != nil && data == nil {
						data = map[string]string{"msg": "Internal Error", "detail": err.Error()}
						if code == 0 {
							code = 500
						}
					}
					item.ResultChan <- JobResult{Data: data, Code: code, Err: err}
					close(item.ResultChan)
				}
			}
		}(i)
	}
}

// ----- BUSINESS LOGIC (Worker Side) -----

func logicApplyPayment(userIDStr string, couponCode, txHash string, daysReq int) (interface{}, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userOID, _ := primitive.ObjectIDFromHex(userIDStr)

	// Fetch User
	var user User
	err := db.Collection("users").FindOne(ctx, bson.M{"_id": userOID}).Decode(&user)
	if err != nil {
		return map[string]string{"msg": "User not found"}, 404, err
	}

	// 1. COUPON LOGIC
	if couponCode != "" {
		couponColl := db.Collection("coupons")
		var cp Coupon

		err := couponColl.FindOne(ctx, bson.M{"code": couponCode}).Decode(&cp)
		if err != nil {
			return map[string]string{"msg": "Invalid coupon code"}, 400, nil
		}

		now := time.Now().UTC()
		// Check Expiry
		if cp.ExpiresAt != nil && cp.ExpiresAt.Before(now) {
			couponColl.DeleteOne(ctx, bson.M{"_id": cp.ID})
			return map[string]string{"msg": "Coupon expired"}, 400, nil
		}
		// Check Max Uses
		if cp.MaxUses != nil && cp.Uses >= *cp.MaxUses {
			couponColl.DeleteOne(ctx, bson.M{"_id": cp.ID})
			return map[string]string{"msg": "Coupon limits reached"}, 400, nil
		}
		// Check if user already used
		for _, uID := range cp.UsedBy {
			if uID == userOID {
				return map[string]string{"msg": "You have already used this coupon"}, 400, nil
			}
		}

		// ATOMIC UPDATE (Compare and Swap)
		filter := bson.M{
			"_id":     cp.ID,
			"uses":    cp.Uses,               // Optimistic Locking
			"used_by": bson.M{"$ne": userOID}, // Double check
		}
		update := bson.M{
			"$inc":  bson.M{"uses": 1},
			"$push": bson.M{"used_by": userOID},
		}

		var updatedCp Coupon
		err = couponColl.FindOneAndUpdate(ctx, filter, update, options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&updatedCp)
		if err != nil {
			return map[string]string{"msg": "Coupon invalid, expired, already used, or limit reached"}, 400, nil
		}

		// Apply Bonus to User
		startPoint := now
		if user.ExpiryDate != nil && user.ExpiryDate.After(now) {
			startPoint = *user.ExpiryDate
		}
		newExpiry := startPoint.Add(time.Duration(cp.BonusDays) * 24 * time.Hour)

		_, err = db.Collection("users").UpdateOne(ctx, bson.M{"_id": userOID}, bson.M{
			"$set": bson.M{"expiryDate": newExpiry},
			"$inc": bson.M{"total_purchases": 1},
		})

		// ROLLBACK Logic
		if err != nil {
			log.Printf("[ROLLBACK] Coupon %s for user %s failed. Rolling back.", cp.Code, userIDStr)
			couponColl.UpdateOne(context.Background(), bson.M{"_id": cp.ID}, bson.M{
				"$inc":  bson.M{"uses": -1},
				"$pull": bson.M{"used_by": userOID},
			})
			return map[string]string{"msg": "Failed to apply coupon, please retry"}, 500, err
		}

		// Post-usage cleanup (if limit reached)
		if updatedCp.MaxUses != nil && updatedCp.Uses >= *updatedCp.MaxUses {
			couponColl.DeleteOne(context.Background(), bson.M{"_id": updatedCp.ID})
		}

		return map[string]interface{}{
			"msg":        "Coupon applied successfully",
			"new_expiry": newExpiry.Format(time.RFC3339),
		}, 200, nil
	}

	// 2. CRYPTO TX LOGIC
	if txHash == "" {
		return map[string]string{"msg": "TX Hash required if no coupon"}, 400, nil
	}

	// Check duplicates
	count, _ := db.Collection("transactions").CountDocuments(ctx, bson.M{"tx_hash": txHash})
	if count > 0 {
		return map[string]string{"msg": "Transaction already submitted"}, 409, nil
	}

	newTx := Transaction{
		UserID:    userOID,
		Username:  user.Username,
		TxHash:    txHash,
		Days:      daysReq,
		Status:    "pending",
		CreatedAt: time.Now().UTC(),
	}

	res, err := db.Collection("transactions").InsertOne(ctx, newTx)
	if err != nil {
		return nil, 500, err
	}

	// Helper to get ID as string for frontend
	idStr := res.InsertedID.(primitive.ObjectID).Hex()

	return map[string]interface{}{
		"msg":   "Transaction pending approval",
		"tx_id": idStr,
	}, 201, nil
}

// ----- AUTH & MIDDLEWARE -----

type CustomClaims struct {
	SessionSalt string `json:"session_salt"`
	jwt.RegisteredClaims
}

func generateTokens(username, salt string) (string, string, error) {
	// Access Token
	accClaims := CustomClaims{
		SessionSalt: salt,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(4 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, accClaims)
	accStr, err := token.SignedString(cfg.JWTSecret)
	if err != nil {
		return "", "", err
	}

	// Refresh Token
	refClaims := CustomClaims{
		SessionSalt: salt,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * 24 * time.Hour)),
		},
	}
	rToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refClaims)
	refStr, err := rToken.SignedString(cfg.JWTSecret)
	return accStr, refStr, err
}

func AuthMiddleware(requiredAdmin bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(401, gin.H{"msg": "Missing or Invalid Token"})
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &CustomClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return cfg.JWTSecret, nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(401, gin.H{"msg": "Invalid Token"})
			return
		}

		username := claims.Subject
		// Strict Session Check
		var user User
		err = db.Collection("users").FindOne(context.Background(), bson.M{"username": username}).Decode(&user)

		// Compare Salt
		if err != nil || user.SessionSalt != claims.SessionSalt {
			c.AbortWithStatusJSON(401, gin.H{"msg": "Session expired or overridden"})
			return
		}

		// Admin Check Logic
		isAdmin := user.Role == "admin"
		// Check config list
		for _, adm := range cfg.AdminUsernames {
			if adm == username {
				isAdmin = true
				break
			}
		}
		// Check env single user
		if cfg.AdminEnvUser != "" && username == cfg.AdminEnvUser {
			isAdmin = true
		}

		if requiredAdmin && !isAdmin {
			c.AbortWithStatusJSON(403, gin.H{"msg": "Admin access required"})
			return
		}

		c.Set("user", user)
		c.Next()
	}
}

// ----- HANDLERS -----

func register(c *gin.Context) {
	var body struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"username": []string{"Missing data"}})
		return
	}

	username := strings.ToLower(strings.TrimSpace(body.Username))
	if len(username) < 3 || strings.Contains(username, " ") {
		c.JSON(400, gin.H{"username": []string{"Invalid username format"}})
		return
	}

	var exists User
	if err := db.Collection("users").FindOne(c, bson.M{"username": username}).Decode(&exists); err == nil {
		c.JSON(409, gin.H{"msg": "Username exists"})
		return
	}

	hashed, _ := hashPassword(body.Password)
	salt := strconv.FormatInt(time.Now().UnixNano(), 10)

	role := "user"
	// Check if this new user should be admin based on ENV
	for _, adm := range cfg.AdminUsernames {
		if adm == username {
			role = "admin"
		}
	}
	if cfg.AdminEnvUser == username {
		role = "admin"
	}

	newUser := User{
		Username:    username,
		Password:    hashed,
		Role:        role,
		SessionSalt: salt,
		CreatedAt:   time.Now().UTC(),
	}

	res, err := db.Collection("users").InsertOne(c, newUser)
	if err != nil {
		c.JSON(500, gin.H{"msg": "DB Error"})
		return
	}
	newUser.ID = res.InsertedID.(primitive.ObjectID)

	at, rt, _ := generateTokens(username, salt)
	c.JSON(201, gin.H{"msg": "Registered", "access_token": at, "refresh_token": rt})
}

func login(c *gin.Context) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	c.ShouldBindJSON(&body) // ignore error, handle logic below
	username := strings.ToLower(strings.TrimSpace(body.Username))

	var user User
	err := db.Collection("users").FindOne(c, bson.M{"username": username}).Decode(&user)
	if err != nil || !checkPassword(body.Password, user.Password) {
		c.JSON(401, gin.H{"msg": "Invalid credentials"})
		return
	}

	newSalt := strconv.FormatInt(time.Now().UnixNano(), 10)
	db.Collection("users").UpdateOne(c, bson.M{"_id": user.ID}, bson.M{"$set": bson.M{"session_salt": newSalt}})

	at, rt, _ := generateTokens(username, newSalt)
	c.JSON(200, gin.H{"access_token": at, "refresh_token": rt})
}

func getMe(c *gin.Context) {
	u, _ := c.Get("user")
	currentUser := u.(User)

	task := func() (interface{}, int, error) {
		// Re-fetch to be safe
		var user User
		db.Collection("users").FindOne(context.Background(), bson.M{"_id": currentUser.ID}).Decode(&user)

		now := time.Now().UTC()
		daysLeft := 0
		expIso := "" // Nullable in JSON

		if user.ExpiryDate != nil {
			expIso = user.ExpiryDate.Format(time.RFC3339)
			if user.ExpiryDate.After(now) {
				daysLeft = int(user.ExpiryDate.Sub(now).Hours() / 24)
			}
		}

		// Use nil for null in JSON if empty string isn't desired, but Python sends null if None.
		// We'll return a map.
		resp := gin.H{
			"username":  user.Username,
			"role":      user.Role,
			"days_left": daysLeft,
		}
		if user.ExpiryDate != nil {
			resp["expiry_iso"] = expIso
		} else {
			resp["expiry_iso"] = nil
		}
		return resp, 200, nil
	}

	res, code, err := SubmitJob(0, task, true)
	if err != nil {
		c.JSON(code, gin.H{"msg": "System error"})
		return
	}
	c.JSON(code, res)
}

func submitPayment(c *gin.Context) {
	u, _ := c.Get("user")
	currentUser := u.(User)

	var body struct {
		Days       *int   `json:"days"`
		TxHash     string `json:"tx_hash"`
		CouponCode string `json:"coupon_code"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		// Return specific validation error structure if needed, or generic
		c.JSON(400, gin.H{"msg": "Validation failed"})
		return
	}

	if body.CouponCode == "" && body.Days == nil {
		c.JSON(400, gin.H{"msg": "days is required when no coupon is used"})
		return
	}

	days := 0
	if body.Days != nil {
		days = *body.Days
	}

	if body.CouponCode == "" && (days < 1 || days > 3650) {
		c.JSON(400, gin.H{"msg": "Days must be between 1-3650"})
		return
	}

	task := func() (interface{}, int, error) {
		return logicApplyPayment(currentUser.ID.Hex(), body.CouponCode, body.TxHash, days)
	}

	res, code, err := SubmitJob(10, task, true)
	if err != nil {
		// Python checks specific error strings to return 400
		if resMap, ok := res.(map[string]string); ok {
			c.JSON(code, resMap)
			return
		}
		c.JSON(code, gin.H{"msg": "Operation failed", "detail": err.Error()})
		return
	}
	c.JSON(code, res)
}

// ----- ADMIN HANDLERS -----

func adminListTx(c *gin.Context) {
	status := c.Query("status")
	filter := bson.M{}
	if status != "" {
		filter["status"] = status
	}

	opts := options.Find().SetSort(bson.M{"created_at": -1}).SetLimit(100)
	cursor, err := db.Collection("transactions").Find(context.Background(), filter, opts)
	if err != nil {
		c.JSON(500, gin.H{"msg": "DB error"})
		return
	}

	var rawResults []Transaction
	cursor.All(context.Background(), &rawResults)

	// Map to JSON friendly format (strings for OIDs, ISO dates)
	output := []gin.H{}
	for _, tx := range rawResults {
		item := gin.H{
			"_id":        tx.ID.Hex(),
			"user_id":    tx.UserID.Hex(),
			"username":   tx.Username,
			"tx_hash":    tx.TxHash,
			"days":       tx.Days,
			"status":     tx.Status,
			"created_at": tx.CreatedAt.Format(time.RFC3339),
		}
		if tx.ProcessedAt != nil {
			item["processed_at"] = tx.ProcessedAt.Format(time.RFC3339)
		}
		if tx.RejectedAt != nil {
			item["rejected_at"] = tx.RejectedAt.Format(time.RFC3339)
		}
		if tx.RejectReason != "" {
			item["reject_reason"] = tx.RejectReason
		}
		output = append(output, item)
	}
	c.JSON(200, output)
}

func adminApproveTx(c *gin.Context) {
	txID := c.Param("tx_id")
	admin := c.MustGet("user").(User)

	task := func() (interface{}, int, error) {
		ctx := context.Background()
		oid, err := primitive.ObjectIDFromHex(txID)
		if err != nil {
			return map[string]string{"msg": "Invalid ID format"}, 400, nil
		}

		var tx Transaction
		if err := db.Collection("transactions").FindOne(ctx, bson.M{"_id": oid, "status": "pending"}).Decode(&tx); err != nil {
			return map[string]string{"msg": "Transaction not found or not pending"}, 404, nil
		}

		var targetUser User
		if err := db.Collection("users").FindOne(ctx, bson.M{"_id": tx.UserID}).Decode(&targetUser); err != nil {
			return map[string]string{"msg": "Linked user missing"}, 404, nil
		}

		now := time.Now().UTC()
		start := now
		if targetUser.ExpiryDate != nil && targetUser.ExpiryDate.After(now) {
			start = *targetUser.ExpiryDate
		}
		newExp := start.Add(time.Duration(tx.Days) * 24 * time.Hour)

		db.Collection("users").UpdateOne(ctx, bson.M{"_id": targetUser.ID}, bson.M{
			"$set": bson.M{"expiryDate": newExp},
			"$inc": bson.M{"total_purchases": 1},
		})

		db.Collection("transactions").UpdateOne(ctx, bson.M{"_id": oid}, bson.M{
			"$set": bson.M{
				"status":       "approved",
				"approved_by":  admin.Username,
				"processed_at": now,
			},
		})

		return map[string]string{"msg": "Approved", "new_expiry": newExp.Format(time.RFC3339)}, 200, nil
	}

	res, code, _ := SubmitJob(5, task, true)
	c.JSON(code, res)
}

func adminRejectTx(c *gin.Context) {
	txID := c.Param("tx_id")
	admin := c.MustGet("user").(User)
	
	// Handle JSON body for reason
	var body struct { Reason string `json:"reason"` }
	c.ShouldBindJSON(&body)
	if body.Reason == "" { body.Reason = "No reason provided" }

	task := func() (interface{}, int, error) {
		ctx := context.Background()
		oid, err := primitive.ObjectIDFromHex(txID)
		if err != nil {
			return map[string]string{"msg": "Invalid ID format"}, 400, nil
		}

		var tx Transaction
		if err := db.Collection("transactions").FindOne(ctx, bson.M{"_id": oid, "status": "pending"}).Decode(&tx); err != nil {
			return map[string]string{"msg": "Transaction not found or not pending"}, 404, nil
		}

		_, err = db.Collection("transactions").UpdateOne(ctx,
			bson.M{"_id": oid},
			bson.M{"$set": bson.M{
				"status":        "rejected",
				"rejected_by":   admin.Username,
				"rejected_at":   time.Now().UTC(),
				"reject_reason": body.Reason,
			}},
		)

		if err != nil {
			return nil, 500, err
		}
		return map[string]string{"msg": "Transaction rejected successfully"}, 200, nil
	}

	res, code, _ := SubmitJob(5, task, true)
	c.JSON(code, res)
}

func manageCoupons(c *gin.Context) {
	if c.Request.Method == "GET" {
		cursor, _ := db.Collection("coupons").Find(context.Background(), bson.M{}, options.Find().SetSort(bson.M{"created_at": -1}))
		var coupons []Coupon
		cursor.All(context.Background(), &coupons)

		output := []gin.H{}
		for _, cp := range coupons {
			usedByStrs := []string{}
			for _, u := range cp.UsedBy {
				usedByStrs = append(usedByStrs, u.Hex())
			}

			item := gin.H{
				"_id":        cp.ID.Hex(),
				"code":       cp.Code,
				"bonus_days": cp.BonusDays,
				"max_uses":   cp.MaxUses,
				"uses":       cp.Uses,
				"used_by":    usedByStrs, // Return as array of strings
				"created_at": cp.CreatedAt.Format(time.RFC3339),
			}
			if cp.ExpiresAt != nil {
				item["expires_at"] = cp.ExpiresAt.Format(time.RFC3339)
			} else {
				item["expires_at"] = nil
			}
			output = append(output, item)
		}
		c.JSON(200, output)
		return
	}

	// POST
	var body struct {
		Code      string     `json:"code" binding:"required"`
		BonusDays int        `json:"bonus_days" binding:"required"`
		MaxUses   *int       `json:"max_uses"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"msg": err.Error()})
		return
	}

	newC := Coupon{
		Code:      body.Code,
		BonusDays: body.BonusDays,
		MaxUses:   body.MaxUses,
		ExpiresAt: body.ExpiresAt,
		Uses:      0,
		UsedBy:    []primitive.ObjectID{},
		CreatedAt: time.Now().UTC(),
	}

	_, err := db.Collection("coupons").InsertOne(context.Background(), newC)
	if mongo.IsDuplicateKeyError(err) {
		c.JSON(409, gin.H{"msg": "Coupon code already exists"}) // Match python message
		return
	}
	c.JSON(201, gin.H{"msg": "Coupon created"})
}

// ----- STARTUP -----

func ensureIndexesAndAdmin() {
	ctx := context.Background()

	db.Collection("users").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "username", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	db.Collection("transactions").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "tx_hash", Value: 1}},
		Options: options.Index().SetUnique(true).SetSparse(true),
	})
	db.Collection("coupons").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "code", Value: 1}},
		Options: options.Index().SetUnique(true),
	})

	// Bootstrap Admin
	if cfg.AdminEnvUser != "" && cfg.AdminEnvPass != "" {
		hash, _ := hashPassword(cfg.AdminEnvPass)
		userColl := db.Collection("users")
		if err := userColl.FindOne(ctx, bson.M{"username": cfg.AdminEnvUser}).Err(); err == mongo.ErrNoDocuments {
			userColl.InsertOne(ctx, User{
				Username:    cfg.AdminEnvUser,
				Password:    hash,
				Role:        "admin",
				SessionSalt: "system",
				CreatedAt:   time.Now().UTC(),
			})
			log.Println("Bootstrap admin created")
		}
	}
}

func cleanupCouponsTask() {
	ticker := time.NewTicker(1 * time.Hour)
	for {
		select {
		case <-shutdownCh:
			return
		case <-ticker.C:
			res, _ := db.Collection("coupons").DeleteMany(context.Background(), bson.M{
				"expires_at": bson.M{"$lt": time.Now().UTC()},
			})
			if res.DeletedCount > 0 {
				log.Printf("Deleted %d expired coupons", res.DeletedCount)
			}
		}
	}
}

func main() {
	loadConfig()
	connectDB()

	heap.Init(&jobQueue)
	startWorkers(cfg.WorkerCount)

	// Startup Jobs
	go func() {
		// Use worker to ensure db connection is ready or just run direct as in Python "on_app_ready"
		ensureIndexesAndAdmin()
		cleanupCouponsTask()
	}()

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	// CORS Config aligned with Python
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowAllOrigins = true
	if origins := os.Getenv("FRONTEND_ORIGINS"); origins != "" {
		corsConfig.AllowAllOrigins = false
		corsConfig.AllowOrigins = strings.Split(origins, ",")
	}
	corsConfig.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type", "Authorization"}
	corsConfig.AllowMethods = []string{"GET", "POST", "OPTIONS"}
	r.Use(cors.New(corsConfig))

	// Routes
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"service":        "TwoManga API",
			"mode":           "Worker Queue PRO (Go)",
			"workers_active": cfg.WorkerCount,
			"db":             true,
		})
	})

	auth := r.Group("/auth")
	{
		auth.POST("/register", register)
		auth.POST("/login", login)
		auth.GET("/me", AuthMiddleware(false), getMe)
	}

	payment := r.Group("/payment")
	payment.Use(AuthMiddleware(false))
	{
		payment.POST("/submit", submitPayment)
	}

	admin := r.Group("/admin")
	admin.Use(AuthMiddleware(true))
	{
		admin.GET("/transactions", adminListTx)
		admin.POST("/transactions/:tx_id/approve", adminApproveTx)
		admin.POST("/transactions/:tx_id/reject", adminRejectTx)
		admin.GET("/coupons", manageCoupons)
		admin.POST("/coupons", manageCoupons)
	}

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: r,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()
	log.Printf("Server running on port %s", cfg.Port)

	// Graceful Shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down...")

	close(shutdownCh)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server Shutdown:", err)
	}
	
	if mongoClient != nil {
		mongoClient.Disconnect(context.Background())
	}
	log.Println("Bye.")
}
